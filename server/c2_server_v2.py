"""
server/c2_server_v2.py -- JOCKY C2 Server v2
=============================================
Adds task dispatch endpoints so investigator can
send .jky script tasks to dormant agents.

New endpoints:
  POST /api/task              -- investigator dispatches task
  GET  /api/task/pending/{id} -- agent polls for its next task
  GET  /api/tasks             -- list all tasks + status
  POST /api/script/run        -- run .jky script text directly
  GET  /api/scripts/builtins  -- list built-in scripts
  GET  /api/collectors        -- list available collectors
"""
from __future__ import annotations

import asyncio, base64, hashlib, hmac, json, logging
import os, struct, sys, time, uuid
from collections import deque
from datetime    import datetime, timezone
from pathlib     import Path
from typing      import Any, AsyncIterator, Dict, List, Optional

import uvicorn
from fastapi              import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses    import StreamingResponse, HTMLResponse
from pydantic             import BaseModel

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
for _p in [str(_ROOT), str(_ROOT/"integrity"), str(_ROOT/"jocky_lang")]:
    if _p not in sys.path: sys.path.insert(0, _p)

from blockchain import ForensicBlockchain
from runner     import JockyParser, BUILTIN_SCRIPTS, COLLECTORS

log = logging.getLogger("jocky.c2v2")

# ── config ────────────────────────────────────────────────────────────────────
PSK          = b"JOCKY_DEMO_PSK_32_BYTES_12345678"
CASE_ID      = "NTRO-2026-001"
INVESTIGATOR = "INV-ALPHA"
EVIDENCE_DIR = _ROOT / "evidence"
EVIDENCE_DIR.mkdir(exist_ok=True)

app = FastAPI(title="JOCKY C2 v2", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

# ── in-memory state ───────────────────────────────────────────────────────────
_agents:    Dict[str, Dict]          = {}
_evidence:  List[Dict]               = []
_tasks:     Dict[str, Dict]          = {}   # task_id -> task
_pending:   Dict[str, deque]         = {}   # agent_id -> queue of tasks
_sse_queue: asyncio.Queue            = asyncio.Queue(maxsize=512)
_blockchain: Optional[ForensicBlockchain] = None

# ── helpers ───────────────────────────────────────────────────────────────────
def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _broadcast(event: dict):
    try: _sse_queue.put_nowait(event)
    except asyncio.QueueFull: pass

def _derive_key(psk: bytes, agent_id: str) -> bytes:
    prk = hmac.new(b"jocky-salt-v1", psk, hashlib.sha256).digest()
    return hmac.new(prk, agent_id.encode() + b"\x01", hashlib.sha256).digest()

def _decrypt(agent_id: str, psk: bytes, b64: str) -> Optional[dict]:
    try:
        raw    = base64.b64decode(b64)
        nonce  = raw[:12]; ct = raw[12:]
        key    = _derive_key(psk, agent_id)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        pt     = AESGCM(key).decrypt(nonce, ct, agent_id.encode())
        magic, msg_type, plen = struct.unpack(">III", pt[:12])
        if magic != 0x4A4F4B59: return None
        return json.loads(pt[12:12+plen].decode())
    except Exception as e:
        log.debug(f"decrypt: {e}"); return None

# ── startup ───────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def on_startup():
    global _blockchain
    _blockchain = ForensicBlockchain(
        case_id      = CASE_ID,
        investigator = INVESTIGATOR,
        chain_file   = str(EVIDENCE_DIR / f"coc_{CASE_ID}.json"),
        key_file     = str(EVIDENCE_DIR / f"inv_key_{INVESTIGATOR}.pem"),
    )
    log.info(f"[c2] blockchain ready: {_blockchain.length} blocks")

# ── models ────────────────────────────────────────────────────────────────────
class CheckinPayload(BaseModel):
    agent_id:  str
    hostname:  str = ""
    platform:  str = ""
    state:     str = "DORMANT"
    timestamp: str = ""

class EvidencePayload(BaseModel):
    agent_id:      str
    seq:           int
    data:          str
    plain_summary: dict = {}

class TaskRequest(BaseModel):
    target:     str           # agent_id or "all"
    collectors: List[str]
    filters:    List[str] = []
    flags:      List[str] = []
    alerts:     List[str] = []
    case_id:    str = CASE_ID
    source:     str = ""      # original .jky source

class ScriptRunRequest(BaseModel):
    source:  str              # .jky script text
    target:  str = "all"
    case_id: str = CASE_ID

# ── /api/checkin ──────────────────────────────────────────────────────────────
@app.post("/api/checkin")
async def checkin(payload: CheckinPayload):
    aid = payload.agent_id
    _agents[aid] = {
        "agent_id":      aid,
        "hostname":      payload.hostname,
        "platform":      payload.platform,
        "state":         payload.state,
        "first_seen":    _agents.get(aid, {}).get("first_seen", _utcnow()),
        "last_seen":     _utcnow(),
        "evidence_count":_agents.get(aid, {}).get("evidence_count", 0),
        "via":           "USB",
    }
    if aid not in _pending:
        _pending[aid] = deque()

    if _blockchain and payload.state == "DORMANT" and \
       _agents[aid].get("evidence_count", 0) == 0:
        try:
            _blockchain.add_event("AGENT_DEPLOYED", {
                "action":    "AGENT_CONNECTED",
                "agent_id":  aid,
                "hostname":  payload.hostname,
                "platform":  payload.platform,
                "via":       "USB_AUTO_DEPLOY",
            })
        except Exception: pass

    _broadcast({"type":"checkin","agent_id":aid,
                "state":payload.state,"ts":time.time()})
    return {"ok": True, "case_id": CASE_ID}

# ── /api/task (investigator dispatches task) ──────────────────────────────────
@app.post("/api/task")
async def dispatch_task(req: TaskRequest):
    """
    Investigator sends a task (from .jky script).
    Task queued for the target agent(s).
    Agent picks it up on next poll.
    """
    task_id = str(uuid.uuid4())
    task = {
        "task_id":    task_id,
        "case_id":    req.case_id,
        "collectors": req.collectors,
        "filters":    req.filters,
        "flags":      req.flags,
        "alerts":     req.alerts,
        "source":     req.source,
        "status":     "PENDING",
        "created_at": _utcnow(),
        "target":     req.target,
    }
    _tasks[task_id] = task

    # resolve targets
    targets = []
    if req.target == "all":
        targets = list(_agents.keys())
        if not targets:
            return {"ok": False, "error": "no agents connected"}
    else:
        targets = [req.target]

    for aid in targets:
        if aid not in _pending:
            _pending[aid] = deque()
        agent_task = dict(task)
        agent_task["agent_id"] = aid
        _pending[aid].append(agent_task)
        log.info(f"[c2] task {task_id[:8]} queued for {aid}: {req.collectors}")

    # log to blockchain
    if _blockchain:
        try:
            _blockchain.add_event("TASK_DISPATCHED", {
                "task_id":    task_id,
                "targets":    targets,
                "collectors": req.collectors,
                "case_id":    req.case_id,
            })
        except Exception: pass

    # fire SSE
    _broadcast({
        "type":       "task_dispatched",
        "task_id":    task_id,
        "targets":    targets,
        "collectors": req.collectors,
        "ts":         time.time(),
    })

    return {
        "ok":      True,
        "task_id": task_id,
        "targets": targets,
        "queued":  len(targets),
    }

# ── /api/task/pending/{agent_id} (agent polls) ────────────────────────────────
@app.get("/api/task/pending/{agent_id}")
async def poll_task(agent_id: str):
    """
    Agent polls this endpoint every N seconds.
    Returns next pending task or null.
    This is how DORMANT agents receive work.
    """
    q = _pending.get(agent_id)
    if not q:
        return {"task": None}

    task = q.popleft() if q else None
    if task:
        task["status"] = "SENT"
        _tasks[task["task_id"]]["status"] = "SENT"
        log.info(f"[c2] task {task['task_id'][:8]} → {agent_id}")
        _broadcast({
            "type":       "task_sent",
            "task_id":    task["task_id"],
            "agent_id":   agent_id,
            "collectors": task["collectors"],
            "ts":         time.time(),
        })
    return {"task": task}

# ── /api/script/run (run .jky from dashboard) ─────────────────────────────────
@app.post("/api/script/run")
async def run_script(req: ScriptRunRequest):
    """
    Investigator pastes/writes .jky script in dashboard.
    Server parses it and dispatches tasks to agents.
    """
    parser = JockyParser()
    plan   = parser.parse(req.source)

    if plan["errors"]:
        return {"ok": False, "errors": plan["errors"]}

    targets = plan["targets"] or ([req.target] if req.target != "all"
                                   else list(_agents.keys()))
    if "all" in targets:
        targets = list(_agents.keys())

    if not targets:
        return {"ok":False,"error":"No agents connected. Deploy USB first."}

    if not plan["collectors"]:
        return {"ok":False,"error":"No collectors specified in script."}

    task_req = TaskRequest(
        target     = targets[0] if len(targets)==1 else "all",
        collectors = plan["collectors"],
        filters    = plan["filters"],
        flags      = plan["flags"],
        alerts     = plan["alerts"],
        case_id    = plan["case_id"] or req.case_id,
        source     = req.source,
    )

    dispatched = []
    for aid in targets:
        task_id = str(uuid.uuid4())
        task = {
            "task_id":    task_id,
            "agent_id":   aid,
            "case_id":    task_req.case_id,
            "collectors": plan["collectors"],
            "filters":    plan["filters"],
            "flags":      plan["flags"],
            "status":     "PENDING",
            "created_at": _utcnow(),
            "source":     req.source,
        }
        _tasks[task_id] = task
        if aid not in _pending: _pending[aid] = deque()
        _pending[aid].append(task)
        dispatched.append({"agent_id":aid,"task_id":task_id})

    if _blockchain:
        try:
            _blockchain.add_event("TASK_DISPATCHED", {
                "script_len":  len(req.source),
                "collectors":  plan["collectors"],
                "targets":     targets,
                "case_id":     task_req.case_id,
            })
        except Exception: pass

    _broadcast({
        "type":       "script_dispatched",
        "targets":    targets,
        "collectors": plan["collectors"],
        "ts":         time.time(),
    })

    return {
        "ok":        True,
        "plan":      plan,
        "targets":   targets,
        "dispatched":dispatched,
    }

# ── /api/evidence (agent submits results) ─────────────────────────────────────
@app.post("/api/evidence")
async def receive_evidence(payload: EvidencePayload):
    aid = payload.agent_id
    decrypted = _decrypt(aid, PSK, payload.data)
    evidence_data = decrypted or {}

    entry = {
        "agent_id":    aid,
        "seq":         payload.seq,
        "received_at": _utcnow(),
        "summary":     payload.plain_summary,
        "evidence":    evidence_data.get("evidence", {}),
        "hostname":    evidence_data.get("hostname",
                        payload.plain_summary.get("hostname","")),
        "decrypted":   decrypted is not None,
        "case_id":     evidence_data.get("case_id", CASE_ID),
        "suspicious":  evidence_data.get("suspicious", 0),
    }
    _evidence.append(entry)
    if len(_evidence) > 5000: _evidence.pop(0)

    if aid in _agents:
        _agents[aid]["evidence_count"] = _agents[aid].get("evidence_count",0) + 1
        _agents[aid]["state"] = "IDLE"
        _agents[aid]["last_seen"] = _utcnow()

    # update task status
    for tid, task in _tasks.items():
        if task.get("agent_id") == aid and task.get("status") == "SENT":
            task["status"] = "COMPLETE"
            task["completed_at"] = _utcnow()
            break

    block_index = -1
    if _blockchain:
        try:
            block = _blockchain.add_event("EVIDENCE_COLLECTED", {
                "agent_id":   aid,
                "hostname":   entry["hostname"],
                "seq":        payload.seq,
                "collectors": payload.plain_summary.get("collectors",[]),
                "suspicious": entry["suspicious"],
                "case_id":    entry["case_id"],
            })
            block_index = block.index
            if entry["suspicious"] > 0:
                _blockchain.add_event("ANOMALY_DETECTED", {
                    "agent_id":       aid,
                    "suspicious_count":entry["suspicious"],
                })
        except Exception as e:
            log.warning(f"blockchain: {e}")

    # save to disk
    try:
        ef = EVIDENCE_DIR / f"evidence_{aid}_{payload.seq:06d}.json"
        ef.write_text(json.dumps(entry, default=str, indent=2), encoding="utf-8")
    except Exception: pass

    _broadcast({
        "type":        "evidence",
        "agent_id":    aid,
        "seq":         payload.seq,
        "hostname":    entry["hostname"],
        "summary":     payload.plain_summary,
        "suspicious":  entry["suspicious"],
        "block_index": block_index,
        "evidence":    entry["evidence"],
        "ts":          time.time(),
    })

    return {"ok": True, "block": block_index, "received_at": entry["received_at"]}

# ── query endpoints ───────────────────────────────────────────────────────────
@app.get("/agents")
def list_agents():
    return {"agents": _agents, "count": len(_agents)}

@app.get("/health")
def health():
    return {
        "ok":          True,
        "agents":      len(_agents),
        "tasks":       len(_tasks),
        "evidence":    len(_evidence),
        "blockchain":  _blockchain.length if _blockchain else 0,
        "pending":     sum(len(q) for q in _pending.values()),
        "timestamp":   time.time(),
    }

@app.get("/api/tasks")
def list_tasks():
    return {"tasks": list(_tasks.values()), "count": len(_tasks)}

@app.get("/api/evidence")
def list_evidence(agent_id: Optional[str] = None, limit: int = 100):
    items = _evidence
    if agent_id: items = [e for e in items if e["agent_id"]==agent_id]
    return {"count":len(items),"items":items[-limit:]}

@app.get("/api/scripts/builtins")
def list_builtins():
    return {"scripts": [
        {"name":k,
         "desc":v["desc"],
         "collectors":v["collectors"],
         "flags":v.get("flags",[]),
         "alert":v.get("alert","")}
        for k,v in BUILTIN_SCRIPTS.items()
    ]}

@app.get("/api/collectors")
def list_collectors():
    return {"collectors": [
        {"name":k,"desc":v["desc"],"platform":v["platform"]}
        for k,v in COLLECTORS.items()
    ]}

@app.get("/coc/summary")
def coc_summary():
    if not _blockchain: return {"error":"not init"}
    return _blockchain.summary()

@app.get("/coc/blocks")
def coc_blocks(event_type: Optional[str] = None):
    if not _blockchain: return {"blocks":[]}
    blocks = _blockchain.get_events(event_type)
    return {"count":len(blocks),"blocks":[b.to_dict() for b in blocks]}

@app.get("/coc/verify")
def coc_verify():
    if not _blockchain: return {"verified":False,"report":"not init"}
    ok, report = _blockchain.verify()
    return {"verified":ok,"report":report,"blocks":_blockchain.length}

@app.get("/stream")
async def event_stream():
    async def generate() -> AsyncIterator[str]:
        yield 'data: {"type":"connected"}\n\n'
        while True:
            try:
                event = await asyncio.wait_for(_sse_queue.get(), timeout=30)
                yield f"data: {json.dumps(event, default=str)}\n\n"
            except asyncio.TimeoutError:
                yield 'data: {"type":"ping"}\n\n'
            except Exception:
                break
    return StreamingResponse(generate(), media_type="text/event-stream",
                              headers={"Cache-Control":"no-cache",
                                       "X-Accel-Buffering":"no"})

@app.get("/", response_class=HTMLResponse)
async def root():
    html = _ROOT / "management_interface" / "dashboard" / "index.html"
    if html.exists():
        return HTMLResponse(content=html.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>JOCKY C2 v2</h1>")

@app.post("/demo/seed")
async def seed_demo():
    demo = [
        {"agent_id":"jocky-dc01", "hostname":"NTRO-DC-01",    "platform":"windows"},
        {"agent_id":"jocky-ws01", "hostname":"NTRO-FINANCE",  "platform":"windows"},
        {"agent_id":"jocky-mob01","hostname":"NTRO-MOBILE-01","platform":"android"},
    ]
    for a in demo:
        _agents[a["agent_id"]] = {**a,"state":"DORMANT",
                                   "first_seen":_utcnow(),"last_seen":_utcnow(),
                                   "evidence_count":0,"via":"USB"}
        _pending[a["agent_id"]] = deque()
        if _blockchain:
            try:
                _blockchain.add_event("AGENT_DEPLOYED",
                    {"action":"AGENT_CONNECTED","agent_id":a["agent_id"],
                     "hostname":a["hostname"],"platform":a["platform"],"via":"USB"})
            except Exception: pass
    _broadcast({"type":"demo_seeded","agents":[a["agent_id"] for a in demo],"ts":time.time()})
    return {"ok":True,"agents":[a["agent_id"] for a in demo]}

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--host",  default="0.0.0.0")
    ap.add_argument("--port",  type=int, default=8000)
    ap.add_argument("--case",  default="NTRO-2026-001")
    args = ap.parse_args()
    CASE_ID = args.case
    logging.basicConfig(level=logging.INFO,
                        format="[%(asctime)s] %(name)s %(levelname)s: %(message)s")
    print("\n  JOCKY C2 Server v2 — Task Dispatch + Dormant Agent Support")
    print(f"  Dashboard:   http://127.0.0.1:{args.port}/")
    print(f"  Health:      http://127.0.0.1:{args.port}/health")
    print(f"  Builtins:    http://127.0.0.1:{args.port}/api/scripts/builtins")
    print()
    uvicorn.run("c2_server_v2:app", host=args.host, port=args.port,
                reload=False, log_level="info", app_dir=str(_HERE))
