"""
server/c2_server.py -- JOCKY C2 Server
=======================================
Receives real forensic evidence from deployed agents.
For every POST /api/evidence:
  1. Parse + log the evidence bundle
  2. Append EVIDENCE_COLLECTED block to forensic blockchain
  3. Fire SSE event to all connected dashboard tabs
  4. Return block index to agent

Also serves the live dashboard at GET /

Run:
  cd D:\\Dinku\\projects\\JOCKY
  python server/c2_server.py --host 0.0.0.0 --port 8000
  # then on target machine:
  python agent/main.py --c2 http://<your_ip>:8000 --interval 60
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import struct
import sys
import time
from datetime   import datetime, timezone
from pathlib    import Path
from typing     import Any, AsyncIterator, Dict, List, Optional

import uvicorn
from fastapi              import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses    import StreamingResponse, HTMLResponse
from pydantic             import BaseModel

# ── path bootstrap ────────────────────────────────────────────────────────────
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
for _p in [str(_ROOT), str(_ROOT/"integrity")]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from blockchain import ForensicBlockchain

log = logging.getLogger("jocky.c2")

# ── config ────────────────────────────────────────────────────────────────────
PSK         = b"JOCKY_DEMO_PSK_32_BYTES_12345678"
CASE_ID     = "NTRO-2025-001"
INVESTIGATOR= "INV-ALPHA"
EVIDENCE_DIR = _ROOT / "evidence"
EVIDENCE_DIR.mkdir(exist_ok=True)

# ── FastAPI ───────────────────────────────────────────────────────────────────
app = FastAPI(title="JOCKY C2 Server", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

# ── in-memory state ───────────────────────────────────────────────────────────
_agents:     Dict[str, Dict] = {}   # agent_id -> {hostname, last_seen, count}
_evidence:   List[Dict]      = []   # all received evidence bundles
_sse_queue:  asyncio.Queue   = asyncio.Queue(maxsize=512)
_blockchain: Optional[ForensicBlockchain] = None

# ── AES-256-GCM decrypt ───────────────────────────────────────────────────────
AES_KEY_LEN   = 32
GCM_NONCE_LEN = 12
GCM_TAG_LEN   = 16
JOCKY_MAGIC   = 0x4A4F4B59

def _derive_key(psk: bytes, agent_id: str) -> bytes:
    prk = hmac.new(b"jocky-salt-v1", psk, hashlib.sha256).digest()
    return hmac.new(prk, agent_id.encode() + b"\x01", hashlib.sha256).digest()

def _decrypt(agent_id: str, psk: bytes, b64_data: str) -> Optional[dict]:
    """Decrypt an agent evidence bundle. Returns plaintext dict or None."""
    try:
        raw = base64.b64decode(b64_data)
        nonce  = raw[:GCM_NONCE_LEN]
        ct_tag = raw[GCM_NONCE_LEN:]
        key    = _derive_key(psk, agent_id)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        pt = AESGCM(key).decrypt(nonce, ct_tag, agent_id.encode())
        # parse JOCKY wire format
        magic, msg_type, payload_len = struct.unpack(">III", pt[:12])
        if magic != JOCKY_MAGIC:
            log.warning(f"bad magic from {agent_id}: 0x{magic:08X}")
            return None
        payload_bytes = pt[12:12+payload_len]
        return json.loads(payload_bytes.decode("utf-8"))
    except Exception as e:
        log.warning(f"decrypt failed for {agent_id}: {e}")
        return None

# ── startup ───────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def on_startup():
    global _blockchain
    _blockchain = ForensicBlockchain(
        case_id      = CASE_ID,
        investigator = INVESTIGATOR,
        chain_file   = str(EVIDENCE_DIR / f"blockchain_{CASE_ID}.json"),
        key_file     = str(EVIDENCE_DIR / f"inv_key_{CASE_ID}.pem"),
    )
    log.info(f"[c2] blockchain ready: {_blockchain.length} blocks")
    log.info(f"[c2] C2 server started -- listening for agents")

# ── SSE broadcast ─────────────────────────────────────────────────────────────
def _broadcast(event: dict):
    try: _sse_queue.put_nowait(event)
    except asyncio.QueueFull: pass

# ── Models ────────────────────────────────────────────────────────────────────
class CheckinPayload(BaseModel):
    agent_id:  str
    hostname:  str = ""
    platform:  str = ""
    timestamp: str = ""

class EvidencePayload(BaseModel):
    agent_id:      str
    seq:           int
    data:          str          # AES-256-GCM encrypted, base64
    plain_summary: dict = {}    # unencrypted quick summary

# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    html_path = _ROOT / "management_interface" / "dashboard" / "index.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>JOCKY C2</h1><p>Dashboard index.html not found</p>")

@app.get("/health")
def health():
    return {"ok": True, "agents": len(_agents),
            "evidence_received": len(_evidence),
            "blockchain_blocks":  _blockchain.length if _blockchain else 0,
            "timestamp": time.time()}

@app.post("/api/checkin")
async def checkin(payload: CheckinPayload):
    """Agent announces itself. No evidence yet."""
    _agents[payload.agent_id] = {
        "agent_id":  payload.agent_id,
        "hostname":  payload.hostname,
        "platform":  payload.platform,
        "first_seen": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_seen":  datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "evidence_count": 0,
        "state": "CONNECTED",
    }
    log.info(f"[c2] checkin: {payload.agent_id} from {payload.hostname}")

    # add blockchain event
    if _blockchain:
        _blockchain.add_event("AGENT_DEPLOYED", {
            "agent_id": payload.agent_id,
            "hostname": payload.hostname,
            "platform": payload.platform,
        })

    _broadcast({"type":"checkin","agent_id":payload.agent_id,
                 "hostname":payload.hostname,"ts":time.time()})
    return {"ok": True, "case_id": CASE_ID}

@app.post("/api/evidence")
async def receive_evidence(payload: EvidencePayload):
    """
    Receive AES-256-GCM encrypted evidence bundle from agent.
    Decrypt, log, append blockchain, fire SSE.
    """
    agent_id = payload.agent_id
    log.info(f"[c2] evidence from {agent_id} seq={payload.seq} "
             f"encrypted_bytes={len(payload.data)}")

    # decrypt
    decrypted = _decrypt(agent_id, PSK, payload.data)
    if decrypted is None:
        log.warning(f"[c2] decrypt failed for {agent_id} -- storing plain summary")
        evidence_data = payload.plain_summary
    else:
        evidence_data = decrypted

    # store
    entry = {
        "agent_id":    agent_id,
        "seq":         payload.seq,
        "received_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary":     payload.plain_summary,
        "evidence":    evidence_data.get("evidence", {}) if decrypted else {},
        "hostname":    evidence_data.get("hostname","") if decrypted else payload.plain_summary.get("hostname",""),
        "decrypted":   decrypted is not None,
    }
    _evidence.append(entry)
    if len(_evidence) > 2000:
        _evidence.pop(0)

    # update agent state
    if agent_id in _agents:
        _agents[agent_id]["last_seen"] = entry["received_at"]
        _agents[agent_id]["evidence_count"] = _agents[agent_id].get("evidence_count",0) + 1
        _agents[agent_id]["state"] = "COLLECTING"
    else:
        _agents[agent_id] = {
            "agent_id": agent_id,
            "hostname": entry["hostname"],
            "last_seen": entry["received_at"],
            "evidence_count": 1,
            "state": "COLLECTING",
        }

    # append blockchain
    block_index = -1
    if _blockchain:
        try:
            summary = payload.plain_summary
            block = _blockchain.add_event("EVIDENCE_COLLECTED", {
                "agent_id":    agent_id,
                "hostname":    entry["hostname"],
                "seq":         payload.seq,
                "collectors":  summary.get("collectors", []),
                "proc_count":  summary.get("proc_count", 0),
                "net_count":   summary.get("net_count", 0),
                "suspicious":  summary.get("suspicious", 0),
                "decrypted":   entry["decrypted"],
            })
            block_index = block.index
            log.info(f"[c2] blockchain block #{block_index} for {agent_id}")
        except Exception as e:
            log.warning(f"[c2] blockchain append failed: {e}")

    # anomaly detection — if suspicious items found, add ANOMALY block
    if payload.plain_summary.get("suspicious", 0) > 0 and _blockchain:
        try:
            _blockchain.add_event("ANOMALY_DETECTED", {
                "agent_id":  agent_id,
                "suspicious_count": payload.plain_summary.get("suspicious", 0),
                "seq": payload.seq,
            })
        except Exception: pass

    # fire SSE to dashboard
    _broadcast({
        "type":         "evidence",
        "agent_id":     agent_id,
        "seq":          payload.seq,
        "hostname":     entry["hostname"],
        "summary":      payload.plain_summary,
        "block_index":  block_index,
        "ts":           time.time(),
        # live evidence keys for dashboard display
        "evidence_keys": list(evidence_data.get("evidence",{}).keys()) if decrypted else [],
    })

    # save evidence to disk
    ev_file = EVIDENCE_DIR / f"evidence_{agent_id}_{payload.seq:06d}.json"
    try:
        ev_file.write_text(json.dumps(entry, default=str, indent=2), encoding="utf-8")
    except Exception as e:
        log.warning(f"[c2] save evidence: {e}")

    return {"ok": True, "block": block_index,
            "received_at": entry["received_at"]}

# ── Query endpoints ───────────────────────────────────────────────────────────

@app.get("/agents")
def list_agents():
    return {"agents": _agents, "count": len(_agents)}

@app.get("/api/evidence")
def list_evidence(agent_id: Optional[str] = None, limit: int = 50):
    items = _evidence
    if agent_id: items = [e for e in items if e["agent_id"] == agent_id]
    return {"count": len(items), "items": items[-limit:]}

@app.get("/api/evidence/{agent_id}/latest")
def latest_evidence(agent_id: str):
    items = [e for e in _evidence if e["agent_id"] == agent_id]
    if not items: raise HTTPException(404, "no evidence for agent")
    latest = items[-1]
    # include full evidence data
    return latest

@app.get("/coc/summary")
def coc_summary():
    if not _blockchain: return {"error":"blockchain not init"}
    return _blockchain.summary()

@app.get("/coc/blocks")
def coc_blocks(event_type: Optional[str] = None):
    if not _blockchain: return {"blocks":[]}
    blocks = _blockchain.get_events(event_type)
    return {"count":len(blocks),"blocks":[b.to_dict() for b in blocks]}

@app.get("/coc/verify")
def coc_verify():
    if not _blockchain: return {"verified":False,"report":"blockchain not init"}
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
                              headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@app.post("/demo/seed")
async def seed_demo():
    """Inject demo evidence for SIH presentation without a real target."""
    if not _blockchain:
        return {"ok":False,"error":"blockchain not ready"}

    demo_agents = [
        {"agent_id":"jocky-dc01","hostname":"NTRO-DC-01","platform":"Windows Server 2022"},
        {"agent_id":"jocky-ws01","hostname":"NTRO-WS-FINANCE","platform":"Windows 11 Pro"},
        {"agent_id":"jocky-srv02","hostname":"NTRO-FILE-SERVER","platform":"Windows Server 2019"},
    ]
    for a in demo_agents:
        _agents[a["agent_id"]] = {**a,"last_seen":datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                   "evidence_count":3,"state":"IDLE"}

    # seed blockchain events
    events = [
        ("AGENT_DEPLOYED", {"agent_id":"jocky-dc01","hostname":"NTRO-DC-01"}),
        ("AGENT_DEPLOYED", {"agent_id":"jocky-ws01","hostname":"NTRO-WS-FINANCE"}),
        ("AGENT_DEPLOYED", {"agent_id":"jocky-srv02","hostname":"NTRO-FILE-SERVER"}),
        ("TASK_DISPATCHED",{"cmd":"proc_list","agents":3}),
        ("EVIDENCE_COLLECTED",{"agent_id":"jocky-dc01","collectors":["proc_list","net_state"],"proc_count":87,"suspicious":2}),
        ("ANOMALY_DETECTED", {"agent_id":"jocky-dc01","threat":"mimikatz.exe in prefetch","suspicious_count":2}),
        ("EVIDENCE_COLLECTED",{"agent_id":"jocky-ws01","collectors":["reg_persistence","event_log"],"suspicious":1}),
        ("EVIDENCE_COLLECTED",{"agent_id":"jocky-srv02","collectors":["browser_hist","scheduled_tasks"],"suspicious":0}),
        ("CHAIN_VERIFIED",   {"blocks":8,"result":"INTACT"}),
    ]
    block_indices = []
    for ev_type, data in events:
        try:
            block = _blockchain.add_event(ev_type, data)
            block_indices.append(block.index)
        except Exception: pass

    # fire SSE for demo evidence
    for a in demo_agents:
        _broadcast({"type":"evidence","agent_id":a["agent_id"],"hostname":a["hostname"],
                    "summary":{"collectors":["proc_list","net_state"],"proc_count":87,"suspicious":2},
                    "ts":time.time()})
    return {"ok":True,"agents":len(demo_agents),"blockchain_blocks":block_indices}

# ── entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--case", default="NTRO-2025-001")
    args = ap.parse_args()
    CASE_ID = args.case

    logging.basicConfig(level=logging.INFO,
                        format="[%(asctime)s] %(name)s %(levelname)s: %(message)s")
    print("\n  JOCKY C2 Server + Dashboard")
    print("  ================================")
    print(f"  Listening:  http://{args.host}:{args.port}")
    print(f"  Dashboard:  http://127.0.0.1:{args.port}/")
    print(f"  Health:     http://127.0.0.1:{args.port}/health")
    print(f"  Chain:      http://127.0.0.1:{args.port}/coc/verify")
    print(f"  Live feed:  http://127.0.0.1:{args.port}/stream")
    print()
    print("  On target machine run:")
    print(f"    python agent/main.py --c2 http://<THIS_IP>:{args.port} --interval 60")
    print()
    uvicorn.run("c2_server:app", host=args.host, port=args.port,
                reload=False, log_level="info",
                app_dir=str(_HERE))
