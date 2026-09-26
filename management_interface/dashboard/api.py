# management_interface/dashboard/api.py
# [JOCKY phase 17 -- management dashboard API + integrity integration]
#
# PURPOSE
# -------
# FastAPI backend serving the investigator dashboard.
# Exposes REST endpoints for:
#   - Agent status and health monitoring
#   - Task dispatch to deployed agents
#   - Evidence retrieval with integrity verification
#   - Hash-chain log access and signing
#   - Real-time SSE (Server-Sent Events) for live agent updates
#
# INTEGRITY INTEGRATION
# ----------------------
# Every result collected from an agent is immediately appended to that
# agent's hash-chain log (Phase 17 integrity engine). The chain is
# Ed25519-signed so evidence is court-admissible from the moment
# it lands in the dashboard.
#
# RUN
# ---
#   python management_interface/dashboard/api.py
#   # opens at http://127.0.0.1:8000
#   # docs at  http://127.0.0.1:8000/docs
#
# *the investigator opens a browser. every agent is visible.
#  every byte of evidence is signed before the screen finishes loading.*

from __future__ import annotations
import sys, pathlib
_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
for _p in [str(_ROOT),
           str(_ROOT / 'integrity'),
           str(_ROOT / 'language' / 'lexer_parser'),
           str(_ROOT / 'build_pipeline' / 'obfuscator')]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

import asyncio
import json
import logging
import time
from pathlib import Path
from typing  import Any, AsyncIterator, Dict, List, Optional

import uvicorn
from fastapi              import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses    import StreamingResponse, JSONResponse
from pydantic             import BaseModel
from fastapi.responses    import HTMLResponse
# ── JOCKY internal imports ────────────────────────────────────────────────────
from management_interface.agent_controller import AgentController, AgentState
from hash_chain import HashChain
from signing    import ChainSigner
from verifier   import verify_chain

log = logging.getLogger("jocky.dashboard")

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title       = "JOCKY Forensic Dashboard",
    description = "Multi-agent forensic intelligence framework — SIH 2025",
    version     = "1.0.0",
    docs_url    = "/docs",
    redoc_url   = "/redoc",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins  = ["*"],
    allow_methods  = ["*"],
    allow_headers  = ["*"],
)

# ── Global controller + integrity state ──────────────────────────────────────
controller    = AgentController()
_chains:      Dict[str, HashChain]   = {}   # agent_id -> HashChain
_signers:     Dict[str, ChainSigner] = {}   # agent_id -> ChainSigner
_evidence_dir = _ROOT / "evidence"
_evidence_dir.mkdir(exist_ok=True)

# SSE broadcast queue — all connected dashboard clients receive live updates
_sse_queue: asyncio.Queue = asyncio.Queue(maxsize=256)


# ── Startup / shutdown ────────────────────────────────────────────────────────

@app.on_event("startup")
async def on_startup() -> None:
    # wire the controller's result callback -> integrity chain + SSE push
    controller.set_result_callback(_on_agent_result_with_blockchain)
    controller.start()
    log.info("[dashboard] started -- controller running")

@app.on_event("shutdown")
async def on_shutdown() -> None:
    controller.stop()
    log.info("[dashboard] stopped")


# ── Integrity helpers ─────────────────────────────────────────────────────────

def _get_chain(agent_id: str) -> HashChain:
    """Get or create the hash-chain for an agent."""
    if agent_id not in _chains:
        chain_path = _evidence_dir / f"chain_{agent_id}.json"
        _chains[agent_id] = HashChain(str(chain_path))
    return _chains[agent_id]

def _get_signer(agent_id: str) -> ChainSigner:
    """Get or create the Ed25519 signer for an agent."""
    if agent_id not in _signers:
        key_path = _evidence_dir / f"key_{agent_id}.pem"
        _signers[agent_id] = ChainSigner(str(key_path))
    return _signers[agent_id]

def _on_agent_result(agent_id: str, result: dict) -> None:
    """
    Callback fired by AgentController whenever a result arrives.
    1. Append to agent's hash-chain (integrity)
    2. Sign the entry (court-admissible)
    3. Push to SSE queue (live dashboard update)

    *evidence lands, is hashed, is signed, in the same heartbeat.*
    """
    try:
        chain   = _get_chain(agent_id)
        signer  = _get_signer(agent_id)
        entry_id = chain.append(
            event = "evidence",
            data  = result,
        )
        signer.sign_entry(chain, entry_id)
        log.info(f"[dashboard] chain entry #{entry_id} signed: {agent_id}")
    except Exception as e:
        log.warning(f"[dashboard] integrity chain error for {agent_id}: {e}")

    # push live update to SSE clients (non-blocking)
    event = {
        "type":     "result",
        "agent_id": agent_id,
        "data":     result,
        "ts":       time.time(),
    }
    try:
        _sse_queue.put_nowait(event)
    except asyncio.QueueFull:
        pass   # drop if no clients are listening


# ── Pydantic request models ───────────────────────────────────────────────────

class RegisterAgentRequest(BaseModel):
    agent_id:   str
    psk_hex:    str          # 32-byte PSK as hex string (64 chars)
    c2_backend: str
    cdn_fronts: Optional[List[str]] = None
    label:      Optional[str]       = None

class TaskRequest(BaseModel):
    cmd_type: str
    args:     Dict[str, Any] = {}

class BroadcastRequest(BaseModel):
    cmd_type: str
    args:     Dict[str, Any] = {}


# ── Endpoints ─────────────────────────────────────────────────────────────────

# ── / health ──────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse, tags=["meta"])
def root():
    html = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(content=html)

@app.get("/health", tags=["meta"])
def health() -> dict:
    snap = controller.status()
    return {
        "ok":          True,
        "agents":      snap["agent_count"],
        "pending":     snap["pending_tasks"],
        "total_tasks": snap["total_tasks"],
        "timestamp":   snap["timestamp"],
    }


# ── /agents ────────────────────────────────────────────────────────────────────
@app.get("/agents", tags=["agents"])
def list_agents() -> dict:
    """Return status of all registered agents."""
    snap = controller.status()
    return snap

@app.post("/agents", tags=["agents"])
def register_agent(req: RegisterAgentRequest) -> dict:
    """Register a new target agent."""
    try:
        psk = bytes.fromhex(req.psk_hex)
        if len(psk) != 32:
            raise ValueError("PSK must be exactly 32 bytes (64 hex chars)")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    controller.register_agent(
        agent_id   = req.agent_id,
        psk        = psk,
        c2_backend = req.c2_backend,
        cdn_fronts = req.cdn_fronts,
        label      = req.label,
        chain_path = str(_evidence_dir / f"chain_{req.agent_id}.json"),
    )
    return {"ok": True, "agent_id": req.agent_id, "label": req.label}

@app.get("/agents/{agent_id}", tags=["agents"])
def agent_detail(agent_id: str) -> dict:
    """Get detailed status for one agent."""
    status = controller.agent_status(agent_id)
    if not status:
        raise HTTPException(status_code=404, detail=f"agent not found: {agent_id}")
    return status

@app.delete("/agents/{agent_id}", tags=["agents"])
def deregister_agent(agent_id: str) -> dict:
    """Remove an agent from the controller."""
    controller.deregister_agent(agent_id)
    return {"ok": True, "agent_id": agent_id}


# ── /agents/{id}/tasks ────────────────────────────────────────────────────────
@app.post("/agents/{agent_id}/tasks", tags=["tasks"])
def dispatch_task(agent_id: str, req: TaskRequest) -> dict:
    """
    Dispatch a forensic task to a specific agent.

    cmd_type examples:
        proc_list    -- running process enumeration
        mem_acquire  -- process memory dump
        reg_walk     -- registry hive walk
        net_state    -- active network connections
        fs_analysis  -- filesystem artifact collection
    """
    try:
        task_id = controller.task(agent_id, req.cmd_type, req.args)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return {"ok": True, "task_id": task_id,
            "agent_id": agent_id, "cmd_type": req.cmd_type}

@app.get("/agents/{agent_id}/tasks/{task_id}", tags=["tasks"])
def get_task_status(agent_id: str, task_id: str) -> dict:
    """Check status of a dispatched task."""
    task = controller.get_task(task_id)
    if not task or task.agent_id != agent_id:
        raise HTTPException(status_code=404, detail="task not found")
    return {
        "task_id":     task.task_id,
        "agent_id":    task.agent_id,
        "cmd_type":    task.cmd_type,
        "args":        task.args,
        "status":      task.status.name,
        "created_at":  task.created_at,
        "sent_at":     task.sent_at,
        "completed_at":task.completed_at,
        "elapsed_sec": task.elapsed,
        "result":      task.result,
        "error":       task.error,
    }


# ── /broadcast ────────────────────────────────────────────────────────────────
@app.post("/broadcast", tags=["tasks"])
def broadcast(req: BroadcastRequest) -> dict:
    """Dispatch a task to ALL registered agents simultaneously."""
    task_ids = controller.broadcast(req.cmd_type, req.args)
    return {"ok": True, "cmd_type": req.cmd_type,
            "dispatched_to": len(task_ids), "task_ids": task_ids}


# ── /agents/{id}/results ──────────────────────────────────────────────────────
@app.get("/agents/{agent_id}/results", tags=["evidence"])
def get_results(agent_id:   str,
                since:      float = 0.0,
                cmd_filter: Optional[str] = None) -> dict:
    """Retrieve collected evidence from an agent."""
    results = controller.results(agent_id,
                                  since=since,
                                  cmd_filter=cmd_filter)
    return {
        "agent_id": agent_id,
        "count":    len(results),
        "results":  results,
    }

@app.get("/results", tags=["evidence"])
def all_results() -> dict:
    """Retrieve all evidence from all agents."""
    data = controller.all_results()
    total = sum(len(v) for v in data.values())
    return {"total": total, "by_agent": data}


# ── /integrity ────────────────────────────────────────────────────────────────
@app.get("/integrity/{agent_id}", tags=["integrity"])
def get_chain(agent_id: str) -> dict:
    """
    Return the full hash-chain for an agent's evidence log.
    Each entry is SHA-256 chained and Ed25519-signed.
    """
    chain_path = _evidence_dir / f"chain_{agent_id}.json"
    if not chain_path.exists():
        raise HTTPException(status_code=404,
                            detail=f"no chain for agent: {agent_id}")
    try:
        with open(chain_path, encoding="utf-8") as f:
            chain_data = json.load(f)
        return {"agent_id": agent_id, "chain": chain_data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/integrity/{agent_id}/verify", tags=["integrity"])
def verify_agent_chain(agent_id: str) -> dict:
    """
    Verify the integrity of an agent's evidence chain.
    Returns verification status and a human-readable report.
    *the chain either holds or it doesn't. there is no almost.*
    """
    chain_path = _evidence_dir / f"chain_{agent_id}.json"
    key_path   = _evidence_dir / f"key_{agent_id}.pem"

    if not chain_path.exists():
        raise HTTPException(status_code=404,
                            detail=f"no chain for agent: {agent_id}")

    key_hex = None
    if key_path.exists():
        try:
            signer  = ChainSigner(str(key_path))
            key_hex = getattr(signer, "_public_key_hex", None)
        except Exception:
            pass

    ok, report = verify_chain(str(chain_path), public_key_hex=key_hex)
    return {
        "agent_id": agent_id,
        "verified": ok,
        "report":   report,
    }

# ── add to api.py: blockchain chain of custody ────────────────────────────────

import sys as _sys2, pathlib as _pl2
_sys2.path.insert(0, str(_pl2.Path(__file__).resolve().parent.parent.parent / "integrity"))
from blockchain import ForensicBlockchain

# global blockchain per case
_blockchains: Dict[str, ForensicBlockchain] = {}
_DEFAULT_CASE = "NTRO-2025-001"
_DEFAULT_INV  = "INV-ALPHA"


def _get_blockchain(case_id: str = _DEFAULT_CASE) -> ForensicBlockchain:
    if case_id not in _blockchains:
        _blockchains[case_id] = ForensicBlockchain(
            case_id      = case_id,
            investigator = _DEFAULT_INV,
            chain_file   = str(_evidence_dir / f"blockchain_{case_id}.json"),
            key_file     = str(_evidence_dir / f"inv_key_{case_id}.pem"),
        )
    return _blockchains[case_id]


# wire blockchain into result callback (call this from on_startup)
def _on_agent_result_with_blockchain(agent_id: str, result: dict) -> None:
    _on_agent_result(agent_id, result)   # existing hash-chain
    try:
        bc = _get_blockchain()
        bc.add_event("EVIDENCE_COLLECTED", {
            "agent_id": agent_id,
            "cmd_type": result.get("cmd_type"),
            "task_id":  result.get("task_id"),
            "bytes":    len(str(result.get("data", ""))),
        })
    except Exception as e:
        log.warning(f"[blockchain] add_event failed: {e}")


@app.get("/coc/summary", tags=["chain-of-custody"])
def coc_summary(case_id: str = _DEFAULT_CASE) -> dict:
    """Return blockchain summary for a case."""
    return _get_blockchain(case_id).summary()


@app.get("/coc/blocks", tags=["chain-of-custody"])
def coc_blocks(case_id: str = _DEFAULT_CASE,
               event_type: Optional[str] = None) -> dict:
    """Return all blocks, optionally filtered by event type."""
    bc = _get_blockchain(case_id)
    blocks = bc.get_events(event_type)
    return {"case_id": case_id, "count": len(blocks),
            "blocks": [b.to_dict() for b in blocks]}


@app.get("/coc/blocks/{index}", tags=["chain-of-custody"])
def coc_block(index: int, case_id: str = _DEFAULT_CASE) -> dict:
    """Return a specific block by index."""
    block = _get_blockchain(case_id).get_block(index)
    if not block:
        raise HTTPException(status_code=404, detail=f"block {index} not found")
    return block.to_dict()


@app.get("/coc/verify", tags=["chain-of-custody"])
def coc_verify(case_id: str = _DEFAULT_CASE) -> dict:
    """Verify the full blockchain integrity."""
    ok, report = _get_blockchain(case_id).verify()
    return {"case_id": case_id, "verified": ok, "report": report}


@app.post("/coc/event", tags=["chain-of-custody"])
def coc_add_event(event_type: str,
                  data: Dict[str, Any] = {},
                  case_id: str = _DEFAULT_CASE) -> dict:
    """Manually append an event to the blockchain."""
    block = _get_blockchain(case_id).add_event(event_type, data)
    return {"ok": True, "block_index": block.index, "hash": block.hash}
# ── /stream (SSE live feed) ───────────────────────────────────────────────────
@app.get("/stream", tags=["live"])
async def event_stream() -> StreamingResponse:
    """
    Server-Sent Events endpoint for live dashboard updates.
    Connect with EventSource('/stream') in the React dashboard.
    Each event carries: agent_id, result data, timestamp.

    *the dashboard listens. agents speak. the stream never closes.*
    """
    async def generate() -> AsyncIterator[str]:
        yield "data: {\"type\": \"connected\"}\n\n"
        while True:
            try:
                event = await asyncio.wait_for(_sse_queue.get(), timeout=30)
                yield f"data: {json.dumps(event)}\n\n"
            except asyncio.TimeoutError:
                # keepalive ping every 30s
                yield "data: {\"type\": \"ping\"}\n\n"
            except Exception:
                break

    return StreamingResponse(
        generate(),
        media_type = "text/event-stream",
        headers    = {
            "Cache-Control":   "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ── demo endpoint (SIH demo mode) ────────────────────────────────────────────
@app.post("/demo/seed", tags=["demo"])
def seed_demo_data() -> dict:
    """
    Seed the dashboard with demo agents and synthetic evidence.
    Called during SIH presentation to populate the UI instantly.
    """
    import secrets, hashlib

    demo_agents = [
        {"id": "agent-dc01",  "label": "TARGET-DC01 (Domain Controller)"},
        {"id": "agent-ws01",  "label": "TARGET-WORKSTATION-FINANCE"},
        {"id": "agent-srv02", "label": "TARGET-SERVER-02 (File Server)"},
    ]
    psk = b"JOCKY_DEMO_PSK_32_BYTES_12345678"

    for a in demo_agents:
        try:
            controller.register_agent(
                agent_id   = a["id"],
                psk        = psk,
                c2_backend = "demo.c2.example.com",
                label      = a["label"],
            )
        except Exception:
            pass  # already registered

        # inject synthetic evidence directly into chain
        chain  = _get_chain(a["id"])
        signer = _get_signer(a["id"])
        demo_results = [
            {"cmd": "proc_list",   "data": {"count": 87, "suspicious": ["mimikatz.exe"]}},
            {"cmd": "net_state",   "data": {"connections": 12, "external_ips": ["185.220.101.0"]}},
            {"cmd": "mem_acquire", "data": {"pid": 1234, "bytes_captured": 65536}},
        ]
        for r in demo_results:
            eid = chain.append(event="evidence", data=r)
            signer.sign_entry(chain, eid)

    return {
        "ok":     True,
        "seeded": [a["id"] for a in demo_agents],
        "msg":    "Demo data seeded -- open /docs to explore",
    }


# ── entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(
        level  = logging.INFO,
        format = "[%(asctime)s] %(name)s %(levelname)s: %(message)s",
    )
    print("\n  JOCKY Forensic Dashboard -- Phase 17")
    print("  ======================================")
    print("  API docs:  http://127.0.0.1:8000/docs")
    print("  Health:    http://127.0.0.1:8000/health")
    print("  Live feed: http://127.0.0.1:8000/stream")
    print("  Demo seed: POST http://127.0.0.1:8000/demo/seed\n")

    uvicorn.run(app, host="127.0.0.1", port=8000, reload=False)