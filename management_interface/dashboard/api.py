"""
JOCKY Management Dashboard — FastAPI Backend  (Phase 17)
=========================================================
Real-time multi-agent coordination API.

Endpoints:
  GET  /                    — Health check
  GET  /agents              — List all connected agents
  POST /agents/connect      — Connect to a new agent
  DELETE /agents/{id}       — Disconnect an agent
  POST /agents/{id}/command — Send a forensic command to an agent
  POST /agents/broadcast    — Broadcast command to all agents
  GET  /agents/{id}/results — Get all results from an agent
  GET  /chain/{path}        — Verify a hash-chain log
  POST /compile             — Compile a JOCKY script
  GET  /ws                  — WebSocket for real-time agent events

Run:
    pip install fastapi uvicorn websockets
    python management_interface/dashboard/api.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

# ─── Path bootstrap ───────────────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent.parent.parent
for _p in [
    str(_ROOT),
    str(_ROOT / "management_interface"),
    str(_ROOT / "integrity"),
    str(_ROOT / "language" / "lexer_parser"),
    str(_ROOT / "language" / "llvm_frontend"),
    str(_ROOT / "build_pipeline" / "polymorphic_engine"),
]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    import uvicorn
    _FASTAPI_OK = True
except ImportError:
    _FASTAPI_OK = False
    print("FastAPI not installed. Run: pip install fastapi uvicorn")
    sys.exit(1)

from pydantic import BaseModel
from agent_controller import AgentController
from hash_chain import HashChain
from verifier import verify_chain

# ─── App setup ────────────────────────────────────────────────────────────────

app = FastAPI(
    title       = "JOCKY Management Dashboard",
    description = "Real-time multi-agent forensic coordination API",
    version     = "1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins     = ["*"],   # Restrict in production
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

# Global controller instance
_controller = AgentController()

# WebSocket broadcast set
_ws_clients: set[WebSocket] = set()


# ─── Request/Response models ──────────────────────────────────────────────────

class ConnectRequest(BaseModel):
    host:     str
    port:     int   = 4444
    agent_id: str

class CommandRequest(BaseModel):
    command:   str
    primitive: str
    args:      dict[str, Any] = {}
    timeout:   float = 60.0

class CompileRequest(BaseModel):
    script_path: str
    obfuscate:   bool = False
    output_dir:  str  = ""


# ─── Health ───────────────────────────────────────────────────────────────────

@app.get("/")
async def health():
    return {
        "status":  "ok",
        "service": "JOCKY Management Dashboard",
        "version": "1.0.0",
        "agents":  len(_controller.list_agents()),
    }


# ─── Agent management ─────────────────────────────────────────────────────────

@app.get("/agents")
async def list_agents():
    """List all connected agents with their status."""
    return {"agents": _controller.list_agents()}


@app.post("/agents/connect")
async def connect_agent(req: ConnectRequest):
    """Connect to a JOCKY agent on a target machine."""
    try:
        session = await _controller.connect(req.host, req.port, req.agent_id)
        await _broadcast_event("agent_connected", {
            "agent_id": req.agent_id,
            "host":     req.host,
            "port":     req.port,
        })
        return {
            "status":    "connected",
            "agent_id":  session.agent_id,
            "connected_at": session.connected_at,
        }
    except (ConnectionError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.delete("/agents/{agent_id}")
async def disconnect_agent(agent_id: str):
    """Disconnect an agent."""
    await _controller.disconnect(agent_id)
    await _broadcast_event("agent_disconnected", {"agent_id": agent_id})
    return {"status": "disconnected", "agent_id": agent_id}


# ─── Command dispatch ─────────────────────────────────────────────────────────

@app.post("/agents/{agent_id}/command")
async def send_command(agent_id: str, req: CommandRequest):
    """Send a forensic command to a specific agent."""
    try:
        result = await _controller.send_command(
            agent_id  = agent_id,
            command   = req.command,
            primitive = req.primitive,
            args      = req.args,
            timeout   = req.timeout,
        )
        await _broadcast_event("command_result", {
            "agent_id":  agent_id,
            "command":   req.command,
            "primitive": req.primitive,
            "status":    result.get("status"),
        })
        return result
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except TimeoutError as exc:
        raise HTTPException(status_code=408, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/agents/broadcast")
async def broadcast_command(req: CommandRequest):
    """Send the same command to all connected agents simultaneously."""
    results = await _controller.broadcast_command(
        command   = req.command,
        primitive = req.primitive,
        args      = req.args,
        timeout   = req.timeout,
    )
    await _broadcast_event("broadcast_complete", {
        "command":   req.command,
        "primitive": req.primitive,
        "agents":    list(results.keys()),
    })
    return {"results": results}


@app.get("/agents/{agent_id}/results")
async def get_results(agent_id: str):
    """Get all accumulated forensic results from an agent."""
    try:
        results = _controller.get_results(agent_id)
        return {"agent_id": agent_id, "count": len(results), "results": results}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


# ─── Integrity chain ──────────────────────────────────────────────────────────

@app.get("/chain/verify")
async def verify_chain_endpoint(path: str, pubkey: str = ""):
    """Verify a JOCKY hash-chain integrity log."""
    if not Path(path).exists():
        raise HTTPException(status_code=404, detail=f"Chain file not found: {path}")
    ok, report = verify_chain(path, pubkey or None)
    return {"intact": ok, "report": report}


# ─── Compiler ─────────────────────────────────────────────────────────────────

@app.post("/compile")
async def compile_script(req: CompileRequest):
    """Compile a JOCKY script to a native binary."""
    script = Path(req.script_path)
    if not script.exists():
        raise HTTPException(status_code=404, detail=f"Script not found: {req.script_path}")

    # Run compilation in a subprocess to avoid blocking the event loop
    cmd = [sys.executable, str(_ROOT / "main.py"), "compile", str(script)]
    if req.obfuscate:
        cmd.append("--obfuscate")
    if req.output_dir:
        cmd.extend(["--output", req.output_dir])

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()

    success = proc.returncode == 0
    await _broadcast_event("compile_complete", {
        "script":  req.script_path,
        "success": success,
    })

    return {
        "success":   success,
        "stdout":    stdout.decode("utf-8", errors="replace"),
        "stderr":    stderr.decode("utf-8", errors="replace"),
        "exit_code": proc.returncode,
    }


# ─── WebSocket real-time events ───────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    """
    WebSocket endpoint for real-time agent event streaming.
    The React dashboard connects here to receive live updates.
    """
    await ws.accept()
    _ws_clients.add(ws)
    try:
        # Send current agent list on connect
        await ws.send_json({
            "event": "connected",
            "data":  {"agents": _controller.list_agents()},
        })
        # Keep connection alive
        while True:
            await ws.receive_text()   # ping/pong
    except WebSocketDisconnect:
        pass
    finally:
        _ws_clients.discard(ws)


async def _broadcast_event(event: str, data: dict) -> None:
    """Broadcast an event to all connected WebSocket clients."""
    if not _ws_clients:
        return
    msg = json.dumps({"event": event, "data": data})
    dead = set()
    for ws in _ws_clients:
        try:
            await ws.send_text(msg)
        except Exception:
            dead.add(ws)
    _ws_clients -= dead


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "api:app",
        host    = "127.0.0.1",
        port    = 8000,
        reload  = False,
        log_level = "info",
    )
