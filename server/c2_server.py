"""
server/c2_server.py -- JOCKY C2 Server
========================================
Receives encrypted forensic evidence from deployed agents.
Decrypts, classifies by scenario, appends to forensic blockchain,
fires SSE events to live dashboard.

Run:
  python server/c2_server.py --host 0.0.0.0 --port 8000
  python server/c2_server.py --host 0.0.0.0 --port 8000 --case NTRO-2025-001 --investigator INV-ALPHA
"""
from __future__ import annotations

import argparse
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
from datetime import datetime, timezone
from pathlib  import Path
from typing   import Any, AsyncIterator, Dict, List, Optional

# ── path bootstrap ────────────────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent.parent
for _p in [str(_ROOT), str(_ROOT / "integrity"),
           str(_ROOT / "management_interface")]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

import uvicorn
from fastapi              import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses    import HTMLResponse, JSONResponse, StreamingResponse

from blockchain import ForensicBlockchain
from hash_chain import HashChain
from signing    import ChainSigner

log = logging.getLogger("jocky.c2")

# ── config (overridable via CLI args) ────────────────────────────────────────
_CASE_ID     = "NTRO-2025-001"
_INVESTIGATOR= "INV-ALPHA"
_PSK         = b"JOCKY_DEMO_PSK_32_BYTES_12345678"
_EVIDENCE_DIR= _ROOT / "evidence"

# ── state ─────────────────────────────────────────────────────────────────────
_blockchain:  Optional[ForensicBlockchain] = None
_chains:      Dict[str, HashChain]         = {}
_signers:     Dict[str, ChainSigner]       = {}
_agents:      Dict[str, dict]              = {}
_sse_queue:   asyncio.Queue                = asyncio.Queue(maxsize=512)
_evidence_count = 0

# ── crypto (same HKDF as agent) ──────────────────────────────────────────────

def _derive_key(psk: bytes, agent_id: str) -> bytes:
    prk = hmac.new(b"jocky-salt-v1", psk, hashlib.sha256).digest()
    okm = hmac.new(prk, agent_id.encode() + b"\x01", hashlib.sha256).digest()
    return okm


def _decrypt_bundle(agent_id: str, data_b64: str) -> Optional[dict]:
    """AES-256-GCM decrypt an evidence bundle from the agent."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        raw  = base64.b64decode(data_b64)
        nonce, ct_tag = raw[:12], raw[12:]
        key  = _derive_key(_PSK, agent_id)
        pt   = AESGCM(key).decrypt(nonce, ct_tag, agent_id.encode())

        # unpack JOCKY wire format
        MAGIC, msg_type, payload_len = struct.unpack(">III", pt[:12])
        if MAGIC != 0x4A4F4B59:
            log.warning(f"bad magic from {agent_id}: 0x{MAGIC:08X}")
            return None
        payload_bytes = pt[12:12 + payload_len]
        return json.loads(payload_bytes.decode("utf-8"))
    except Exception as e:
        log.warning(f"decrypt failed for {agent_id}: {e}")
        return None


# ── anomaly detection ─────────────────────────────────────────────────────────

def _detect_anomalies(agent_id: str, bundle: dict) -> List[dict]:
    """
    Scan collected evidence for threat indicators.
    Returns list of anomaly dicts — each gets its own blockchain block.
    """
    anomalies = []
    collectors = bundle.get("evidence", bundle.get("collectors", {}))
    scenario   = bundle.get("scenario", "baseline")

    # proc_list anomalies
    procs = collectors.get("proc_list", {})
    for p in procs.get("suspicious", []):
        anomalies.append({
            "type":      "SUSPICIOUS_PROCESS",
            "agent_id":  agent_id,
            "scenario":  scenario,
            "detail":    f"{p.get('name','?')} PID={p.get('pid','?')}",
            "flags":     p.get("flags", []),
            "exe":       p.get("exe",""),
        })

    # net_state anomalies
    net = collectors.get("net_state", {})
    for c in net.get("suspicious", []):
        anomalies.append({
            "type":     "SUSPICIOUS_CONNECTION",
            "agent_id": agent_id,
            "scenario": scenario,
            "detail":   f"{c.get('proto','?')} {c.get('local','?')} -> {c.get('remote','?')}",
            "flags":    c.get("flags", []),
        })

    # registry anomalies
    reg = collectors.get("reg_persistence", {})
    for r in reg.get("suspicious", []):
        anomalies.append({
            "type":     "SUSPICIOUS_REGISTRY",
            "agent_id": agent_id,
            "scenario": scenario,
            "detail":   f"{r.get('hive','?')}\\{r.get('key','?')}\\{r.get('name','?')}",
            "data":     r.get("data","")[:128],
            "flags":    r.get("flags", []),
        })

    # event log anomalies
    evts = collectors.get("event_log", {})
    for e in evts.get("suspicious", []):
        anomalies.append({
            "type":     "SUSPICIOUS_EVENT",
            "agent_id": agent_id,
            "scenario": scenario,
            "event_id": e.get("event_id"),
            "flags":    e.get("flags", []),
            "ts":       e.get("timestamp",""),
        })

    # prefetch anomalies
    pf = collectors.get("prefetch", {})
    for p in pf.get("suspicious", []):
        anomalies.append({
            "type":     "ATTACKER_TOOL_EXECUTION",
            "agent_id": agent_id,
            "scenario": scenario,
            "detail":   p.get("exe_name",""),
            "last_run": p.get("last_run",""),
            "flags":    p.get("flags",[]),
        })

    # browser anomalies (insider)
    bh = collectors.get("browser_hist", {})
    for b in bh.get("suspicious", []):
        anomalies.append({
            "type":     "EXFILTRATION_INDICATOR",
            "agent_id": agent_id,
            "scenario": scenario,
            "detail":   b.get("url","")[:128],
            "flags":    b.get("flags",[]),
        })

    # scheduled task anomalies
    st = collectors.get("scheduled_tasks", {})
    for t in st.get("suspicious", []):
        anomalies.append({
            "type":     "SUSPICIOUS_SCHEDULED_TASK",
            "agent_id": agent_id,
            "scenario": scenario,
            "detail":   t.get("name",""),
            "action":   t.get("action","")[:128],
            "flags":    t.get("flags",[]),
        })

    return anomalies


# ── integrity helpers ─────────────────────────────────────────────────────────

def _get_chain(agent_id: str) -> HashChain:
    if agent_id not in _chains:
        p = _EVIDENCE_DIR / f"chain_{agent_id}.json"
        _chains[agent_id] = HashChain(str(p))
    return _chains[agent_id]

def _get_signer(agent_id: str) -> ChainSigner:
    if agent_id not in _signers:
        p = _EVIDENCE_DIR / f"key_{agent_id}.pem"
        _signers[agent_id] = ChainSigner(str(p))
    return _signers[agent_id]


# ── SSE push ──────────────────────────────────────────────────────────────────

def _push_sse(event_type: str, data: dict) -> None:
    try:
        _sse_queue.put_nowait({"type": event_type, "data": data, "ts": time.time()})
    except asyncio.QueueFull:
        pass


# ── FastAPI app ───────────────────────────────────────────────────────────────

app = FastAPI(title="JOCKY C2 Server", version="1.0.0", docs_url="/api/docs")
app.add_middleware(CORSMiddleware,
                   allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.on_event("startup")
async def startup():
    global _blockchain
    _EVIDENCE_DIR.mkdir(exist_ok=True)
    _blockchain = ForensicBlockchain(
        case_id      = _CASE_ID,
        investigator = _INVESTIGATOR,
        chain_file   = str(_EVIDENCE_DIR / f"blockchain_{_CASE_ID}.json"),
        key_file     = str(_EVIDENCE_DIR / f"inv_key_{_CASE_ID}.pem"),
    )
    log.info(f"[c2] blockchain ready: {_CASE_ID}")
    log.info(f"[c2] evidence dir: {_EVIDENCE_DIR}")


# ── Agent check-in ────────────────────────────────────────────────────────────

@app.post("/api/checkin")
async def checkin(req: Request) -> dict:
    body = await req.json()
    agent_id = body.get("agent_id", "unknown")
    hostname = body.get("hostname", "")
    platform = body.get("platform","")

    is_new = agent_id not in _agents
    _agents[agent_id] = {
        "agent_id":   agent_id,
        "hostname":   hostname,
        "platform":   platform,
        "first_seen": _agents.get(agent_id, {}).get("first_seen", _ts()),
        "last_seen":  _ts(),
        "evidence_count": _agents.get(agent_id, {}).get("evidence_count", 0),
        "state":      "CONNECTED",
    }

    if is_new and _blockchain:
        try:
            _blockchain.add_event("AGENT_DEPLOYED", {
                "agent_id": agent_id,
                "hostname": hostname,
                "platform": platform,
                "case_id":  _CASE_ID,
            })
            log.info(f"[c2] AGENT_DEPLOYED block added: {agent_id}")
        except Exception as e:
            log.warning(f"[c2] blockchain AGENT_DEPLOYED failed: {e}")

    _push_sse("agent_checkin", {"agent_id": agent_id, "hostname": hostname})
    log.info(f"[c2] checkin: {agent_id} ({hostname})")
    return {"ok": True, "agent_id": agent_id, "case_id": _CASE_ID}


# ── Evidence receiver ─────────────────────────────────────────────────────────

@app.post("/api/evidence")
async def receive_evidence(req: Request) -> dict:
    global _evidence_count
    body = await req.json()

    agent_id     = body.get("agent_id", "unknown")
    seq          = body.get("seq", 0)
    data_b64     = body.get("data", "")
    plain_summary= body.get("plain_summary", {})

    # update agent state
    if agent_id not in _agents:
        _agents[agent_id] = {
            "agent_id":     agent_id,
            "hostname":     plain_summary.get("hostname",""),
            "first_seen":   _ts(),
            "evidence_count": 0,
            "state": "COLLECTING",
        }
    _agents[agent_id]["last_seen"]      = _ts()
    _agents[agent_id]["state"]          = "COLLECTING"
    _agents[agent_id]["evidence_count"] = _agents[agent_id].get("evidence_count",0) + 1

    # decrypt
    bundle = None
    if data_b64:
        bundle = _decrypt_bundle(agent_id, data_b64)
    if bundle is None:
        # fallback: use plain_summary only
        bundle = {"evidence": {}, "scenario": "baseline"}
        log.warning(f"[c2] decrypt failed for {agent_id} seq={seq} — using summary only")

    scenario = bundle.get("scenario", plain_summary.get("scenario", "baseline"))

    # ── save raw evidence ─────────────────────────────────────────────────────
    ev_file = _EVIDENCE_DIR / f"evidence_{agent_id}_{seq:06d}.json"
    save_payload = {
        "received_at": _ts(),
        "agent_id":    agent_id,
        "seq":         seq,
        "scenario":    scenario,
        "hostname":    bundle.get("hostname","") or plain_summary.get("hostname",""),
        "username":    bundle.get("username",""),
        "platform":    bundle.get("platform",""),
        "summary":     plain_summary,
        "evidence":    bundle.get("evidence", bundle.get("collectors", {})),
        "errors":      bundle.get("errors", {}),
    }
    ev_file.write_text(json.dumps(save_payload, indent=2, default=str),
                       encoding="utf-8")
    log.info(f"[c2] evidence saved: {ev_file.name}")

    # ── append to hash-chain (per-agent) ──────────────────────────────────────
    chain_entry_id = None
    try:
        chain  = _get_chain(agent_id)
        signer = _get_signer(agent_id)
        chain_entry_id = chain.append(
            event = "evidence",
            data  = {
                "agent_id": agent_id,
                "seq":      seq,
                "scenario": scenario,
                "summary":  plain_summary,
                "file":     ev_file.name,
            }
        )
        signer.sign_entry(chain, chain_entry_id)
    except Exception as e:
        log.warning(f"[c2] hash-chain error for {agent_id}: {e}")

    # ── blockchain: EVIDENCE_COLLECTED block ──────────────────────────────────
    bc_block = None
    if _blockchain:
        try:
            collectors_run = plain_summary.get("collectors", [])
            bc_block = _blockchain.add_event("EVIDENCE_COLLECTED", {
                "agent_id":      agent_id,
                "seq":           seq,
                "scenario":      scenario,
                "hostname":      save_payload["hostname"],
                "collectors":    collectors_run,
                "suspicious_total": plain_summary.get("suspicious", 0),
                "proc_count":    plain_summary.get("proc_count", 0),
                "net_count":     plain_summary.get("net_count", 0),
                "evidence_file": ev_file.name,
                "chain_entry":   chain_entry_id,
            })
            log.info(f"[c2] blockchain block #{bc_block.index}: EVIDENCE_COLLECTED")
        except Exception as e:
            log.warning(f"[c2] blockchain EVIDENCE_COLLECTED failed: {e}")

    # ── anomaly detection ─────────────────────────────────────────────────────
    anomalies = _detect_anomalies(agent_id, save_payload)
    anomaly_blocks = []
    if anomalies and _blockchain:
        for anom in anomalies:
            try:
                ab = _blockchain.add_event("ANOMALY_DETECTED", anom)
                anomaly_blocks.append(ab.index)
                log.warning(f"[c2] ANOMALY: {anom['type']} from {agent_id}")
            except Exception as e:
                log.warning(f"[c2] anomaly block failed: {e}")

    _evidence_count += 1

    # ── SSE push to dashboard ─────────────────────────────────────────────────
    _push_sse("evidence", {
        "agent_id":     agent_id,
        "seq":          seq,
        "scenario":     scenario,
        "hostname":     save_payload["hostname"],
        "summary":      plain_summary,
        "anomaly_count": len(anomalies),
        "anomalies":    [a["type"] for a in anomalies],
        "block":        bc_block.index if bc_block else None,
    })

    return {
        "ok":            True,
        "agent_id":      agent_id,
        "seq":           seq,
        "block":         bc_block.index if bc_block else None,
        "anomalies":     len(anomalies),
        "chain_entry":   chain_entry_id,
    }


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    html_file = Path(__file__).parent.parent / "management_interface" / "dashboard" / "index.html"
    if html_file.exists():
        return HTMLResponse(html_file.read_text(encoding="utf-8"))
    return HTMLResponse(f"""<html><body style='background:#0A0E1A;color:#00D4FF;
        font-family:monospace;padding:40px'>
        <h1>JOCKY C2 Server</h1>
        <p>Dashboard HTML not found at {html_file}</p>
        <p>Evidence dir: {_EVIDENCE_DIR}</p>
        <p><a href='/api/docs' style='color:#7B2FBE'>API Docs →</a></p>
        <p><a href='/api/status' style='color:#7B2FBE'>Status →</a></p>
        <p><a href='/coc/verify' style='color:#7B2FBE'>Verify Chain →</a></p>
        </body></html>""")


# ── Status / health ───────────────────────────────────────────────────────────

@app.get("/api/status")
async def status() -> dict:
    bc_summary = _blockchain.summary() if _blockchain else {}
    return {
        "ok":             True,
        "case_id":        _CASE_ID,
        "investigator":   _INVESTIGATOR,
        "agents":         len(_agents),
        "evidence_count": _evidence_count,
        "blockchain":     bc_summary,
        "timestamp":      _ts(),
    }

@app.get("/api/agents")
async def agents_list() -> dict:
    return {"agents": list(_agents.values()), "count": len(_agents)}

@app.get("/api/evidence")
async def evidence_list() -> dict:
    files = sorted(_EVIDENCE_DIR.glob("evidence_*.json"),
                   key=lambda f: f.stat().st_mtime, reverse=True)[:50]
    items = []
    for f in files:
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
            items.append({
                "file":       f.name,
                "agent_id":   d.get("agent_id"),
                "seq":        d.get("seq"),
                "scenario":   d.get("scenario"),
                "hostname":   d.get("hostname"),
                "received_at":d.get("received_at"),
                "suspicious": d.get("summary",{}).get("suspicious",0),
            })
        except Exception:
            pass
    return {"count": len(items), "files": items}

@app.get("/api/evidence/{filename}")
async def evidence_detail(filename: str) -> dict:
    f = _EVIDENCE_DIR / filename
    if not f.exists() or not f.name.startswith("evidence_"):
        raise HTTPException(status_code=404, detail="not found")
    return json.loads(f.read_text(encoding="utf-8"))


# ── Blockchain COC endpoints ──────────────────────────────────────────────────

@app.get("/coc/summary")
async def coc_summary() -> dict:
    if not _blockchain:
        raise HTTPException(status_code=503, detail="blockchain not ready")
    return _blockchain.summary()

@app.get("/coc/blocks")
async def coc_blocks(event_type: Optional[str] = None) -> dict:
    if not _blockchain:
        raise HTTPException(status_code=503, detail="blockchain not ready")
    blocks = _blockchain.get_events(event_type)
    return {"count": len(blocks), "blocks": [b.to_dict() for b in blocks]}

@app.get("/coc/blocks/{index}")
async def coc_block(index: int) -> dict:
    if not _blockchain:
        raise HTTPException(status_code=503, detail="blockchain not ready")
    b = _blockchain.get_block(index)
    if not b:
        raise HTTPException(status_code=404, detail=f"block {index} not found")
    return b.to_dict()

@app.get("/coc/verify")
async def coc_verify() -> dict:
    if not _blockchain:
        raise HTTPException(status_code=503, detail="blockchain not ready")
    ok, report = _blockchain.verify()
    return {"verified": ok, "case_id": _CASE_ID, "report": report}

@app.post("/coc/event")
async def coc_add_event(req: Request) -> dict:
    body       = await req.json()
    event_type = body.get("event_type", "CHAIN_VERIFIED")
    data       = body.get("data", {})
    if not _blockchain:
        raise HTTPException(status_code=503, detail="blockchain not ready")
    b = _blockchain.add_event(event_type, data)
    return {"ok": True, "block_index": b.index, "hash": b.hash}


# ── Standalone verifier download ──────────────────────────────────────────────

@app.get("/coc/verifier")
async def download_verifier():
    """
    Download the standalone verifier script.
    This file is self-contained — give it to court/counsel.
    Run: python verify_chain_standalone.py blockchain_NTRO-2025-001.json --html report.html
    """
    verifier = _ROOT / "integrity" / "verify_chain_standalone.py"
    if not verifier.exists():
        raise HTTPException(status_code=404,
                            detail="verify_chain_standalone.py not found")
    from fastapi.responses import Response
    return Response(
        content=verifier.read_bytes(),
        media_type="text/x-python",
        headers={"Content-Disposition":
                 "attachment; filename=verify_chain_standalone.py"}
    )

@app.get("/coc/export")
async def export_chain():
    """Download the blockchain JSON file for offline verification."""
    chain_file = _EVIDENCE_DIR / f"blockchain_{_CASE_ID}.json"
    if not chain_file.exists():
        raise HTTPException(status_code=404, detail="chain file not found")
    from fastapi.responses import Response
    return Response(
        content=chain_file.read_bytes(),
        media_type="application/json",
        headers={"Content-Disposition":
                 f"attachment; filename=blockchain_{_CASE_ID}.json"}
    )


# ── SSE live stream ───────────────────────────────────────────────────────────

@app.get("/stream")
async def sse_stream():
    async def generate() -> AsyncIterator[str]:
        yield f"data: {json.dumps({'type':'connected','case_id':_CASE_ID})}\n\n"
        while True:
            try:
                event = await asyncio.wait_for(_sse_queue.get(), timeout=25)
                yield f"data: {json.dumps(event, default=str)}\n\n"
            except asyncio.TimeoutError:
                yield 'data: {"type":"ping"}\n\n'
            except Exception:
                break

    return StreamingResponse(generate(), media_type="text/event-stream",
                             headers={"Cache-Control":"no-cache",
                                      "X-Accel-Buffering":"no"})


# ── Demo seed ─────────────────────────────────────────────────────────────────

@app.post("/demo/seed")
async def demo_seed() -> dict:
    """Populate with synthetic evidence for demo/presentation."""
    if not _blockchain:
        raise HTTPException(status_code=503, detail="blockchain not ready")

    demo_agents = [
        {"id":"agent-dc01",  "host":"CORP-DC01",       "scenario":"intrusion"},
        {"id":"agent-ws01",  "host":"FINANCE-WS001",   "scenario":"insider"},
        {"id":"agent-srv02", "host":"FILE-SERVER-02",  "scenario":"ransomware"},
    ]
    psk = _PSK

    seeded_blocks = []
    for a in demo_agents:
        _agents[a["id"]] = {
            "agent_id":     a["id"],
            "hostname":     a["host"],
            "scenario":     a["scenario"],
            "first_seen":   _ts(),
            "last_seen":    _ts(),
            "evidence_count": 3,
            "state":        "IDLE",
        }
        b1 = _blockchain.add_event("AGENT_DEPLOYED", {
            "agent_id": a["id"], "hostname": a["host"], "scenario": a["scenario"]
        })
        b2 = _blockchain.add_event("EVIDENCE_COLLECTED", {
            "agent_id": a["id"], "scenario": a["scenario"],
            "collectors": ["proc_list","net_state","reg_persistence"],
            "suspicious_total": 2 if a["scenario"] != "baseline" else 0,
        })
        if a["scenario"] != "baseline":
            b3 = _blockchain.add_event("ANOMALY_DETECTED", {
                "type": {
                    "intrusion":  "SUSPICIOUS_CONNECTION",
                    "insider":    "EXFILTRATION_INDICATOR",
                    "ransomware": "ATTACKER_TOOL_EXECUTION",
                }[a["scenario"]],
                "agent_id": a["id"],
                "scenario": a["scenario"],
                "detail":   f"Demo anomaly on {a['host']}",
            })
            seeded_blocks.append(b3.index)
        seeded_blocks += [b1.index, b2.index]

        _push_sse("agent_checkin", {"agent_id": a["id"], "hostname": a["host"]})
        _push_sse("evidence", {
            "agent_id": a["id"], "scenario": a["scenario"],
            "hostname": a["host"], "anomaly_count": 1 if a["scenario"] != "baseline" else 0,
        })

    return {
        "ok": True,
        "seeded_agents": [a["id"] for a in demo_agents],
        "blocks_added":  seeded_blocks,
        "msg": "Demo data seeded. Open / to see the dashboard.",
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    global _CASE_ID, _INVESTIGATOR, _PSK, _EVIDENCE_DIR

    ap = argparse.ArgumentParser(
        prog="c2_server",
        description="JOCKY C2 Server — receives forensic evidence from agents"
    )
    ap.add_argument("--host",         default="0.0.0.0")
    ap.add_argument("--port",         type=int, default=8000)
    ap.add_argument("--case",         default="NTRO-2025-001", dest="case_id")
    ap.add_argument("--investigator", default="INV-ALPHA")
    ap.add_argument("--psk",          default="JOCKY_DEMO_PSK_32_BYTES_12345678")
    ap.add_argument("--evidence-dir", default=str(_ROOT / "evidence"))
    args = ap.parse_args()

    _CASE_ID      = args.case_id
    _INVESTIGATOR = args.investigator
    _EVIDENCE_DIR = Path(args.evidence_dir)
    psk_raw = args.psk
    if len(psk_raw) == 64 and all(c in "0123456789abcdefABCDEF" for c in psk_raw):
        _PSK = bytes.fromhex(psk_raw)
    else:
        raw = psk_raw.encode("utf-8")
        _PSK = (raw + b"\x00" * 32)[:32]

    logging.basicConfig(
        level  = logging.INFO,
        format = "[%(asctime)s] %(name)s %(levelname)s: %(message)s"
    )

    print(f"""
  JOCKY C2 Server + Dashboard
  ================================
  Case:         {_CASE_ID}
  Investigator: {_INVESTIGATOR}
  Evidence dir: {_EVIDENCE_DIR}

  Dashboard:    http://{args.host if args.host != '0.0.0.0' else '127.0.0.1'}:{args.port}/
  API Docs:     http://127.0.0.1:{args.port}/api/docs
  COC Verify:   http://127.0.0.1:{args.port}/coc/verify
  Download COC: http://127.0.0.1:{args.port}/coc/export
  Verifier:     http://127.0.0.1:{args.port}/coc/verifier
  Live Stream:  http://127.0.0.1:{args.port}/stream

  Agent command (target machine):
    python agent/main.py --c2 http://<THIS_IP>:{args.port} --interval 60
    jocky_agent.exe   --c2 http://<THIS_IP>:{args.port} --interval 60
""")

    uvicorn.run(app, host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()