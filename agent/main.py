"""
agent/main.py -- JOCKY Agent Entry Point
=========================================
Deployed on target machine.
Loop: collect forensic evidence -> AES-256-GCM encrypt -> POST to C2.
Runs as Windows service or standalone admin process.

Usage:
  python agent/main.py --c2 http://192.168.1.100:8000 --interval 60
  python agent/main.py --c2 http://192.168.1.100:8000 --once
  jocky_agent.exe --c2 http://192.168.1.100:8000 --interval 120
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import logging
import os
import platform
import secrets
import socket
import struct
import sys
import time
import threading
from datetime import datetime, timezone
from pathlib  import Path
from typing   import Any, Dict, Optional

# ── add project root to path (when run as standalone .exe or from agent/) ──
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
for _p in [str(_ROOT), str(_ROOT / "integrity"), str(_ROOT / "transport")]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from collector import collect_all

logging.basicConfig(
    level  = logging.INFO,
    format = "[%(asctime)s] %(levelname)s: %(message)s"
)
log = logging.getLogger("jocky.agent")

# ── AES-256-GCM (same as cloud_api_wrapper but self-contained here) ──────────
AES_KEY_LEN   = 32
GCM_NONCE_LEN = 12
GCM_TAG_LEN   = 16

class AES256GCM:
    def __init__(self, key: bytes):
        self._key = key
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            self._be = AESGCM(key)
        except ImportError:
            self._be = None

    def encrypt(self, pt: bytes, aad: bytes = b"") -> bytes:
        nonce = secrets.token_bytes(GCM_NONCE_LEN)
        if self._be:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            ct_tag = AESGCM(self._key).encrypt(nonce, pt, aad or None)
            return nonce + ct_tag
        raise RuntimeError("cryptography library required: pip install cryptography")

def _derive_key(psk: bytes, agent_id: str) -> bytes:
    prk = hmac.new(b"jocky-salt-v1", psk, hashlib.sha256).digest()
    okm = hmac.new(prk, agent_id.encode() + b"\x01", hashlib.sha256).digest()
    return okm

def _pack_and_encrypt(agent_id: str, psk: bytes, seq: int, payload: dict) -> str:
    """Pack payload into JOCKY wire format and AES-256-GCM encrypt it."""
    MAGIC = 0x4A4F4B59
    payload_bytes = json.dumps(payload, default=str).encode("utf-8")
    header = struct.pack(">III", MAGIC, 0x03, len(payload_bytes))  # type=RESULT
    seq_b  = struct.pack(">I", seq)
    pt = header + payload_bytes + seq_b
    key = _derive_key(psk, agent_id)
    ct  = AES256GCM(key).encrypt(pt, aad=agent_id.encode())
    return base64.b64encode(ct).decode("ascii")

# ── HTTP POST (stdlib only — no requests needed) ──────────────────────────────
def _post_json(url: str, data: dict, timeout: int = 30) -> Optional[dict]:
    """
    POST JSON to C2 using urllib (stdlib, no pip needed).
    Falls back gracefully on connection error.
    """
    import urllib.request
    import urllib.error
    body = json.dumps(data, default=str).encode("utf-8")
    req  = urllib.request.Request(url, data=body,
                                   headers={"Content-Type": "application/json",
                                             "User-Agent":    "JOCKY-Agent/1.0"},
                                   method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        log.warning(f"POST {url} -> HTTP {e.code}: {e.read()[:200]}")
        return None
    except Exception as e:
        log.warning(f"POST {url} failed: {e}")
        return None

# ── Agent ─────────────────────────────────────────────────────────────────────
class JockyAgent:
    """
    Deployed forensic agent.
    Collects evidence, encrypts it, POSTs to C2, sleeps, repeats.
    """

    def __init__(self, c2_url: str, psk: bytes,
                 agent_id: Optional[str] = None,
                 interval: int = 60,
                 collectors: Optional[list] = None):
        self.c2_url    = c2_url.rstrip("/")
        self.psk       = psk
        self.agent_id  = agent_id or self._make_agent_id()
        self.interval  = interval
        self.collectors = collectors  # None = all
        self._seq      = 0
        self._running  = False

        log.info(f"[agent] id={self.agent_id}")
        log.info(f"[agent] c2={self.c2_url}")
        log.info(f"[agent] interval={self.interval}s")

    @staticmethod
    def _make_agent_id() -> str:
        """Stable ID derived from hostname + MAC address."""
        hostname = socket.gethostname()
        try:
            import uuid
            mac = uuid.getnode()
            seed = f"{hostname}-{mac}"
        except Exception:
            seed = hostname
        h = hashlib.sha256(seed.encode()).hexdigest()
        return f"jocky-{h[:8]}"

    def _collect(self) -> Dict[str, Any]:
        log.info("[agent] starting collection...")
        bundle = collect_all(self.collectors)
        log.info(f"[agent] collected: {list(bundle['collectors'].keys())}")
        return bundle

    def _send(self, bundle: Dict[str, Any]) -> bool:
        """Encrypt bundle and POST to C2 /api/evidence endpoint."""
        self._seq += 1
        payload = {
            "agent_id":   self.agent_id,
            "seq":        self._seq,
            "timestamp":  datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "hostname":   bundle.get("hostname", ""),
            "username":   bundle.get("username", ""),
            "platform":   platform.platform(),
            "evidence":   bundle["collectors"],
            "errors":     bundle.get("errors", {}),
        }

        # encrypt
        try:
            encrypted_b64 = _pack_and_encrypt(self.agent_id, self.psk,
                                               self._seq, payload)
            wire = {
                "agent_id": self.agent_id,
                "seq":      self._seq,
                "data":     encrypted_b64,
                "plain_summary": {   # unencrypted summary for dashboard quickview
                    "hostname":    payload["hostname"],
                    "username":    payload["username"],
                    "collectors":  list(bundle["collectors"].keys()),
                    "proc_count":  bundle["collectors"].get("proc_list",{}).get("count",0),
                    "net_count":   bundle["collectors"].get("net_state",{}).get("total",0),
                    "suspicious":  sum(
                        len(bundle["collectors"].get(k,{}).get("suspicious",[]))
                        for k in bundle["collectors"]
                    ),
                }
            }
        except Exception as e:
            log.error(f"[agent] encrypt failed: {e}")
            return False

        url = f"{self.c2_url}/api/evidence"
        log.info(f"[agent] posting {len(json.dumps(wire))} bytes to {url}")
        resp = _post_json(url, wire)
        if resp:
            log.info(f"[agent] C2 response: {resp.get('ok')} block={resp.get('block')}")
            return True
        return False

    def run_once(self) -> bool:
        bundle = self._collect()
        return self._send(bundle)

    def run_loop(self) -> None:
        self._running = True
        # initial checkin
        log.info("[agent] checkin...")
        _post_json(f"{self.c2_url}/api/checkin", {
            "agent_id":  self.agent_id,
            "hostname":  socket.gethostname(),
            "platform":  platform.platform(),
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        })

        while self._running:
            try:
                self.run_once()
            except Exception as e:
                log.error(f"[agent] loop error: {e}")
            log.info(f"[agent] sleeping {self.interval}s...")
            time.sleep(self.interval)

    def stop(self) -> None:
        self._running = False


# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(prog="jocky_agent",
                                  description="JOCKY forensic agent")
    ap.add_argument("--c2",       required=True,  help="C2 URL e.g. http://192.168.1.100:8000")
    ap.add_argument("--psk",      default="JOCKY_DEMO_PSK_32_BYTES_12345678",
                                   help="32-byte PSK (string or hex)")
    ap.add_argument("--id",       default=None,   help="Agent ID (auto if omitted)")
    ap.add_argument("--interval", type=int, default=60, help="Collection interval seconds")
    ap.add_argument("--once",     action="store_true",  help="Collect once and exit")
    ap.add_argument("--collectors", nargs="*", default=None,
                    choices=["proc_list","net_state","reg_persistence","event_log",
                             "usb_history","prefetch","browser_hist","scheduled_tasks"],
                    help="Which collectors to run (default: all)")
    args = ap.parse_args()

    # parse PSK
    psk_raw = args.psk
    if len(psk_raw) == 64 and all(c in "0123456789abcdefABCDEF" for c in psk_raw):
        psk = bytes.fromhex(psk_raw)
    else:
        psk = psk_raw.encode("utf-8")
        if len(psk) < 32: psk = psk.ljust(32, b"\x00")
        psk = psk[:32]

    agent = JockyAgent(
        c2_url     = args.c2,
        psk        = psk,
        agent_id   = args.id,
        interval   = args.interval,
        collectors = args.collectors,
    )

    if args.once:
        ok = agent.run_once()
        sys.exit(0 if ok else 1)
    else:
        try:
            agent.run_loop()
        except KeyboardInterrupt:
            agent.stop()
            log.info("[agent] stopped")

if __name__ == "__main__":
    main()
