"""
jocky_lang/runner.py -- JOCKY Script Runner / Task Dispatcher
=============================================================
Parses .jky scripts and dispatches collector tasks to agents via C2.

.jky syntax:
    case "NTRO-2026-001"
    target "jocky-dc01"           # specific agent
    target all                    # all connected agents
    collect proc_list             # single collector
    run triage                    # pre-defined script
    filter url contains "mega.nz" # filter rule (sent to agent)
    flag external_ips             # flag rule
    alert if suspicious > 0       # alert condition

Usage:
    runner = JockyRunner(c2_url="http://localhost:8000", case_id="NTRO-2026-001")
    runner.run_file("scripts/triage.jky")
    runner.run_script("run triage")
    runner.run_builtin("browser_forensics", target="jocky-dc01")
"""
from __future__ import annotations

import json
import re
import time
import logging
import urllib.request
import urllib.error
from pathlib  import Path
from typing   import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone

log = logging.getLogger("jocky.runner")

# ── collector registry ────────────────────────────────────────────────────────
# maps collector name -> description + platform support
COLLECTORS = {
    # Windows + Android
    "proc_list":         {"desc":"Running processes + SHA256 hashes",       "platform":["windows","android"]},
    "net_state":         {"desc":"TCP/UDP connections + process mapping",    "platform":["windows","android"]},
    "browser_hist":      {"desc":"Chrome/Edge/Firefox history + downloads",  "platform":["windows","android"]},
    "usb_history":       {"desc":"USB devices ever connected",               "platform":["windows"]},
    "event_log":         {"desc":"Windows Security/System event logs",       "platform":["windows"]},
    "reg_persistence":   {"desc":"Registry autorun keys",                    "platform":["windows"]},
    "prefetch":          {"desc":"Execution history from Prefetch files",    "platform":["windows"]},
    "scheduled_tasks":   {"desc":"Scheduled tasks + suspicious flags",       "platform":["windows"]},
    "dns_cache":         {"desc":"DNS resolver cache",                       "platform":["windows","android"]},
    "arp_table":         {"desc":"ARP table / local network hosts",          "platform":["windows"]},
    "proc_memory":       {"desc":"Process memory string extraction",         "platform":["windows"]},
    # Android-only
    "sms_history":       {"desc":"SMS messages",                             "platform":["android"]},
    "call_log":          {"desc":"Call history",                             "platform":["android"]},
    "installed_apps":    {"desc":"Installed APKs + permissions",             "platform":["android"]},
    "contacts":          {"desc":"Contact list",                             "platform":["android"]},
    "location_history":  {"desc":"GPS history",                              "platform":["android"]},
    "whatsapp_db":       {"desc":"WhatsApp message database",                "platform":["android"]},
    "telegram_db":       {"desc":"Telegram local cache",                     "platform":["android"]},
}

# ── built-in script definitions ────────────────────────────────────────────────
BUILTIN_SCRIPTS = {
    "triage": {
        "desc":       "Full baseline: processes, network, registry, events",
        "collectors": ["proc_list","net_state","reg_persistence","event_log"],
        "flags":      ["proc_list.suspicious","net_state.external_ips"],
        "alert":      "any.suspicious > 0",
    },
    "persistence_check": {
        "desc":       "What survives a reboot: registry, services, tasks",
        "collectors": ["reg_persistence","scheduled_tasks"],
        "flags":      ["reg_persistence.suspicious","scheduled_tasks.suspicious"],
        "alert":      "any.suspicious > 0",
    },
    "browser_forensics": {
        "desc":       "Browser history, downloads, flagged URLs",
        "collectors": ["browser_hist","usb_history"],
        "filters":    [{"field":"browser_hist.url","contains":["pastebin.com","mega.nz","wetransfer.com","telegram.org"]}],
        "flags":      ["browser_hist.dangerous_downloads"],
        "alert":      "browser_hist.flagged > 0",
    },
    "network_forensics": {
        "desc":       "Deep network state: connections, DNS, ARP",
        "collectors": ["net_state","dns_cache","arp_table"],
        "flags":      ["net_state.external_ips","net_state.threat_ips"],
        "alert":      "net_state.threat_ips > 0",
    },
    "exfil_indicators": {
        "desc":       "Exfiltration signs: cloud sync, USB, large transfers",
        "collectors": ["net_state","browser_hist","usb_history","scheduled_tasks"],
        "flags":      ["usb_history.devices","net_state.large_transfers"],
        "alert":      "usb_history.count > 0",
    },
    "ransomware_triage": {
        "desc":       "Ransomware indicators: shadow copies, log clearing",
        "collectors": ["proc_list","net_state","event_log","scheduled_tasks"],
        "filters":    [{"field":"proc_list.name","contains":["vssadmin","wbadmin","cipher"]}],
        "flags":      ["proc_list.high_cpu","event_log.log_cleared"],
        "alert":      "event_log.log_cleared > 0",
    },
    "insider_threat": {
        "desc":       "Insider exfiltration: browser, USB, after-hours",
        "collectors": ["browser_hist","usb_history","event_log","scheduled_tasks"],
        "flags":      ["usb_history.devices"],
        "alert":      "usb_history.count > 2",
    },
    "memory_forensics": {
        "desc":       "Process memory string extraction on suspicious PIDs",
        "collectors": ["proc_list","proc_memory"],
        "flags":      ["proc_memory.flagged"],
        "alert":      "proc_memory.flagged > 0",
    },
    "mobile_forensics": {
        "desc":       "Android: SMS, calls, apps, location, chat DBs",
        "collectors": ["sms_history","call_log","installed_apps","contacts",
                       "location_history","whatsapp_db","telegram_db"],
        "flags":      ["installed_apps.unknown_source","installed_apps.flagged"],
        "alert":      "installed_apps.flagged > 0",
    },
    "full_investigation": {
        "desc":       "Complete investigation: all collectors",
        "collectors": ["proc_list","net_state","reg_persistence","event_log",
                       "browser_hist","usb_history","scheduled_tasks",
                       "dns_cache","prefetch"],
        "flags":      ["proc_list.suspicious","net_state.threat_ips",
                       "browser_hist.flagged","usb_history.devices"],
        "alert":      "any.suspicious > 0",
    },
}

# ── .jky parser ───────────────────────────────────────────────────────────────
class JockyParser:
    """
    Parses a .jky script into a task plan.
    Returns: {case_id, targets, collectors, filters, flags, alerts}
    """

    def parse(self, source: str) -> dict:
        plan = {
            "case_id":    None,
            "targets":    [],
            "collectors": [],
            "filters":    [],
            "flags":      [],
            "alerts":     [],
            "scripts":    [],
            "errors":     [],
        }

        for line_no, raw in enumerate(source.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            try:
                self._parse_line(line, plan, line_no)
            except Exception as e:
                plan["errors"].append(f"line {line_no}: {e}  ('{line}')")

        # expand 'run' directives into collectors
        for script_name in plan["scripts"]:
            if script_name in BUILTIN_SCRIPTS:
                s = BUILTIN_SCRIPTS[script_name]
                for c in s["collectors"]:
                    if c not in plan["collectors"]:
                        plan["collectors"].append(c)
                for f in s.get("flags", []):
                    if f not in plan["flags"]:
                        plan["flags"].append(f)
                plan["alerts"].append(s.get("alert",""))
            else:
                plan["errors"].append(f"unknown script: '{script_name}'")

        return plan

    def _parse_line(self, line: str, plan: dict, ln: int):
        # case "NTRO-2026-001"
        m = re.match(r'^case\s+"([^"]+)"', line)
        if m: plan["case_id"] = m.group(1); return

        # target "jocky-dc01"  OR  target all
        m = re.match(r'^target\s+"?([^"]+)"?', line)
        if m:
            t = m.group(1).strip()
            if t == "all":
                plan["targets"] = ["all"]
            elif t not in plan["targets"]:
                plan["targets"].append(t)
            return

        # collect <name>
        m = re.match(r'^collect\s+(\w+)', line)
        if m:
            c = m.group(1)
            if c not in COLLECTORS:
                raise ValueError(f"unknown collector '{c}'")
            if c not in plan["collectors"]:
                plan["collectors"].append(c)
            return

        # run <script>
        m = re.match(r'^run\s+(\w+)', line)
        if m:
            plan["scripts"].append(m.group(1)); return

        # filter <field> contains [...]  OR  filter <field> <op> <value>
        m = re.match(r'^filter\s+(.+)', line)
        if m:
            plan["filters"].append(m.group(1).strip()); return

        # flag <field>
        m = re.match(r'^flag\s+(.+)', line)
        if m:
            plan["flags"].append(m.group(1).strip()); return

        # alert if <condition>
        m = re.match(r'^alert\s+if\s+(.+)', line)
        if m:
            plan["alerts"].append(m.group(1).strip()); return

        # export to dashboard (no-op — always exports)
        if line.startswith("export"): return

        raise ValueError(f"unrecognised statement")

    def parse_file(self, path: str) -> dict:
        return self.parse(Path(path).read_text(encoding="utf-8"))

# ── task dispatcher ───────────────────────────────────────────────────────────
class JockyRunner:
    """
    Compiles a .jky plan into tasks and dispatches them to agents via C2.
    """

    def __init__(self, c2_url: str, case_id: str,
                 psk: str = "JOCKY_DEMO_PSK_32_BYTES_12345678"):
        self.c2_url  = c2_url.rstrip("/")
        self.case_id = case_id
        self.psk     = psk
        self._parser = JockyParser()

    def _post(self, path: str, data: dict) -> Optional[dict]:
        body = json.dumps(data, default=str).encode()
        req  = urllib.request.Request(
            f"{self.c2_url}{path}", data=body,
            headers={"Content-Type":"application/json","User-Agent":"JOCKY-Runner/1.0"},
            method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return json.loads(r.read())
        except Exception as e:
            log.warning(f"POST {path} failed: {e}")
            return None

    def _get(self, path: str) -> Optional[dict]:
        try:
            with urllib.request.urlopen(f"{self.c2_url}{path}", timeout=10) as r:
                return json.loads(r.read())
        except Exception as e:
            log.warning(f"GET {path} failed: {e}")
            return None

    def _get_agents(self) -> List[str]:
        data = self._get("/agents")
        if not data: return []
        return list(data.get("agents",{}).keys())

    def run_script(self, source: str,
                   default_target: Optional[str] = None) -> dict:
        """
        Parse and dispatch a .jky script.
        Returns execution report.
        """
        plan = self._parser.parse(source)

        if plan["errors"]:
            return {"ok":False,"errors":plan["errors"]}

        # resolve targets
        targets = plan["targets"] or (["all"] if not default_target else [default_target])
        if "all" in targets:
            targets = self._get_agents() or ["all"]

        log.info(f"[runner] plan: collectors={plan['collectors']} targets={targets}")

        dispatched = []
        for target in targets:
            task = {
                "case_id":    plan["case_id"] or self.case_id,
                "target":     target,
                "collectors": plan["collectors"],
                "filters":    plan["filters"],
                "flags":      plan["flags"],
                "alerts":     plan["alerts"],
                "source":     source,
                "dispatched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            resp = self._post("/api/task", task)
            dispatched.append({
                "target": target,
                "task":   task,
                "resp":   resp,
            })
            log.info(f"[runner] dispatched to {target}: {resp}")

        return {
            "ok":        True,
            "plan":      plan,
            "targets":   targets,
            "dispatched":dispatched,
        }

    def run_file(self, path: str,
                 default_target: Optional[str] = None) -> dict:
        source = Path(path).read_text(encoding="utf-8")
        return self.run_script(source, default_target)

    def run_builtin(self, script_name: str,
                    target: Optional[str] = None) -> dict:
        if script_name not in BUILTIN_SCRIPTS:
            return {"ok":False,"errors":[f"unknown script: {script_name}"]}
        s = BUILTIN_SCRIPTS[script_name]
        jky = f'case "{self.case_id}"\n'
        if target:
            jky += f'target "{target}"\n'
        else:
            jky += 'target all\n'
        for c in s["collectors"]:
            jky += f'collect {c}\n'
        if s.get("alert"):
            jky += f'alert if {s["alert"]}\n'
        return self.run_script(jky)

    def list_builtins(self) -> List[dict]:
        return [{"name":k,"desc":v["desc"],"collectors":v["collectors"]}
                for k,v in BUILTIN_SCRIPTS.items()]

    def list_collectors(self) -> List[dict]:
        return [{"name":k,"desc":v["desc"],"platform":v["platform"]}
                for k,v in COLLECTORS.items()]

# ── CLI ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse, sys
    logging.basicConfig(level=logging.INFO,
                        format="[%(asctime)s] %(levelname)s: %(message)s")
    ap = argparse.ArgumentParser(prog="jocky_runner")
    ap.add_argument("--c2",       default="http://localhost:8000")
    ap.add_argument("--case",     default="NTRO-2026-001")
    ap.add_argument("--target",   default=None)
    ap.add_argument("--script",   default=None,  help=".jky file path")
    ap.add_argument("--run",      default=None,  help="built-in script name")
    ap.add_argument("--list",     action="store_true")
    args = ap.parse_args()

    runner = JockyRunner(args.c2, args.case)

    if args.list:
        print("\nBUILT-IN SCRIPTS:")
        for s in runner.list_builtins():
            print(f"  {s['name']:<25}  {s['desc']}")
            print(f"  {'':25}  collectors: {', '.join(s['collectors'])}")
            print()
        print("COLLECTORS:")
        for c in runner.list_collectors():
            print(f"  {c['name']:<22}  [{','.join(c['platform'])}]  {c['desc']}")
        sys.exit(0)

    if args.run:
        result = runner.run_builtin(args.run, args.target)
    elif args.script:
        result = runner.run_file(args.script, args.target)
    else:
        # interactive REPL
        print("JOCKY Script Runner — interactive mode")
        print("Commands: list / run <script> / collect <name> / quit")
        print()
        while True:
            try:
                line = input("jocky.script> ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not line: continue
            if line == "quit": break
            if line == "list":
                for s in runner.list_builtins():
                    print(f"  {s['name']:<25}  {s['desc']}")
                continue
            result = runner.run_script(line, args.target)
            print(json.dumps(result, indent=2, default=str))

    if 'result' in dir():
        print(json.dumps(result, indent=2, default=str))
