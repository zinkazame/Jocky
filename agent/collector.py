"""
agent/collector.py -- JOCKY Forensic Collectors
=================================================
8 real forensic collectors for Windows targets.
Supports 4 investigation scenarios.

Scenarios:
  baseline    -- all collectors, no specific focus
  ransomware  -- prefetch, event_log, reg_persistence, proc_list, net_state
  insider     -- browser_hist, usb_history, event_log, reg_persistence, scheduled_tasks
  intrusion   -- net_state, proc_list, event_log, scheduled_tasks, reg_persistence

Usage:
  from collector import collect_all
  bundle = collect_all(scenario="ransomware")
  bundle = collect_all(which=["proc_list","net_state"])
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import re
import socket
import struct
import subprocess
import sys
import time
import winreg
from datetime import datetime, timezone
from pathlib  import Path
from typing   import Any, Dict, List, Optional

log = logging.getLogger("jocky.collector")


# ── Scenario definitions ─────────────────────────────────────────────────────

SCENARIOS: Dict[str, List[str]] = {
    "baseline": [
        "proc_list", "net_state", "reg_persistence",
        "event_log", "usb_history", "prefetch",
        "browser_hist", "scheduled_tasks",
    ],
    "ransomware": [
        # Focus: execution traces, lateral movement, encrypted file indicators
        "proc_list",        # suspicious processes, injected memory
        "prefetch",         # execution history (mimikatz, psexec, vssadmin)
        "event_log",        # 4688 process creates, 4698 sched task, VSS deletion
        "reg_persistence",  # dropped autorun keys
        "net_state",        # C2 connections, SMB spread
        "usb_history",      # initial access vector
    ],
    "insider": [
        # Focus: data staging, exfiltration paths, access patterns
        "browser_hist",     # cloud upload sites, webmail, file sharing
        "usb_history",      # data copied to USB
        "event_log",        # 4663 object access, 4624 logons outside hours
        "reg_persistence",  # tools installed for exfiltration
        "scheduled_tasks",  # automated exfiltration jobs
        "proc_list",        # cloud sync tools, compression utilities
    ],
    "intrusion": [
        # Focus: persistence, privilege escalation, lateral movement
        "net_state",        # active C2 connections, unusual listeners
        "proc_list",        # reverse shells, injected processes
        "event_log",        # 4624/4625 logons, 7045 service install, 4698 sched task
        "scheduled_tasks",  # persistence via scheduled tasks
        "reg_persistence",  # registry persistence keys
        "prefetch",         # attacker tooling execution traces
    ],
}

# ── Threat indicators per scenario ───────────────────────────────────────────

RANSOMWARE_PROC_IOC = [
    "mimikatz", "psexec", "wce", "fgdump", "procdump", "vssadmin",
    "bcdedit", "wbadmin", "cipher", "sdelete", "7zip", "7z.exe",
    "rar.exe", "wscript", "cscript", "mshta", "certutil",
]
RANSOMWARE_NET_IOC_PORTS = {445, 139, 3389, 22, 4444, 8080, 1337}

INSIDER_BROWSER_IOC_DOMAINS = [
    "mega.nz", "wetransfer.com", "dropbox.com", "anonfile",
    "file.io", "gofile.io", "transfer.sh", "ufile.io",
    "sendspace.com", "mediafire.com", "pastebin.com",
]
INSIDER_PROC_IOC = [
    "rclone", "s3cmd", "aws", "gdrive", "nextcloud",
    "7z.exe", "winrar", "winzip", "robocopy",
]

INTRUSION_PROC_IOC = [
    "nc.exe", "ncat", "netcat", "nmap", "masscan",
    "cobalt", "beacon", "meterpreter", "empire",
    "powersploit", "invoke-", "psexec", "wmiexec",
    "dcsync", "bloodhound", "sharphound",
]
INTRUSION_NET_LISTEN_SUSPICIOUS = {4444, 4445, 8888, 31337, 1337, 9001, 9002}


# ── Helper utilities ──────────────────────────────────────────────────────────

def _run(cmd: str, timeout: int = 15) -> str:
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, timeout=timeout,
            encoding="utf-8", errors="replace"
        )
        return r.stdout.strip()
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as e:
        return f"[ERROR: {e}]"


def _sha256_file(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ═══════════════════════════════════════════════════════════════════════════════
# COLLECTOR 1: Process List
# ═══════════════════════════════════════════════════════════════════════════════

def _proc_list(scenario: str = "baseline") -> dict:
    """
    Enumerate all running processes.
    - PID, PPID, name, path, command line
    - SHA-256 of executable
    - Flags: no disk image (possible injection/hollow), suspicious name
    """
    log.info("[collector] proc_list starting...")

    ioc_names = {
        "ransomware": RANSOMWARE_PROC_IOC,
        "insider":    INSIDER_PROC_IOC,
        "intrusion":  INTRUSION_PROC_IOC,
    }.get(scenario, RANSOMWARE_PROC_IOC + INSIDER_PROC_IOC + INTRUSION_PROC_IOC)

    try:
        import psutil
        procs = []
        suspicious = []
        for p in psutil.process_iter(
            ["pid","ppid","name","exe","cmdline","status","create_time","username"]
        ):
            try:
                info = p.info
                exe  = info.get("exe") or ""
                name = (info.get("name") or "").lower()
                cmd  = " ".join(info.get("cmdline") or [])

                sha  = _sha256_file(exe) if exe and os.path.exists(exe) else ""
                no_disk = bool(exe and not os.path.exists(exe))

                flags = []
                for ioc in ioc_names:
                    if ioc.lower() in name or ioc.lower() in cmd.lower():
                        flags.append(f"IOC_NAME:{ioc}")
                if no_disk:
                    flags.append("NO_DISK_IMAGE")
                if not exe and info["pid"] > 4:
                    flags.append("NO_EXE_PATH")

                entry = {
                    "pid":     info["pid"],
                    "ppid":    info.get("ppid"),
                    "name":    info.get("name"),
                    "exe":     exe,
                    "sha256":  sha,
                    "cmd":     cmd[:256],
                    "user":    info.get("username",""),
                    "status":  info.get("status",""),
                    "flags":   flags,
                }
                procs.append(entry)
                if flags:
                    suspicious.append(entry)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return {
            "count":     len(procs),
            "suspicious_count": len(suspicious),
            "suspicious": suspicious,
            "processes": procs,
        }

    except ImportError:
        # fallback: tasklist
        raw = _run("tasklist /FO CSV /NH /V")
        procs = []
        for line in raw.splitlines():
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) >= 2:
                name = parts[0].lower()
                flags = [f"IOC_NAME:{ioc}" for ioc in ioc_names if ioc in name]
                procs.append({"name": parts[0], "pid": parts[1], "flags": flags})
        suspicious = [p for p in procs if p["flags"]]
        return {"count": len(procs), "suspicious_count": len(suspicious),
                "suspicious": suspicious, "processes": procs}


# ═══════════════════════════════════════════════════════════════════════════════
# COLLECTOR 2: Network State
# ═══════════════════════════════════════════════════════════════════════════════

def _net_state(scenario: str = "baseline") -> dict:
    """
    All TCP/UDP connections mapped to process names.
    Flags: external IPs, suspicious ports, listening on unusual ports.
    """
    log.info("[collector] net_state starting...")

    suspicious_ports = {
        "ransomware": RANSOMWARE_NET_IOC_PORTS,
        "intrusion":  INTRUSION_NET_LISTEN_SUSPICIOUS,
    }.get(scenario, RANSOMWARE_NET_IOC_PORTS | INTRUSION_NET_LISTEN_SUSPICIOUS)

    raw = _run("netstat -ano", timeout=20)
    connections = []
    suspicious  = []

    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        proto = parts[0]
        if proto not in ("TCP", "UDP"):
            continue

        local  = parts[1]
        remote = parts[2] if proto == "TCP" else "*:*"
        state  = parts[3] if proto == "TCP" and len(parts) > 3 else ""
        pid    = parts[-1]

        local_port  = local.rsplit(":", 1)[-1]
        remote_ip   = remote.rsplit(":", 1)[0].strip("[]")
        remote_port_str = remote.rsplit(":", 1)[-1]

        flags = []
        # external IP check
        if remote_ip not in ("0.0.0.0", "127.0.0.1", "::", "*", "[::]", "") \
                and not remote_ip.startswith("192.168.") \
                and not remote_ip.startswith("10.") \
                and not remote_ip.startswith("172."):
            flags.append(f"EXTERNAL_IP:{remote_ip}")

        # suspicious port check
        try:
            rp = int(remote_port_str)
            if rp in suspicious_ports:
                flags.append(f"SUSPICIOUS_PORT:{rp}")
        except ValueError:
            pass

        entry = {
            "proto":   proto,
            "local":   local,
            "remote":  remote,
            "state":   state,
            "pid":     pid,
            "flags":   flags,
        }
        connections.append(entry)
        if flags:
            suspicious.append(entry)

    # DNS cache (useful for intrusion/insider)
    dns_cache = []
    if scenario in ("intrusion", "insider", "baseline"):
        dns_raw = _run("ipconfig /displaydns", timeout=10)
        for line in dns_raw.splitlines():
            if "Record Name" in line:
                name = line.split(":", 1)[-1].strip()
                dns_cache.append(name)

    return {
        "total":       len(connections),
        "suspicious_count": len(suspicious),
        "suspicious":  suspicious,
        "connections": connections,
        "dns_cache":   dns_cache[:50],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# COLLECTOR 3: Registry Persistence
# ═══════════════════════════════════════════════════════════════════════════════

def _reg_persistence(scenario: str = "baseline") -> dict:
    """
    All autorun registry keys across HKLM and HKCU.
    Flags: shell interpreters, obfuscation markers, temp paths.
    """
    log.info("[collector] reg_persistence starting...")

    AUTORUN_KEYS = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Classes\*\shellex\ContextMenuHandlers"),
    ]

    SUSPICIOUS_PATTERNS = [
        "powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32",
        "regsvr32", "certutil", "bitsadmin", "msiexec", "installutil",
        "base64", "iex ", "invoke-expression", "downloadstring",
        "\\temp\\", "\\tmp\\", "\\appdata\\roaming\\", "%temp%",
        "bypass", "hidden", "encoded", "-enc ", "-nop ",
        # insider-specific
        "rclone", "gdrive", "s3cmd", "mega",
    ]
    # ransomware-specific additions
    if scenario == "ransomware":
        SUSPICIOUS_PATTERNS += ["vssadmin", "wbadmin", "bcdedit", "cipher"]

    entries   = []
    suspicious = []

    for hive, key_path in AUTORUN_KEYS:
        try:
            hive_name = {
                winreg.HKEY_LOCAL_MACHINE: "HKLM",
                winreg.HKEY_CURRENT_USER:  "HKCU",
            }.get(hive, "???")
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
            i   = 0
            while True:
                try:
                    name, data, dtype = winreg.EnumValue(key, i)
                    data_str = str(data).lower()
                    flags = [
                        p for p in SUSPICIOUS_PATTERNS if p in data_str
                    ]
                    entry = {
                        "hive":   hive_name,
                        "key":    key_path,
                        "name":   name,
                        "data":   str(data)[:512],
                        "type":   dtype,
                        "flags":  flags,
                    }
                    entries.append(entry)
                    if flags:
                        suspicious.append(entry)
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except (FileNotFoundError, PermissionError, OSError):
            continue

    return {
        "total":       len(entries),
        "suspicious_count": len(suspicious),
        "suspicious":  suspicious,
        "entries":     entries,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# COLLECTOR 4: Windows Event Log
# ═══════════════════════════════════════════════════════════════════════════════

def _event_log(scenario: str = "baseline") -> dict:
    """
    Pull Security and System event logs.
    Scenario-specific event ID focus.
    """
    log.info("[collector] event_log starting...")

    # scenario → which event IDs to focus on
    SCENARIO_EVENT_IDS = {
        "ransomware": {
            "Security": [4688, 4689, 4624, 4625, 4698, 4702, 4663],
            "System":   [7045, 7036, 7040],
        },
        "insider": {
            "Security": [4663, 4624, 4625, 4634, 4648, 4698, 4702, 5140, 5145],
            "System":   [7045],
        },
        "intrusion": {
            "Security": [4624, 4625, 4648, 4672, 4698, 4720, 4726, 4732, 4756],
            "System":   [7045, 7036],
        },
        "baseline": {
            "Security": [4624, 4625, 4688, 4698, 4702, 4663, 4720, 4726, 4648],
            "System":   [7045, 7036],
        },
    }

    target_ids = SCENARIO_EVENT_IDS.get(scenario, SCENARIO_EVENT_IDS["baseline"])
    events     = []
    suspicious = []

    for log_name, event_ids in target_ids.items():
        for eid in event_ids:
            try:
                # use wevtutil for reliable structured output
                raw = _run(
                    f'wevtutil qe {log_name} '
                    f'/q:"*[System[EventID={eid}]]" '
                    f'/c:20 /rd:true /f:text',
                    timeout=15
                )
                if not raw or "[TIMEOUT]" in raw or "[ERROR" in raw:
                    continue

                # parse text output blocks
                blocks = raw.split("Event[")
                for block in blocks[1:]:  # skip first empty
                    ev = {
                        "log":      log_name,
                        "event_id": eid,
                        "raw":      block[:500],
                        "flags":    [],
                    }

                    # extract timestamp
                    ts_m = re.search(r"Date:\s+(.+)", block)
                    if ts_m:
                        ev["timestamp"] = ts_m.group(1).strip()

                    # scenario-specific flags
                    block_lower = block.lower()
                    if eid == 4688:
                        # process create — check for suspicious new processes
                        for ioc in RANSOMWARE_PROC_IOC + INTRUSION_PROC_IOC:
                            if ioc in block_lower:
                                ev["flags"].append(f"SUSPICIOUS_PROC:{ioc}")
                    if eid == 4625:
                        ev["flags"].append("FAILED_LOGON")
                    if eid == 7045:
                        ev["flags"].append("NEW_SERVICE_INSTALLED")
                    if eid == 4698:
                        ev["flags"].append("SCHEDULED_TASK_CREATED")
                    if eid == 4720:
                        ev["flags"].append("USER_ACCOUNT_CREATED")
                    if eid == 5140 and ("admin$" in block_lower or "c$" in block_lower):
                        ev["flags"].append("ADMIN_SHARE_ACCESS")

                    events.append(ev)
                    if ev["flags"]:
                        suspicious.append(ev)

            except Exception as e:
                log.debug(f"event_log eid={eid}: {e}")

    return {
        "total":       len(events),
        "suspicious_count": len(suspicious),
        "suspicious":  suspicious,
        "events":      events[:200],   # cap at 200
        "scenario_focus": list(target_ids.keys()),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# COLLECTOR 5: USB History
# ═══════════════════════════════════════════════════════════════════════════════

def _usb_history(scenario: str = "baseline") -> dict:
    """
    All USB storage devices ever connected (USBSTOR registry).
    Includes device names, serial numbers, connection timestamps.
    """
    log.info("[collector] usb_history starting...")

    devices = []
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Enum\USBSTOR",
            0, winreg.KEY_READ
        )
        i = 0
        while True:
            try:
                dev_type = winreg.EnumKey(key, i)
                dev_key  = winreg.OpenKey(key, dev_type)
                j = 0
                while True:
                    try:
                        serial   = winreg.EnumKey(dev_key, j)
                        inst_key = winreg.OpenKey(dev_key, serial)
                        try:
                            friendly, _ = winreg.QueryValueEx(inst_key, "FriendlyName")
                        except FileNotFoundError:
                            friendly = dev_type
                        try:
                            mfg, _ = winreg.QueryValueEx(inst_key, "Mfg")
                        except FileNotFoundError:
                            mfg = ""
                        devices.append({
                            "device_type": dev_type,
                            "serial":      serial,
                            "friendly_name": friendly,
                            "manufacturer": mfg,
                        })
                        winreg.CloseKey(inst_key)
                        j += 1
                    except OSError:
                        break
                winreg.CloseKey(dev_key)
                i += 1
            except OSError:
                break
        winreg.CloseKey(key)
    except (FileNotFoundError, PermissionError):
        pass

    return {
        "count":   len(devices),
        "devices": devices,
        "note":    "All USB storage devices ever connected to this machine",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# COLLECTOR 6: Prefetch Analysis
# ═══════════════════════════════════════════════════════════════════════════════

def _prefetch(scenario: str = "baseline") -> dict:
    """
    Parse Windows Prefetch files to reconstruct execution history.
    Flags executables matching known attacker tooling.
    """
    log.info("[collector] prefetch starting...")

    PREFETCH_DIR = Path(r"C:\Windows\Prefetch")

    # scenario-specific IOCs
    PREFETCH_IOC = {
        "ransomware": [
            "MIMIKATZ", "PSEXEC", "WCE", "FGDUMP", "PROCDUMP",
            "VSSADMIN", "WBADMIN", "BCDEDIT", "CIPHER", "SDELETE",
            "7Z", "RAR", "CERTUTIL", "MSHTA", "CSCRIPT", "WSCRIPT",
        ],
        "insider": [
            "RCLONE", "S3CMD", "GDRIVE", "MEGA", "7Z", "WINRAR",
            "ROBOCOPY", "XCOPY", "CERTUTIL", "CURL", "WGET",
        ],
        "intrusion": [
            "NC", "NCAT", "NMAP", "MASSCAN", "PSEXEC", "WMIEXEC",
            "MIMIKATZ", "BLOODHOUND", "SHARPHOUND", "COBALTSTRIKE",
            "METERPRETER", "POWERSPLOIT",
        ],
        "baseline": [
            "MIMIKATZ", "PSEXEC", "WCE", "FGDUMP", "PROCDUMP",
            "VSSADMIN", "WBADMIN", "NC", "NCAT", "RCLONE",
            "CERTUTIL", "MSHTA", "CSCRIPT", "WSCRIPT", "REGSVR32",
        ],
    }
    ioc_list = PREFETCH_IOC.get(scenario, PREFETCH_IOC["baseline"])

    entries    = []
    suspicious = []

    if not PREFETCH_DIR.exists():
        return {"count": 0, "entries": [],
                "note": "Prefetch directory not found or access denied"}

    for pf_file in sorted(PREFETCH_DIR.glob("*.pf"),
                          key=lambda f: f.stat().st_mtime, reverse=True)[:200]:
        try:
            stat      = pf_file.stat()
            name      = pf_file.stem.upper()   # "MIMIKATZ-ABCDEF01"
            exe_name  = name.rsplit("-", 1)[0]  # "MIMIKATZ"
            mtime     = datetime.fromtimestamp(
                            stat.st_mtime, tz=timezone.utc
                        ).strftime("%Y-%m-%dT%H:%M:%SZ")

            flags = [ioc for ioc in ioc_list if ioc in exe_name]
            entry = {
                "filename":   pf_file.name,
                "exe_name":   exe_name,
                "size_bytes": stat.st_size,
                "last_run":   mtime,
                "flags":      flags,
            }
            entries.append(entry)
            if flags:
                suspicious.append(entry)
        except Exception:
            continue

    return {
        "count":       len(entries),
        "suspicious_count": len(suspicious),
        "suspicious":  suspicious,
        "entries":     entries,
        "scenario_ioc": ioc_list,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# COLLECTOR 7: Browser History
# ═══════════════════════════════════════════════════════════════════════════════

def _browser_hist(scenario: str = "baseline") -> dict:
    """
    Chrome and Edge browser history + downloads.
    Insider scenario: flags cloud exfiltration domains.
    """
    log.info("[collector] browser_hist starting...")

    PROFILE_DIRS = []
    local_app = Path(os.environ.get("LOCALAPPDATA", "C:\\Users\\Default\\AppData\\Local"))

    for browser, rel in [
        ("Chrome", r"Google\Chrome\User Data"),
        ("Edge",   r"Microsoft\Edge\User Data"),
        ("Brave",  r"BraveSoftware\Brave-Browser\User Data"),
    ]:
        base = local_app / rel
        if base.exists():
            for profile in ["Default"] + [f"Profile {i}" for i in range(1, 5)]:
                history_db = base / profile / "History"
                if history_db.exists():
                    PROFILE_DIRS.append((browser, profile, history_db))

    exfil_domains = INSIDER_BROWSER_IOC_DOMAINS if scenario == "insider" else []
    entries     = []
    suspicious  = []

    for browser, profile, db_path in PROFILE_DIRS:
        try:
            import shutil, tempfile, sqlite3
            # copy DB (Chrome holds a lock)
            with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
                tmp_path = tmp.name
            shutil.copy2(db_path, tmp_path)
            conn = sqlite3.connect(tmp_path)
            conn.row_factory = sqlite3.Row

            # visits
            cur = conn.execute(
                "SELECT url, title, visit_count, "
                "datetime(last_visit_time/1000000-11644473600,'unixepoch') AS visited "
                "FROM urls ORDER BY last_visit_time DESC LIMIT 200"
            )
            for row in cur:
                url = row["url"] or ""
                flags = []
                for domain in exfil_domains:
                    if domain in url.lower():
                        flags.append(f"EXFIL_DOMAIN:{domain}")
                entry = {
                    "browser": browser,
                    "profile": profile,
                    "url":     url[:256],
                    "title":   (row["title"] or "")[:128],
                    "visits":  row["visit_count"],
                    "visited": row["visited"],
                    "flags":   flags,
                }
                entries.append(entry)
                if flags:
                    suspicious.append(entry)

            # downloads
            try:
                dcur = conn.execute(
                    "SELECT current_path, tab_url, "
                    "datetime(start_time/1000000-11644473600,'unixepoch') AS started "
                    "FROM downloads ORDER BY start_time DESC LIMIT 50"
                )
                for drow in dcur:
                    entries.append({
                        "browser":  browser,
                        "type":     "download",
                        "path":     drow["current_path"],
                        "from_url": (drow["tab_url"] or "")[:256],
                        "started":  drow["started"],
                        "flags":    [],
                    })
            except Exception:
                pass

            conn.close()
            os.unlink(tmp_path)
        except Exception as e:
            log.debug(f"browser_hist {browser}/{profile}: {e}")

    return {
        "total":       len(entries),
        "suspicious_count": len(suspicious),
        "suspicious":  suspicious,
        "entries":     entries[:300],
        "profiles":    [(b, p) for b, p, _ in PROFILE_DIRS],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# COLLECTOR 8: Scheduled Tasks
# ═══════════════════════════════════════════════════════════════════════════════

def _scheduled_tasks(scenario: str = "baseline") -> dict:
    """
    All scheduled tasks.
    Flags: SYSTEM-privilege tasks running shell interpreters.
    """
    log.info("[collector] scheduled_tasks starting...")

    SUSPICIOUS_ACTIONS = [
        "cmd.exe", "powershell", "wscript", "cscript",
        "mshta", "rundll32", "regsvr32", "certutil",
        "bitsadmin", "installutil", "\\temp\\", "\\tmp\\",
    ]
    if scenario == "ransomware":
        SUSPICIOUS_ACTIONS += ["vssadmin", "wbadmin", "bcdedit"]
    if scenario in ("insider", "intrusion"):
        SUSPICIOUS_ACTIONS += ["rclone", "nc.exe", "ncat"]

    raw = _run(
        "schtasks /query /FO CSV /V",
        timeout=20
    )
    tasks      = []
    suspicious = []

    lines = raw.splitlines()
    if not lines:
        return {"count": 0, "tasks": [], "suspicious": []}

    header = [h.strip('"').lower() for h in lines[0].split(",")]
    for line in lines[1:]:
        parts = [p.strip('"') for p in line.split(",")]
        if len(parts) < len(header):
            continue
        row = dict(zip(header, parts))
        task_name  = row.get("taskname", "")
        run_as     = row.get("run as user", "").lower()
        task_to_run= row.get("task to run", "").lower()
        status     = row.get("status", "")

        flags = []
        if "system" in run_as or "localsystem" in run_as:
            for act in SUSPICIOUS_ACTIONS:
                if act in task_to_run:
                    flags.append(f"SYSTEM_SHELL:{act}")
        for act in SUSPICIOUS_ACTIONS:
            if act in task_to_run and "system" not in run_as:
                flags.append(f"SUSPICIOUS_ACTION:{act}")

        entry = {
            "name":      task_name,
            "run_as":    row.get("run as user",""),
            "action":    row.get("task to run","")[:256],
            "status":    status,
            "schedule":  row.get("schedule type",""),
            "last_run":  row.get("last run time",""),
            "next_run":  row.get("next run time",""),
            "flags":     flags,
        }
        tasks.append(entry)
        if flags:
            suspicious.append(entry)

    return {
        "count":       len(tasks),
        "suspicious_count": len(suspicious),
        "suspicious":  suspicious,
        "tasks":       tasks,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def collect_all(which: Optional[List[str]] = None,
                scenario: str = "baseline") -> dict:
    """
    Run forensic collectors and return a unified bundle.

    Args:
        which:    explicit list of collector names to run (overrides scenario)
        scenario: "baseline" | "ransomware" | "insider" | "intrusion"

    Returns:
        bundle dict with collectors, errors, hostname, metadata
    """
    if scenario not in SCENARIOS:
        log.warning(f"unknown scenario '{scenario}', using baseline")
        scenario = "baseline"

    collectors_to_run = which or SCENARIOS[scenario]

    COLLECTOR_MAP = {
        "proc_list":       _proc_list,
        "net_state":       _net_state,
        "reg_persistence": _reg_persistence,
        "event_log":       _event_log,
        "usb_history":     _usb_history,
        "prefetch":        _prefetch,
        "browser_hist":    _browser_hist,
        "scheduled_tasks": _scheduled_tasks,
    }

    bundle: Dict[str, Any] = {
        "timestamp":   _ts(),
        "hostname":    socket.gethostname(),
        "username":    os.environ.get("USERNAME", ""),
        "platform":    platform.platform(),
        "scenario":    scenario,
        "collectors":  {},
        "errors":      {},
        "summary": {
            "scenario": scenario,
            "collectors_run": [],
            "suspicious_total": 0,
        }
    }

    for name in collectors_to_run:
        fn = COLLECTOR_MAP.get(name)
        if not fn:
            log.warning(f"unknown collector: {name}")
            continue
        t0 = time.time()
        try:
            result = fn(scenario=scenario)
            bundle["collectors"][name] = result
            bundle["summary"]["collectors_run"].append(name)
            susp = result.get("suspicious_count", 0)
            bundle["summary"]["suspicious_total"] += susp
            log.info(f"[collector] {name}: OK ({time.time()-t0:.1f}s) "
                     f"suspicious={susp}")
        except Exception as e:
            bundle["errors"][name] = str(e)
            log.warning(f"[collector] {name}: FAILED -- {e}")

    return bundle