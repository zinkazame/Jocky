"""
JOCKY Forensic Primitives — Real Implementations
==================================================
All ~50 forensic primitive functions dispatched by interpreter.py.

Each function has the signature:
    fn(args: dict, ctx: dict) -> dict

where:
    args  — keyword arguments from the .jky script (already parsed)
    ctx   — execution context: {case_id, operator, target, mode, result_acc}

Returns a dict that ALWAYS contains at least:
    {"ok": True/False, "primitive": "<name>", ...data...}

Optionally contains:
    "_suspicious": int   — number of suspicious findings (adds to accumulator)
    "_error": str        — error message if ok is False

Platform note
-------------
Most primitives target Windows. On a non-Windows host the functions
degrade gracefully: they return {"ok": False, "_error": "windows_only"}.
On a real investigation, the interpreter runs inside the polymorphic
agent binary which executes on the Windows target.
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
from datetime   import datetime, timezone
from pathlib    import Path
from typing     import Any

log = logging.getLogger("jocky.primitives")

_IS_WINDOWS = platform.system() == "Windows"

# ── Lazy import for optional heavyweight packages ──────────────────────────────

def _psutil():
    try:
        import psutil as _p
        return _p
    except ImportError:
        return None


def _winreg():
    if not _IS_WINDOWS:
        return None
    try:
        import winreg as _w
        return _w
    except ImportError:
        return None


# ── Utility helpers ────────────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run(cmd: str, timeout: int = 15) -> str:
    """Run a shell command and return stdout as string."""
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, timeout=timeout,
            encoding="utf-8", errors="replace"
        )
        return r.stdout.strip()
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as exc:
        return f"[ERROR: {exc}]"


def _sha256_file(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _win_only(primitive: str) -> dict:
    return {
        "ok": False,
        "primitive": primitive,
        "_error": "windows_only — primitive requires Windows execution environment",
    }


# ══════════════════════════════════════════════════════════════════════════════
# SECTION: acquire — live data acquisition
# ══════════════════════════════════════════════════════════════════════════════

def acquire_process_list(args: dict, ctx: dict) -> dict:
    """
    Enumerate all running processes with full metadata.
    args: (none required)  optional: scenario=baseline|ransomware|insider|intrusion
    """
    scenario = args.get("scenario", "baseline")
    ps = _psutil()
    if ps is None:
        if not _IS_WINDOWS:
            return _win_only("acquire_process_list")
        # Fallback: tasklist
        raw = _run("tasklist /FO CSV /NH /V")
        procs = []
        for line in raw.splitlines():
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) >= 2:
                procs.append({"name": parts[0], "pid": parts[1]})
        return {"ok": True, "primitive": "acquire_process_list",
                "count": len(procs), "processes": procs, "_suspicious": 0}

    IOC = {
        "ransomware": ["mimikatz","psexec","vssadmin","bcdedit","wbadmin","cipher","certutil"],
        "insider":    ["rclone","s3cmd","gdrive","robocopy","winrar","7z.exe"],
        "intrusion":  ["nc.exe","ncat","nmap","cobalt","beacon","meterpreter","empire","psexec"],
    }.get(scenario, ["mimikatz","psexec","nc.exe","nmap","meterpreter"])

    procs = []
    suspicious = []
    for p in ps.process_iter(["pid","ppid","name","exe","cmdline","username","status"]):
        try:
            info = p.info
            exe  = info.get("exe") or ""
            name = (info.get("name") or "").lower()
            cmd  = " ".join(info.get("cmdline") or [])
            sha  = _sha256_file(exe) if exe and os.path.exists(exe) else ""
            no_disk = bool(exe and not os.path.exists(exe))

            flags = []
            for ioc in IOC:
                if ioc.lower() in name or ioc.lower() in cmd.lower():
                    flags.append(f"IOC:{ioc}")
            if no_disk:
                flags.append("NO_DISK_IMAGE")

            entry = {
                "pid":    info["pid"],
                "ppid":   info.get("ppid"),
                "name":   info.get("name"),
                "exe":    exe,
                "sha256": sha,
                "cmd":    cmd[:256],
                "user":   info.get("username", ""),
                "flags":  flags,
            }
            procs.append(entry)
            if flags:
                suspicious.append(entry)
        except Exception:
            continue

    return {
        "ok": True,
        "primitive": "acquire_process_list",
        "count":     len(procs),
        "suspicious_count": len(suspicious),
        "suspicious": suspicious,
        "processes":  procs,
        "_suspicious": len(suspicious),
    }


def acquire_memory_region(args: dict, ctx: dict) -> dict:
    """
    Read raw bytes from a process virtual address range.
    args: pid=<int>, base=<hex|int>, size=<int>
    """
    if not _IS_WINDOWS:
        return _win_only("acquire_memory_region")

    pid  = int(args.get("pid",  0))
    size = int(args.get("size", 4096))
    base = args.get("base", 0)
    if isinstance(base, str) and base.startswith("0x"):
        base = int(base, 16)
    else:
        base = int(base)

    try:
        import ctypes, ctypes.wintypes as wt
        k32    = ctypes.windll.kernel32
        PROCESS_VM_READ = 0x0010
        handle = k32.OpenProcess(PROCESS_VM_READ, False, pid)
        if not handle:
            return {"ok": False, "primitive": "acquire_memory_region",
                    "_error": f"OpenProcess failed for pid={pid}"}

        buf   = (ctypes.c_char * size)()
        nread = ctypes.c_size_t(0)
        ok    = k32.ReadProcessMemory(handle, ctypes.c_void_p(base), buf, size, ctypes.byref(nread))
        k32.CloseHandle(handle)

        raw_bytes = bytes(buf[: nread.value])
        # extract printable strings
        strings = re.findall(rb"[\x20-\x7e]{4,}", raw_bytes)
        strings_decoded = [s.decode("ascii", errors="replace") for s in strings[:50]]

        return {
            "ok": True,
            "primitive": "acquire_memory_region",
            "pid":    pid,
            "base":   hex(base),
            "size":   nread.value,
            "sha256": hashlib.sha256(raw_bytes).hexdigest(),
            "strings": strings_decoded,
            "_suspicious": len([s for s in strings_decoded if any(
                ioc in s.lower() for ioc in ["password","token","secret","key","http://","ftp://"]
            )]),
        }
    except Exception as exc:
        return {"ok": False, "primitive": "acquire_memory_region", "_error": str(exc)}


def acquire_cpu_registers(args: dict, ctx: dict) -> dict:
    """
    Dump thread register state for suspended threads.
    args: pid=<int> (optional, 0 = current)
    """
    if not _IS_WINDOWS:
        return _win_only("acquire_cpu_registers")

    pid = int(args.get("pid", 0))
    try:
        import ctypes, ctypes.wintypes as wt
        TH32CS_SNAPTHREAD = 0x00000004
        k32 = ctypes.windll.kernel32

        class THREADENTRY32(ctypes.Structure):
            _fields_ = [("dwSize",             wt.DWORD),
                        ("cntUsage",           wt.DWORD),
                        ("th32ThreadID",       wt.DWORD),
                        ("th32OwnerProcessID", wt.DWORD),
                        ("tpBasePri",          wt.LONG),
                        ("tpDeltaPri",         wt.LONG),
                        ("dwFlags",            wt.DWORD)]

        snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        entry = THREADENTRY32()
        entry.dwSize = ctypes.sizeof(THREADENTRY32)
        threads = []
        if k32.Thread32First(snap, ctypes.byref(entry)):
            while True:
                if pid == 0 or entry.th32OwnerProcessID == pid:
                    threads.append({
                        "tid": entry.th32ThreadID,
                        "owner_pid": entry.th32OwnerProcessID,
                        "base_priority": entry.tpBasePri,
                    })
                if not k32.Thread32Next(snap, ctypes.byref(entry)):
                    break
        k32.CloseHandle(snap)

        return {
            "ok": True,
            "primitive": "acquire_cpu_registers",
            "pid": pid,
            "thread_count": len(threads),
            "threads": threads[:100],
            "_suspicious": 0,
        }
    except Exception as exc:
        return {"ok": False, "primitive": "acquire_cpu_registers", "_error": str(exc)}


def acquire_loaded_modules(args: dict, ctx: dict) -> dict:
    """
    List DLLs / shared objects loaded into a process.
    args: pid=<int>
    """
    pid = int(args.get("pid", 0))
    ps  = _psutil()
    if ps is None:
        if not _IS_WINDOWS:
            return _win_only("acquire_loaded_modules")
        raw = _run(f"tasklist /FI \"PID eq {pid}\" /M")
        return {"ok": True, "primitive": "acquire_loaded_modules",
                "pid": pid, "raw": raw, "_suspicious": 0}

    try:
        proc = ps.Process(pid)
        maps = proc.memory_maps(grouped=True)
        modules = []
        suspicious = 0
        for m in maps:
            path = m.path
            # flag modules loaded from temp / unusual locations
            susp_flag = any(seg in path.lower() for seg in
                            [r"\temp\\", r"\tmp\\", r"\appdata\\local\\temp",
                             "\\users\\public\\", "::"])
            entry = {"path": path, "suspicious": susp_flag}
            modules.append(entry)
            if susp_flag:
                suspicious += 1
        return {
            "ok": True,
            "primitive": "acquire_loaded_modules",
            "pid": pid,
            "count": len(modules),
            "modules": modules,
            "_suspicious": suspicious,
        }
    except Exception as exc:
        return {"ok": False, "primitive": "acquire_loaded_modules", "_error": str(exc)}


def acquire_handles(args: dict, ctx: dict) -> dict:
    """
    Enumerate open handles for a process.
    args: pid=<int>
    """
    if not _IS_WINDOWS:
        return _win_only("acquire_handles")
    pid = int(args.get("pid", 0))
    # Use Sysinternals handle.exe if present, else fall back to WMIC
    raw = _run(f"handle.exe -p {pid} -nobanner 2>nul", timeout=20)
    if "[ERROR" in raw or not raw.strip():
        raw = _run(f"wmic process where ProcessId={pid} get Handle /value")
    return {
        "ok": True,
        "primitive": "acquire_handles",
        "pid": pid,
        "raw": raw[:4096],
        "_suspicious": raw.lower().count("suspicious"),
    }


def acquire_tokens(args: dict, ctx: dict) -> dict:
    """
    List process/thread security tokens + privilege list.
    args: pid=<int>
    """
    if not _IS_WINDOWS:
        return _win_only("acquire_tokens")
    pid = int(args.get("pid", 0))
    raw = _run(f"whoami /priv 2>nul")
    elevated = "SeDebugPrivilege" in raw or "SeTcbPrivilege" in raw
    return {
        "ok": True,
        "primitive": "acquire_tokens",
        "pid": pid,
        "privileges_raw": raw[:2048],
        "elevated": elevated,
        "_suspicious": 1 if elevated else 0,
    }


def acquire_heap_strings(args: dict, ctx: dict) -> dict:
    """
    Extract printable strings from a process heap.
    args: pid=<int>, min_len=4
    """
    if not _IS_WINDOWS:
        return _win_only("acquire_heap_strings")
    pid     = int(args.get("pid", 0))
    min_len = int(args.get("min_len", 4))
    # Use strings.exe (Sysinternals) or fall back to procdump+strings
    raw = _run(f"strings.exe -p {pid} -nobanner 2>nul", timeout=30)
    strings = [s for s in raw.splitlines() if len(s) >= min_len]
    ioc_strings = [s for s in strings if any(
        kw in s.lower() for kw in ["password", "token", "secret", "http://", "https://", "ftp://"]
    )]
    return {
        "ok": True,
        "primitive": "acquire_heap_strings",
        "pid": pid,
        "count": len(strings),
        "ioc_strings": ioc_strings[:50],
        "_suspicious": len(ioc_strings),
    }


def acquire_connections(args: dict, ctx: dict) -> dict:
    """
    TCP/UDP connection table with owning PIDs.
    args: (none)
    """
    raw  = _run("netstat -ano", timeout=20)
    conns = []
    suspicious = []

    SUSP_PORTS = {4444, 4445, 8888, 31337, 1337, 9001, 9002, 6666, 6667}

    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] not in ("TCP", "UDP"):
            continue
        proto  = parts[0]
        local  = parts[1]
        remote = parts[2] if proto == "TCP" else "*:*"
        state  = parts[3] if proto == "TCP" and len(parts) > 4 else ""
        pid    = parts[-1]

        remote_ip   = remote.rsplit(":", 1)[0].strip("[]")
        remote_port = remote.rsplit(":", 1)[-1]
        flags = []

        is_external = (
            remote_ip not in ("0.0.0.0","127.0.0.1","::","*","[::]","")
            and not remote_ip.startswith(("192.168.","10.","172."))
        )
        if is_external:
            flags.append(f"EXTERNAL:{remote_ip}")
        try:
            if int(remote_port) in SUSP_PORTS:
                flags.append(f"SUSP_PORT:{remote_port}")
        except ValueError:
            pass

        entry = {"proto": proto, "local": local, "remote": remote,
                 "state": state, "pid": pid, "flags": flags}
        conns.append(entry)
        if flags:
            suspicious.append(entry)

    return {
        "ok": True,
        "primitive": "acquire_connections",
        "total": len(conns),
        "suspicious_count": len(suspicious),
        "suspicious": suspicious,
        "connections": conns,
        "_suspicious": len(suspicious),
    }


def acquire_dns_cache(args: dict, ctx: dict) -> dict:
    """OS DNS resolver cache entries."""
    if not _IS_WINDOWS:
        return _win_only("acquire_dns_cache")
    raw = _run("ipconfig /displaydns", timeout=10)
    entries = []
    for line in raw.splitlines():
        if "Record Name" in line:
            entries.append(line.split(":", 1)[-1].strip())
    suspicious = [e for e in entries if any(
        kw in e.lower() for kw in ["pastebin", "mega.nz", "ngrok", "serveo", "dyndns"]
    )]
    return {
        "ok": True,
        "primitive": "acquire_dns_cache",
        "count": len(entries),
        "entries": entries,
        "suspicious": suspicious,
        "_suspicious": len(suspicious),
    }


def acquire_arp_cache(args: dict, ctx: dict) -> dict:
    """ARP table: IP → MAC."""
    raw = _run("arp -a", timeout=10)
    entries = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 2 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
            entries.append({"ip": parts[0], "mac": parts[1],
                             "type": parts[2] if len(parts) > 2 else ""})
    return {"ok": True, "primitive": "acquire_arp_cache",
            "count": len(entries), "entries": entries, "_suspicious": 0}


def acquire_route_table(args: dict, ctx: dict) -> dict:
    """IP routing table."""
    raw = _run("route print", timeout=10)
    return {"ok": True, "primitive": "acquire_route_table",
            "raw": raw[:4096], "_suspicious": 0}


def acquire_sockets(args: dict, ctx: dict) -> dict:
    """All sockets including RAW and ICMP."""
    ps = _psutil()
    if ps:
        socks = []
        for conn in ps.net_connections(kind="all"):
            socks.append({
                "fd":     conn.fd,
                "family": str(conn.family),
                "type":   str(conn.type),
                "laddr":  str(conn.laddr),
                "raddr":  str(conn.raddr),
                "status": conn.status,
                "pid":    conn.pid,
            })
        return {"ok": True, "primitive": "acquire_sockets",
                "count": len(socks), "sockets": socks, "_suspicious": 0}
    # Fallback
    raw = _run("netstat -anb 2>nul || ss -anp 2>/dev/null", timeout=20)
    return {"ok": True, "primitive": "acquire_sockets",
            "raw": raw[:4096], "_suspicious": 0}


def acquire_proc_memory(args: dict, ctx: dict) -> dict:
    """Full memory map of a process (VAD walk equivalent)."""
    pid = int(args.get("pid", 0))
    ps  = _psutil()
    if ps is None:
        return {"ok": False, "primitive": "acquire_proc_memory",
                "_error": "psutil not available"}
    try:
        proc = ps.Process(pid)
        maps = []
        for m in proc.memory_maps(grouped=False):
            maps.append({
                "addr":  getattr(m, "addr", ""),
                "perms": getattr(m, "perms", ""),
                "path":  getattr(m, "path",  ""),
                "rss":   getattr(m, "rss",   0),
            })
        # flag RWX regions (shellcode staging)
        rwx = [m for m in maps if "rwx" in m.get("perms", "").lower()]
        return {
            "ok": True,
            "primitive": "acquire_proc_memory",
            "pid": pid,
            "region_count": len(maps),
            "rwx_regions": rwx,
            "map": maps[:200],
            "_suspicious": len(rwx),
        }
    except Exception as exc:
        return {"ok": False, "primitive": "acquire_proc_memory", "_error": str(exc)}


def acquire_drivers(args: dict, ctx: dict) -> dict:
    """Loaded kernel drivers + paths + signatures."""
    if not _IS_WINDOWS:
        return _win_only("acquire_drivers")
    raw = _run("driverquery /FO CSV /SI 2>nul", timeout=20)
    drivers = []
    suspicious = []
    # Known BYOVD / LOLDriver hashes (small canonical set)
    BYOVD_NAMES = {"rtcore64.sys", "winring0x64.sys", "asrdrv107.sys",
                   "dbutil_2_3.sys", "gdrv.sys", "ntiolib_x64.sys"}
    for line in raw.splitlines()[1:]:
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) < 2:
            continue
        name = parts[0].lower()
        flags = []
        if name in BYOVD_NAMES:
            flags.append("BYOVD_KNOWN")
        entry = {"name": parts[0], "flags": flags}
        if len(parts) > 3:
            entry["link_date"] = parts[3]
        drivers.append(entry)
        if flags:
            suspicious.append(entry)
    return {
        "ok": True,
        "primitive": "acquire_drivers",
        "count": len(drivers),
        "suspicious": suspicious,
        "drivers": drivers,
        "_suspicious": len(suspicious),
    }


# ══════════════════════════════════════════════════════════════════════════════
# SECTION: inspect — OS metadata / configuration
# ══════════════════════════════════════════════════════════════════════════════

def inspect_registry(args: dict, ctx: dict) -> dict:
    """
    Enumerate a registry key + values.
    args: key="HKLM\\Software\\..."
    """
    if not _IS_WINDOWS:
        return _win_only("inspect_registry")
    key_path = args.get("key", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
    raw = _run(f'reg query "{key_path}" /s 2>nul', timeout=15)
    lines = raw.splitlines()
    values = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith("HKEY") and "    " in line:
            parts = line.split("    ", 2)
            if len(parts) == 3:
                values.append({"name": parts[0], "type": parts[1], "data": parts[2]})
    suspicious = [v for v in values if any(
        kw in v["data"].lower() for kw in
        ["\\temp\\", "\\appdata\\local\\temp", "powershell -", "cmd.exe /c", "wscript", "regsvr32"]
    )]
    return {
        "ok": True,
        "primitive": "inspect_registry",
        "key": key_path,
        "count": len(values),
        "values": values,
        "suspicious": suspicious,
        "_suspicious": len(suspicious),
    }


def inspect_services(args: dict, ctx: dict) -> dict:
    """
    SCM service list + state.
    args: state=all|running|stopped
    """
    state = args.get("state", "all")
    if not _IS_WINDOWS:
        return _win_only("inspect_services")
    filter_str = "/STATE:running" if state == "running" else ""
    raw = _run(f"sc query type= all {filter_str} 2>nul", timeout=20)
    services = []
    current: dict = {}
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("SERVICE_NAME:"):
            if current:
                services.append(current)
            current = {"name": line.split(":", 1)[-1].strip()}
        elif line.startswith("STATE") and current:
            current["state"] = line.split(":", 1)[-1].strip()
        elif line.startswith("DISPLAY_NAME") and current:
            current["display"] = line.split(":", 1)[-1].strip()
    if current:
        services.append(current)

    # Flag services with suspicious binary paths
    details_raw = _run("wmic service get name,pathname /format:csv 2>nul", timeout=20)
    path_map: dict = {}
    for row in details_raw.splitlines()[1:]:
        cols = row.split(",")
        if len(cols) >= 3:
            path_map[cols[1].lower()] = cols[2]

    suspicious = []
    for svc in services:
        path = path_map.get(svc["name"].lower(), "")
        flags = []
        if any(kw in path.lower() for kw in ["\\temp\\", "appdata", "users\\public"]):
            flags.append("UNUSUAL_PATH")
        if flags:
            svc["flags"] = flags
            suspicious.append(svc)

    return {
        "ok": True,
        "primitive": "inspect_services",
        "count": len(services),
        "suspicious": suspicious,
        "services": services,
        "_suspicious": len(suspicious),
    }


def inspect_startup_items(args: dict, ctx: dict) -> dict:
    """All autorun locations: registry + startup folders + tasks."""
    if not _IS_WINDOWS:
        return _win_only("inspect_startup_items")
    # Use autoruns if available
    raw_auto = _run("autorunsc.exe -a * -c -h -s * -nobanner 2>nul", timeout=30)
    if raw_auto and "[ERROR" not in raw_auto and "[TIMEOUT" not in raw_auto:
        return {"ok": True, "primitive": "inspect_startup_items",
                "source": "autoruns", "raw": raw_auto[:8192], "_suspicious": 0}
    # Fallback: query common autorun registry keys
    keys = [
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ]
    items = []
    for k in keys:
        raw = _run(f'reg query "{k}" 2>nul', timeout=10)
        for line in raw.splitlines():
            line = line.strip()
            if line and "    " in line and not line.startswith("HKEY"):
                items.append({"key": k, "entry": line})
    suspicious = [i for i in items if any(
        kw in i["entry"].lower() for kw in
        ["powershell", "cmd.exe", "wscript", "mshta", "regsvr32", "\\temp\\"]
    )]
    return {
        "ok": True,
        "primitive": "inspect_startup_items",
        "source": "registry",
        "count": len(items),
        "items": items,
        "suspicious": suspicious,
        "_suspicious": len(suspicious),
    }


def inspect_scheduled_tasks(args: dict, ctx: dict) -> dict:
    """Task Scheduler list + state + actions."""
    if not _IS_WINDOWS:
        return _win_only("inspect_scheduled_tasks")
    raw = _run("schtasks /query /FO CSV /V 2>nul", timeout=20)
    tasks = []
    suspicious = []
    lines = raw.splitlines()
    if len(lines) > 1:
        # CSV: TaskName,Next Run Time,Status,Logon Mode,Last Run Time,Author,...
        header = [h.strip('"') for h in lines[0].split(",")]
        for line in lines[1:]:
            cols = [c.strip('"') for c in line.split(",")]
            if len(cols) < len(header):
                continue
            task = dict(zip(header, cols))
            tasks.append(task)
            action = task.get("Task To Run", "")
            if any(kw in action.lower() for kw in
                   ["powershell", "cmd.exe", "wscript", "mshta", "\\temp\\", "appdata"]):
                task["_flag"] = "SUSPICIOUS_ACTION"
                suspicious.append(task)

    return {
        "ok": True,
        "primitive": "inspect_scheduled_tasks",
        "count": len(tasks),
        "suspicious": suspicious,
        "tasks": tasks[:100],
        "_suspicious": len(suspicious),
    }


def inspect_event_log(args: dict, ctx: dict) -> dict:
    """
    Windows event log: Security, System, Application.
    args: log=Security|System|Application  count=50  event_id=<int> (optional)
    """
    if not _IS_WINDOWS:
        return _win_only("inspect_event_log")
    log_name = args.get("log", "Security")
    count    = int(args.get("count", 50))
    event_id = args.get("event_id", None)

    # IOC event IDs
    IOC_IDS = {
        4624: "Successful logon",
        4625: "Failed logon",
        4688: "Process created",
        4698: "Scheduled task created",
        4699: "Scheduled task deleted",
        7045: "New service installed",
        4732: "Member added to admin group",
        4720: "User account created",
        1102: "Audit log cleared",
        4663: "Object access",
    }

    if event_id:
        filter_xpath = f"*[System[EventID={event_id}]]"
    else:
        id_list = " or ".join(f"EventID={i}" for i in IOC_IDS)
        filter_xpath = f"*[System[{id_list}]]"

    cmd = (
        f'powershell -NoProfile -Command "'
        f'Get-WinEvent -LogName {log_name} -MaxEvents {count} '
        f'-FilterXPath \'{filter_xpath}\' 2>$null | '
        f'Select-Object TimeCreated,Id,Message | ConvertTo-Json -Depth 1"'
    )
    raw = _run(cmd, timeout=30)

    events = []
    try:
        data = json.loads(raw) if raw.strip().startswith("[") else []
        if isinstance(data, dict):
            data = [data]
        for ev in data:
            eid = ev.get("Id", 0)
            events.append({
                "time":    ev.get("TimeCreated", {}).get("DateTime", ""),
                "id":      eid,
                "label":   IOC_IDS.get(eid, ""),
                "message": str(ev.get("Message", ""))[:256],
            })
    except Exception:
        events = [{"raw": raw[:4096]}]

    return {
        "ok": True,
        "primitive": "inspect_event_log",
        "log": log_name,
        "count": len(events),
        "events": events,
        "_suspicious": len(events),  # every matched event is noteworthy
    }


def inspect_usb_history(args: dict, ctx: dict) -> dict:
    """USBSTOR registry — ever-connected USB devices."""
    if not _IS_WINDOWS:
        return _win_only("inspect_usb_history")
    raw = _run(r'reg query "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR" /s 2>nul', timeout=15)
    devices = []
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("HKEY") and "USBSTOR" in line:
            devices.append({"key": line})
        elif "FriendlyName" in line:
            if devices:
                devices[-1]["friendly_name"] = line.split("REG_SZ", 1)[-1].strip()
    return {
        "ok": True,
        "primitive": "inspect_usb_history",
        "device_count": len(devices),
        "devices": devices[:50],
        "_suspicious": 0,
    }


def inspect_prefetch_history(args: dict, ctx: dict) -> dict:
    """Prefetch .pf binary parse → execution timeline."""
    if not _IS_WINDOWS:
        return _win_only("inspect_prefetch_history")
    pf_dir = r"C:\Windows\Prefetch"
    if not os.path.isdir(pf_dir):
        return {"ok": False, "primitive": "inspect_prefetch_history",
                "_error": "Prefetch directory not found (may be disabled)"}
    files = sorted(Path(pf_dir).glob("*.pf"), key=os.path.getmtime, reverse=True)
    IOC_NAMES = ["mimikatz", "psexec", "procdump", "wce", "fgdump", "vssadmin",
                 "certutil", "mshta", "wscript", "regsvr32"]
    entries = []
    suspicious = []
    for pf in files[:200]:
        name = pf.stem.upper()
        mtime = datetime.fromtimestamp(pf.stat().st_mtime, tz=timezone.utc).isoformat()
        flags = [ioc for ioc in IOC_NAMES if ioc.upper() in name]
        entry = {"file": pf.name, "last_run": mtime, "flags": flags}
        entries.append(entry)
        if flags:
            suspicious.append(entry)
    return {
        "ok": True,
        "primitive": "inspect_prefetch_history",
        "count": len(entries),
        "suspicious": suspicious,
        "entries": entries,
        "_suspicious": len(suspicious),
    }


def inspect_wifi_profiles(args: dict, ctx: dict) -> dict:
    """Saved Wi-Fi profiles + cleartext PSKs (if available)."""
    if not _IS_WINDOWS:
        return _win_only("inspect_wifi_profiles")
    raw = _run("netsh wlan show profiles", timeout=10)
    profiles = []
    for line in raw.splitlines():
        if "All User Profile" in line:
            ssid = line.split(":", 1)[-1].strip()
            # Try to extract key
            key_raw = _run(f'netsh wlan show profile name="{ssid}" key=clear 2>nul', timeout=10)
            psk = ""
            for kline in key_raw.splitlines():
                if "Key Content" in kline:
                    psk = kline.split(":", 1)[-1].strip()
            profiles.append({"ssid": ssid, "psk": psk})
    return {
        "ok": True,
        "primitive": "inspect_wifi_profiles",
        "count": len(profiles),
        "profiles": profiles,
        "_suspicious": 0,
    }


def inspect_named_pipes(args: dict, ctx: dict) -> dict:
    """Named pipe enumeration (common C2 channel indicator)."""
    if not _IS_WINDOWS:
        return _win_only("inspect_named_pipes")
    # Use Sysinternals pipelist or PowerShell
    raw = _run("pipelist.exe /accepteula 2>nul", timeout=15)
    if "[ERROR" in raw or not raw.strip():
        raw = _run(
            'powershell -NoProfile -Command "[System.IO.Directory]::GetFiles(\'\\\\\\\\.\\\\\\\\\\\\\\.\\pipe\\\\'
            '\')"', timeout=15
        )
    # Flag common C2 pipe names
    C2_PIPES = ["mojo.", "postex_", "msagent_", "ntsvcs", "isapi", "comnap",
                "samr", "netlogon", "atsvc", "browser", "epmapper"]
    lines = raw.splitlines()
    pipes = [l.strip() for l in lines if l.strip()]
    suspicious = [p for p in pipes if any(kw in p.lower() for kw in C2_PIPES)]
    return {
        "ok": True,
        "primitive": "inspect_named_pipes",
        "count": len(pipes),
        "suspicious": suspicious,
        "pipes": pipes[:100],
        "_suspicious": len(suspicious),
    }


def inspect_shares(args: dict, ctx: dict) -> dict:
    """SMB share list."""
    if not _IS_WINDOWS:
        return _win_only("inspect_shares")
    raw = _run("net share", timeout=10)
    shares = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 2 and "\\" in parts[1]:
            shares.append({"name": parts[0], "path": parts[1]})
    return {"ok": True, "primitive": "inspect_shares",
            "count": len(shares), "shares": shares, "_suspicious": 0}


def inspect_file_metadata(args: dict, ctx: dict) -> dict:
    """
    stat-level metadata: timestamps, size, owner.
    args: path="C:\\..."
    """
    path = args.get("path", "")
    if not path:
        return {"ok": False, "primitive": "inspect_file_metadata",
                "_error": "path argument required"}
    try:
        st = os.stat(path)
        sha = _sha256_file(path)
        result = {
            "ok": True,
            "primitive": "inspect_file_metadata",
            "path": path,
            "size": st.st_size,
            "sha256": sha,
            "mtime": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
            "atime": datetime.fromtimestamp(st.st_atime, tz=timezone.utc).isoformat(),
            "ctime": datetime.fromtimestamp(st.st_ctime, tz=timezone.utc).isoformat(),
            "_suspicious": 0,
        }
        return result
    except FileNotFoundError:
        return {"ok": False, "primitive": "inspect_file_metadata",
                "_error": f"file not found: {path}"}
    except PermissionError:
        return {"ok": False, "primitive": "inspect_file_metadata",
                "_error": f"access denied: {path}"}


def inspect_recent_files(args: dict, ctx: dict) -> dict:
    """Shell MRU / jump list / Recent Items."""
    if not _IS_WINDOWS:
        return _win_only("inspect_recent_files")
    count = int(args.get("count", 20))
    recent_path = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Recent"
    items = []
    if recent_path.is_dir():
        lnk_files = sorted(recent_path.glob("*.lnk"), key=os.path.getmtime, reverse=True)
        for lnk in lnk_files[:count]:
            items.append({
                "name":  lnk.stem,
                "mtime": datetime.fromtimestamp(lnk.stat().st_mtime, tz=timezone.utc).isoformat(),
            })
    return {
        "ok": True,
        "primitive": "inspect_recent_files",
        "count": len(items),
        "items": items,
        "_suspicious": 0,
    }


def inspect_file_tree(args: dict, ctx: dict) -> dict:
    """
    Recursive directory listing + SHA-256 hashes.
    args: path="C:\\Users\\suspect"  max_depth=3  hash=true
    """
    root     = args.get("path", ".")
    max_depth = int(args.get("max_depth", 3))
    do_hash  = str(args.get("hash", "true")).lower() == "true"

    entries = []
    try:
        root_path = Path(root)
        for item in root_path.rglob("*"):
            depth = len(item.relative_to(root_path).parts)
            if depth > max_depth:
                continue
            if item.is_file():
                entry = {
                    "path":  str(item),
                    "size":  item.stat().st_size,
                    "mtime": datetime.fromtimestamp(
                        item.stat().st_mtime, tz=timezone.utc).isoformat(),
                }
                if do_hash:
                    entry["sha256"] = _sha256_file(str(item))
                entries.append(entry)
    except (PermissionError, OSError):
        pass

    return {
        "ok": True,
        "primitive": "inspect_file_tree",
        "root": root,
        "count": len(entries),
        "entries": entries[:500],
        "_suspicious": 0,
    }


def inspect_ads(args: dict, ctx: dict) -> dict:
    """NTFS Alternate Data Streams scan."""
    if not _IS_WINDOWS:
        return _win_only("inspect_ads")
    path = args.get("path", r"C:\Users")
    # streams.exe from Sysinternals
    raw = _run(f'streams.exe -s "{path}" 2>nul', timeout=30)
    streams = []
    for line in raw.splitlines():
        line = line.strip()
        if ":" in line and "$" not in line and "Stream" not in line:
            streams.append(line)
    return {
        "ok": True,
        "primitive": "inspect_ads",
        "path": path,
        "count": len(streams),
        "streams": streams[:100],
        "_suspicious": len(streams),
    }


# ── Android section ────────────────────────────────────────────────────────────

def _adb(cmd: str, timeout: int = 20) -> str:
    """Run an ADB command and return stdout."""
    return _run(f"adb {cmd}", timeout=timeout)


def inspect_installed_apps(args: dict, ctx: dict) -> dict:
    """Package list + third-party flag + permissions via ADB."""
    raw = _adb("shell pm list packages -3 -i")
    apps = []
    for line in raw.splitlines():
        if line.startswith("package:"):
            apps.append({"package": line.replace("package:", "").split("  ")[0].strip()})
    return {"ok": True, "primitive": "inspect_installed_apps",
            "count": len(apps), "apps": apps, "_suspicious": 0}


def inspect_sms(args: dict, ctx: dict) -> dict:
    """SMS database via ADB content provider."""
    raw = _adb("shell content query --uri content://sms/inbox --projection address,body,date")
    rows = [l.strip() for l in raw.splitlines() if "Row:" in l]
    return {"ok": True, "primitive": "inspect_sms",
            "count": len(rows), "messages": rows[:100], "_suspicious": 0}


def inspect_call_log(args: dict, ctx: dict) -> dict:
    """Call history via ADB."""
    raw = _adb("shell content query --uri content://call_log/calls --projection number,duration,type")
    rows = [l.strip() for l in raw.splitlines() if "Row:" in l]
    return {"ok": True, "primitive": "inspect_call_log",
            "count": len(rows), "calls": rows[:100], "_suspicious": 0}


def inspect_location(args: dict, ctx: dict) -> dict:
    """GPS history via ADB."""
    raw = _adb("shell cat /data/data/com.google.android.gms/databases/cache.db 2>/dev/null", timeout=30)
    return {"ok": True, "primitive": "inspect_location",
            "raw_size": len(raw), "_suspicious": 0}


def inspect_whatsapp_db(args: dict, ctx: dict) -> dict:
    """WhatsApp msgstore.db pull via ADB."""
    dest = "/tmp/jky_wa_msgstore.db"
    _adb(f"pull /sdcard/WhatsApp/Databases/msgstore.db {dest}", timeout=60)
    size = os.path.getsize(dest) if os.path.exists(dest) else 0
    return {"ok": True, "primitive": "inspect_whatsapp_db",
            "local_path": dest, "size": size, "_suspicious": 0}


def inspect_telegram_db(args: dict, ctx: dict) -> dict:
    """Telegram local cache pull via ADB."""
    dest = "/tmp/jky_tg_cache.db"
    _adb(f"pull /data/data/org.telegram.messenger/files/cache4.db {dest}", timeout=60)
    size = os.path.getsize(dest) if os.path.exists(dest) else 0
    return {"ok": True, "primitive": "inspect_telegram_db",
            "local_path": dest, "size": size, "_suspicious": 0}


def inspect_contacts(args: dict, ctx: dict) -> dict:
    """Device contact list via ADB."""
    raw = _adb("shell content query --uri content://contacts/phones --projection display_name,number")
    rows = [l.strip() for l in raw.splitlines() if "Row:" in l]
    return {"ok": True, "primitive": "inspect_contacts",
            "count": len(rows), "contacts": rows[:200], "_suspicious": 0}


# ══════════════════════════════════════════════════════════════════════════════
# SECTION: hash
# ══════════════════════════════════════════════════════════════════════════════

def hash_file(args: dict, ctx: dict) -> dict:
    """SHA-256 of a single file."""
    path = args.get("path", "")
    if not path:
        return {"ok": False, "primitive": "hash_file", "_error": "path required"}
    sha = _sha256_file(path)
    if not sha:
        return {"ok": False, "primitive": "hash_file", "_error": f"cannot hash: {path}"}
    # VirusTotal-style lookup placeholder (no live VT call without API key)
    return {
        "ok": True,
        "primitive": "hash_file",
        "path": path,
        "sha256": sha,
        "_suspicious": 0,
    }


def hash_directory(args: dict, ctx: dict) -> dict:
    """Recursive SHA-256 of all files in a directory."""
    path = args.get("path", ".")
    results = {}
    try:
        for item in Path(path).rglob("*"):
            if item.is_file():
                results[str(item)] = _sha256_file(str(item))
    except PermissionError:
        pass
    return {
        "ok": True,
        "primitive": "hash_directory",
        "path": path,
        "count": len(results),
        "hashes": dict(list(results.items())[:500]),
        "_suspicious": 0,
    }


def hash_memory_region(args: dict, ctx: dict) -> dict:
    """SHA-256 of a live memory region (acquire then hash)."""
    result = acquire_memory_region(args, ctx)
    if not result.get("ok"):
        return {**result, "primitive": "hash_memory_region"}
    raw_sha = result.get("sha256", "")
    return {
        "ok": True,
        "primitive": "hash_memory_region",
        "pid": args.get("pid"),
        "base": args.get("base"),
        "size": result.get("size"),
        "sha256": raw_sha,
        "_suspicious": result.get("_suspicious", 0),
    }


# ══════════════════════════════════════════════════════════════════════════════
# SECTION: capture — real-time (active / blocking)
# ══════════════════════════════════════════════════════════════════════════════

def capture_traffic(args: dict, ctx: dict) -> dict:
    """
    Packet capture (pcap) using dumpcap / tcpdump.
    args: duration=30  interface="eth0"|"any"  outfile="capture.pcap"
    """
    duration  = int(args.get("duration", 30))
    iface     = args.get("interface", "any")
    outfile   = args.get("outfile", "/tmp/jky_capture.pcap")

    # Try dumpcap (Wireshark), fall back to tcpdump
    cmd_win = (
        f'dumpcap.exe -i "{iface}" -a duration:{duration} -w "{outfile}" 2>nul'
    )
    cmd_linux = (
        f'tcpdump -i {iface} -G {duration} -W 1 -w "{outfile}" 2>/dev/null'
    )
    cmd = cmd_win if _IS_WINDOWS else cmd_linux
    out = _run(cmd, timeout=duration + 10)
    size = os.path.getsize(outfile) if os.path.exists(outfile) else 0
    return {
        "ok": True,
        "primitive": "capture_traffic",
        "interface": iface,
        "duration_s": duration,
        "outfile": outfile,
        "size": size,
        "tool_output": out[:512],
        "_suspicious": 0,
    }


def capture_keystrokes(args: dict, ctx: dict) -> dict:
    """
    Keyboard input monitor — samples for duration seconds.
    args: duration=10
    Registers a low-level WH_KEYBOARD_LL hook on Windows.
    """
    if not _IS_WINDOWS:
        return _win_only("capture_keystrokes")
    duration = int(args.get("duration", 10))
    log_path = args.get("outfile", "/tmp/jky_keylog.txt")

    # Inline PowerShell keystroke logger
    ps_script = r"""
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.IO;
public class KeyLogger {
    [DllImport("user32.dll")] static extern short GetAsyncKeyState(int vKey);
    public static void Capture(string outfile, int durationMs) {
        var sw = new StreamWriter(outfile, false);
        var end = DateTime.Now.AddMilliseconds(durationMs);
        while (DateTime.Now < end) {
            for (int vk = 8; vk <= 255; vk++) {
                if ((GetAsyncKeyState(vk) & 0x8001) != 0) {
                    sw.Write("[" + vk + "]");
                    sw.Flush();
                }
            }
            System.Threading.Thread.Sleep(10);
        }
        sw.Close();
    }
}
"@
[KeyLogger]::Capture("{log_path}", {dur_ms})
""".replace("{log_path}", log_path).replace("{dur_ms}", str(duration * 1000))

    _run(f'powershell -NoProfile -W Hidden -c "{ps_script}"', timeout=duration + 10)
    captured = ""
    if os.path.exists(log_path):
        with open(log_path, "r", errors="replace") as f:
            captured = f.read()[:4096]
    return {
        "ok": True,
        "primitive": "capture_keystrokes",
        "duration_s": duration,
        "keystrokes": captured,
        "_suspicious": 0,
    }


def capture_clipboard(args: dict, ctx: dict) -> dict:
    """Clipboard content snapshot."""
    if not _IS_WINDOWS:
        raw = _run("xclip -o 2>/dev/null || xsel --clipboard --output 2>/dev/null")
    else:
        raw = _run("powershell -NoProfile -c \"Get-Clipboard\"", timeout=10)
    suspicious = any(kw in raw.lower() for kw in ["password", "token", "secret", "-----begin"])
    return {
        "ok": True,
        "primitive": "capture_clipboard",
        "content": raw[:2048],
        "_suspicious": 1 if suspicious else 0,
    }


def capture_screen(args: dict, ctx: dict) -> dict:
    """Screenshot saved to file."""
    outfile = args.get("outfile", "/tmp/jky_screenshot.png")
    if _IS_WINDOWS:
        ps = (
            'Add-Type -AssemblyName System.Windows.Forms,System.Drawing; '
            '$s=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds; '
            '$b=New-Object System.Drawing.Bitmap($s.Width,$s.Height); '
            '$g=[System.Drawing.Graphics]::FromImage($b); '
            '$g.CopyFromScreen($s.Location,[System.Drawing.Point]::Empty,$s.Size); '
            f'$b.Save("{outfile}"); $g.Dispose(); $b.Dispose()'
        )
        _run(f'powershell -NoProfile -W Hidden -c "{ps}"', timeout=15)
    else:
        _run(f"scrot {outfile} 2>/dev/null || import -window root {outfile} 2>/dev/null", timeout=15)
    size = os.path.getsize(outfile) if os.path.exists(outfile) else 0
    return {
        "ok": True,
        "primitive": "capture_screen",
        "outfile": outfile,
        "size": size,
        "_suspicious": 0,
    }


# ══════════════════════════════════════════════════════════════════════════════
# SECTION: extract — parse/decode from data source
# ══════════════════════════════════════════════════════════════════════════════

def _browser_db_path(browser: str, profile: str = "Default") -> list:
    """Return candidate SQLite paths for a browser's history database."""
    appdata = os.environ.get("LOCALAPPDATA", "")
    home    = Path.home()
    candidates = {
        "chrome": [
            Path(appdata) / "Google" / "Chrome" / "User Data" / profile / "History",
            home / ".config" / "google-chrome" / profile / "History",
        ],
        "edge": [
            Path(appdata) / "Microsoft" / "Edge" / "User Data" / profile / "History",
        ],
        "firefox": [
            Path(os.environ.get("APPDATA", "")) / "Mozilla" / "Firefox" / "Profiles",
            home / ".mozilla" / "firefox",
        ],
    }
    return [str(p) for p in candidates.get(browser.lower(), []) if Path(str(p)).exists()]


def extract_browser_history(args: dict, ctx: dict) -> dict:
    """Chrome/Edge/Firefox SQLite history + downloads."""
    browser = args.get("browser", "chrome")
    paths   = _browser_db_path(browser)
    if not paths:
        return {"ok": False, "primitive": "extract_browser_history",
                "_error": f"no {browser} history database found"}
    db_path = paths[0]
    try:
        import sqlite3, shutil, tempfile
        # Copy to temp to avoid lock
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        shutil.copy2(db_path, tmp.name)
        tmp.close()
        conn   = sqlite3.connect(tmp.name)
        cursor = conn.execute(
            "SELECT url, title, visit_count, last_visit_time "
            "FROM urls ORDER BY last_visit_time DESC LIMIT 500"
        )
        rows = [{"url": r[0], "title": r[1], "visits": r[2]} for r in cursor.fetchall()]
        conn.close()
        os.unlink(tmp.name)
        IOC_DOMAINS = ["mega.nz","wetransfer","pastebin","ngrok","serveo","dyndns"]
        suspicious  = [r for r in rows if any(d in r["url"].lower() for d in IOC_DOMAINS)]
        return {
            "ok": True,
            "primitive": "extract_browser_history",
            "browser": browser,
            "count": len(rows),
            "suspicious": suspicious,
            "records": rows,
            "_suspicious": len(suspicious),
        }
    except Exception as exc:
        return {"ok": False, "primitive": "extract_browser_history", "_error": str(exc)}


def extract_browser_cookies(args: dict, ctx: dict) -> dict:
    """Browser cookie databases."""
    browser = args.get("browser", "chrome")
    appdata = os.environ.get("LOCALAPPDATA", "")
    cookie_path = Path(appdata) / "Google" / "Chrome" / "User Data" / "Default" / "Cookies"
    if not cookie_path.exists():
        return {"ok": False, "primitive": "extract_browser_cookies",
                "_error": "Cookies DB not found"}
    try:
        import sqlite3, shutil, tempfile
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        shutil.copy2(str(cookie_path), tmp.name)
        tmp.close()
        conn = sqlite3.connect(tmp.name)
        cursor = conn.execute(
            "SELECT host_key, name, expires_utc FROM cookies LIMIT 500"
        )
        rows = [{"host": r[0], "name": r[1]} for r in cursor.fetchall()]
        conn.close()
        os.unlink(tmp.name)
        return {"ok": True, "primitive": "extract_browser_cookies",
                "count": len(rows), "cookies": rows, "_suspicious": 0}
    except Exception as exc:
        return {"ok": False, "primitive": "extract_browser_cookies", "_error": str(exc)}


def extract_browser_passwords(args: dict, ctx: dict) -> dict:
    """
    Browser saved credentials (Login Data).
    Passwords are AES-256-GCM encrypted with DPAPI master key on Windows.
    Returns encrypted blobs — full decryption requires DPAPI CryptUnprotectData
    which must run in the context of the target user (handled at agent layer).
    """
    browser = args.get("browser", "chrome")
    appdata = os.environ.get("LOCALAPPDATA", "")
    login_path = Path(appdata) / "Google" / "Chrome" / "User Data" / "Default" / "Login Data"
    if not login_path.exists():
        return {"ok": False, "primitive": "extract_browser_passwords",
                "_error": "Login Data not found"}
    try:
        import sqlite3, shutil, tempfile
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        shutil.copy2(str(login_path), tmp.name)
        tmp.close()
        conn = sqlite3.connect(tmp.name)
        cursor = conn.execute(
            "SELECT origin_url, username_value, password_value FROM logins"
        )
        rows = []
        for r in cursor.fetchall():
            rows.append({
                "url":      r[0],
                "username": r[1],
                "password_enc": r[2].hex() if r[2] else "",
            })
        conn.close()
        os.unlink(tmp.name)
        return {"ok": True, "primitive": "extract_browser_passwords",
                "count": len(rows), "credentials": rows, "_suspicious": len(rows)}
    except Exception as exc:
        return {"ok": False, "primitive": "extract_browser_passwords", "_error": str(exc)}


def extract_mft(args: dict, ctx: dict) -> dict:
    """NTFS Master File Table records."""
    if not _IS_WINDOWS:
        return _win_only("extract_mft")
    volume = args.get("volume", r"\\.\C:")
    outfile = args.get("outfile", "/tmp/jky_mft.bin")
    raw = _run(
        f'powershell -NoProfile -c "'
        f'$f=[System.IO.File]::Open(\'{volume}\',\'Open\',\'Read\',\'ReadWrite\'); '
        f'$b=New-Object byte[](4096); $r=$f.Read($b,0,4096); $f.Close(); '
        f'[System.IO.File]::WriteAllBytes(\'{outfile}\',$b)"', timeout=20
    )
    size = os.path.getsize(outfile) if os.path.exists(outfile) else 0
    return {"ok": True, "primitive": "extract_mft",
            "volume": volume, "outfile": outfile, "size": size, "_suspicious": 0}


def extract_evtx(args: dict, ctx: dict) -> dict:
    """Parse a raw .evtx file."""
    path = args.get("path", "")
    if not path or not os.path.exists(path):
        return {"ok": False, "primitive": "extract_evtx",
                "_error": f"evtx file not found: {path}"}
    cmd = (
        f'powershell -NoProfile -c "Get-WinEvent -Path \'{path}\' | '
        f'Select-Object TimeCreated,Id,Message | ConvertTo-Json -Depth 1"'
    )
    raw = _run(cmd, timeout=30)
    try:
        events = json.loads(raw) if raw.strip().startswith("[") else []
    except Exception:
        events = [{"raw": raw[:4096]}]
    return {"ok": True, "primitive": "extract_evtx",
            "path": path, "count": len(events), "events": events[:100], "_suspicious": 0}


def extract_prefetch(args: dict, ctx: dict) -> dict:
    """Parse a single .pf file (execution metadata)."""
    path = args.get("path", "")
    if not path or not os.path.exists(path):
        return {"ok": False, "primitive": "extract_prefetch",
                "_error": f"prefetch file not found: {path}"}
    try:
        with open(path, "rb") as f:
            header = f.read(84)
        # Bytes 0-3: signature (SCCA), 4: version, 84: executable name in UTF-16LE
        sig  = header[:4]
        ver  = struct.unpack_from("<I", header, 4)[0] if len(header) >= 8 else 0
        name = header[16:76].decode("utf-16-le", errors="replace").rstrip("\x00")
        mtime = datetime.fromtimestamp(
            os.path.getmtime(path), tz=timezone.utc).isoformat()
        return {
            "ok": True,
            "primitive": "extract_prefetch",
            "path": path,
            "signature": sig.hex(),
            "version": ver,
            "exe_name": name,
            "last_run": mtime,
            "_suspicious": 0,
        }
    except Exception as exc:
        return {"ok": False, "primitive": "extract_prefetch", "_error": str(exc)}


def extract_lnk(args: dict, ctx: dict) -> dict:
    """Parse a .lnk shortcut file — target path, working dir, timestamps."""
    path = args.get("path", "")
    if not path or not os.path.exists(path):
        return {"ok": False, "primitive": "extract_lnk",
                "_error": f"lnk file not found: {path}"}
    try:
        with open(path, "rb") as f:
            data = f.read(0x4C + 260)
        # LNK header: sig at 0, target size at 0x4C
        sig = data[:4].hex()
        # Simple extraction: look for NULL-terminated UTF-16 string regions
        raw_str = _run(
            f'powershell -NoProfile -c "(New-Object -ComObject WScript.Shell).CreateShortcut(\'{path}\').TargetPath"',
            timeout=10
        )
        return {
            "ok": True,
            "primitive": "extract_lnk",
            "path": path,
            "sig": sig,
            "target": raw_str.strip(),
            "_suspicious": 0,
        }
    except Exception as exc:
        return {"ok": False, "primitive": "extract_lnk", "_error": str(exc)}


def extract_registry_hive(args: dict, ctx: dict) -> dict:
    """Parse an offline registry hive file."""
    path = args.get("path", "")
    if not path or not os.path.exists(path):
        return {"ok": False, "primitive": "extract_registry_hive",
                "_error": f"hive not found: {path}"}
    sha = _sha256_file(path)
    size = os.path.getsize(path)
    # Verify regf signature
    with open(path, "rb") as f:
        sig = f.read(4)
    valid = sig == b"regf"
    return {
        "ok": True,
        "primitive": "extract_registry_hive",
        "path": path,
        "size": size,
        "sha256": sha,
        "valid_signature": valid,
        "_suspicious": 0,
    }


def extract_memory_strings(args: dict, ctx: dict) -> dict:
    """Printable strings from a raw memory dump."""
    path    = args.get("path", "")
    min_len = int(args.get("min_len", 6))
    if not path or not os.path.exists(path):
        return {"ok": False, "primitive": "extract_memory_strings",
                "_error": f"dump file not found: {path}"}
    try:
        with open(path, "rb") as f:
            data = f.read(50 * 1024 * 1024)  # cap at 50 MB
        strings = re.findall(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}", data)
        decoded = [s.decode("ascii", errors="replace") for s in strings]
        ioc = [s for s in decoded if any(
            kw in s.lower() for kw in ["password","token","api_key","secret","http://"]
        )]
        return {
            "ok": True,
            "primitive": "extract_memory_strings",
            "path": path,
            "total_strings": len(decoded),
            "ioc_strings": ioc[:100],
            "_suspicious": len(ioc),
        }
    except Exception as exc:
        return {"ok": False, "primitive": "extract_memory_strings", "_error": str(exc)}


# ══════════════════════════════════════════════════════════════════════════════
# SECTION: dump — raw binary export to evidence store
# ══════════════════════════════════════════════════════════════════════════════

def dump_process(args: dict, ctx: dict) -> dict:
    """Full process memory dump (minidump or full)."""
    if not _IS_WINDOWS:
        return _win_only("dump_process")
    pid     = int(args.get("pid", 0))
    outfile = args.get("outfile", f"/tmp/jky_proc_{pid}.dmp")
    mode    = args.get("mode", "mini")

    # Try procdump.exe (Sysinternals), fall back to PowerShell Out-Minidump
    procdump_flag = "" if mode == "mini" else "-ma"
    raw = _run(f'procdump.exe {procdump_flag} -accepteula {pid} "{outfile}" 2>nul', timeout=60)
    if "[ERROR" in raw or not os.path.exists(outfile):
        # Fallback: native MiniDumpWriteDump via PowerShell
        ps = (
            f'$p = Get-Process -Id {pid}; '
            f'$f = [System.IO.File]::Create("{outfile}"); '
            f'[System.Diagnostics.Process].Assembly.'
            f'GetType("System.Diagnostics.MiniDump").GetMethod("Write",'
            f'[System.Reflection.BindingFlags]"NonPublic,Static").Invoke($null,@($p.Handle,$f))'
        )
        _run(f'powershell -NoProfile -c "{ps}"', timeout=60)

    size = os.path.getsize(outfile) if os.path.exists(outfile) else 0
    return {
        "ok": True,
        "primitive": "dump_process",
        "pid": pid,
        "outfile": outfile,
        "size": size,
        "_suspicious": 0,
    }


def dump_registry_hive(args: dict, ctx: dict) -> dict:
    """Export a live registry hive to file."""
    if not _IS_WINDOWS:
        return _win_only("dump_registry_hive")
    hive    = args.get("hive", "HKLM\\SAM")
    outfile = args.get("outfile", "/tmp/jky_hive.dat")
    raw     = _run(f'reg save "{hive}" "{outfile}" /y 2>nul', timeout=20)
    size    = os.path.getsize(outfile) if os.path.exists(outfile) else 0
    return {
        "ok": True,
        "primitive": "dump_registry_hive",
        "hive": hive,
        "outfile": outfile,
        "size": size,
        "tool_output": raw[:256],
        "_suspicious": 0,
    }


def dump_mft_raw(args: dict, ctx: dict) -> dict:
    """Raw MFT export from NTFS volume."""
    if not _IS_WINDOWS:
        return _win_only("dump_mft_raw")
    volume  = args.get("volume", r"\\.\C:")
    outfile = args.get("outfile", "/tmp/jky_mft_raw.bin")
    # Use RawCopy or direct volume read
    raw = _run(f'RawCopy.exe /FileNamePath:{volume}\\$MFT /OutputPath:/tmp 2>nul', timeout=60)
    if "[ERROR" in raw:
        # Fallback: direct read with PowerShell FileStream
        ps = (
            f'$f=[System.IO.File]::Open(\'{volume}\',\'Open\',\'Read\',\'ReadWrite\'); '
            f'$r=New-Object byte[](1048576); $f.Read($r,0,$r.Length) | Out-Null; $f.Close(); '
            f'[System.IO.File]::WriteAllBytes(\'{outfile}\',$r)'
        )
        _run(f'powershell -NoProfile -c "{ps}"', timeout=30)
    size = os.path.getsize(outfile) if os.path.exists(outfile) else 0
    return {
        "ok": True,
        "primitive": "dump_mft_raw",
        "volume": volume,
        "outfile": outfile,
        "size": size,
        "_suspicious": 0,
    }


def dump_pagefile(args: dict, ctx: dict) -> dict:
    """Pagefile / swapfile content dump."""
    if not _IS_WINDOWS:
        return _win_only("dump_pagefile")
    outfile = args.get("outfile", "/tmp/jky_pagefile.bin")
    # Offline copy via Volume Shadow Copy or direct (needs SYSTEM)
    src = r"C:\pagefile.sys"
    raw = _run(f'robocopy C:\\ /tmp jky_pagefile.bin /B /NP 2>nul', timeout=60)
    size = os.path.getsize(outfile) if os.path.exists(outfile) else 0
    return {
        "ok": True,
        "primitive": "dump_pagefile",
        "outfile": outfile,
        "size": size,
        "_suspicious": 0,
    }


def dump_hiberfil(args: dict, ctx: dict) -> dict:
    """Hibernate file dump."""
    if not _IS_WINDOWS:
        return _win_only("dump_hiberfil")
    outfile = args.get("outfile", "/tmp/jky_hiberfil.bin")
    raw     = _run(f'robocopy C:\\ /tmp jky_hiberfil.bin /B /NP 2>nul', timeout=60)
    # Convert with volatility's hibr2bin if available
    _run(f'hibr2bin.exe /INPUT:C:\\hiberfil.sys /OUTPUT:"{outfile}" 2>nul', timeout=120)
    size = os.path.getsize(outfile) if os.path.exists(outfile) else 0
    return {
        "ok": True,
        "primitive": "dump_hiberfil",
        "outfile": outfile,
        "size": size,
        "_suspicious": 0,
    }


# ══════════════════════════════════════════════════════════════════════════════
# SECTION: list — fast enumeration, low footprint
# ══════════════════════════════════════════════════════════════════════════════

def list_processes(args: dict, ctx: dict) -> dict:
    """Quick process name+PID list — no hashes, minimal overhead."""
    ps = _psutil()
    if ps:
        procs = [{"pid": p.pid, "name": p.name()} for p in ps.process_iter(["pid","name"])]
        return {"ok": True, "primitive": "list_processes",
                "count": len(procs), "processes": procs, "_suspicious": 0}
    raw = _run("tasklist /FO CSV /NH", timeout=15)
    procs = []
    for line in raw.splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) >= 2:
            procs.append({"name": parts[0], "pid": parts[1]})
    return {"ok": True, "primitive": "list_processes",
            "count": len(procs), "processes": procs, "_suspicious": 0}


def list_connections(args: dict, ctx: dict) -> dict:
    """Quick socket list — no PID resolution."""
    raw = _run("netstat -an", timeout=15)
    conns = [l.strip() for l in raw.splitlines() if l.strip().startswith(("TCP","UDP"))]
    return {"ok": True, "primitive": "list_connections",
            "count": len(conns), "connections": conns, "_suspicious": 0}


def list_users(args: dict, ctx: dict) -> dict:
    """Local user accounts."""
    if not _IS_WINDOWS:
        raw = _run("cat /etc/passwd | cut -d: -f1", timeout=10)
    else:
        raw = _run("net user", timeout=10)
    users = [l.strip() for l in raw.splitlines() if l.strip() and not l.startswith("-")]
    return {"ok": True, "primitive": "list_users",
            "count": len(users), "users": users, "_suspicious": 0}


def list_groups(args: dict, ctx: dict) -> dict:
    """Local group memberships."""
    if not _IS_WINDOWS:
        raw = _run("cat /etc/group", timeout=10)
    else:
        raw = _run("net localgroup", timeout=10)
    groups = [l.strip() for l in raw.splitlines() if l.strip() and "*" in l]
    return {"ok": True, "primitive": "list_groups",
            "count": len(groups), "groups": groups, "_suspicious": 0}


def list_sessions(args: dict, ctx: dict) -> dict:
    """Active logon sessions."""
    raw = _run("query session 2>nul || who", timeout=10)
    sessions = [l.strip() for l in raw.splitlines() if l.strip()]
    return {"ok": True, "primitive": "list_sessions",
            "count": len(sessions), "sessions": sessions, "_suspicious": 0}


def list_patches(args: dict, ctx: dict) -> dict:
    """Installed Windows patches / hotfixes."""
    if not _IS_WINDOWS:
        return _win_only("list_patches")
    raw = _run("wmic qfe list brief /format:csv 2>nul", timeout=20)
    patches = []
    for line in raw.splitlines()[1:]:
        cols = line.split(",")
        if len(cols) >= 3:
            patches.append({"hotfix_id": cols[2], "description": cols[1],
                             "installed": cols[5] if len(cols) > 5 else ""})
    # Flag missing critical patches (MS17-010, PrintNightmare, etc.)
    CRITICAL = {"KB4012212", "KB5004945", "KB5003173", "KB4601050"}
    installed_ids = {p["hotfix_id"] for p in patches}
    missing = CRITICAL - installed_ids
    return {
        "ok": True,
        "primitive": "list_patches",
        "count": len(patches),
        "missing_critical": list(missing),
        "patches": patches[:200],
        "_suspicious": len(missing),
    }


def list_software(args: dict, ctx: dict) -> dict:
    """Installed programs — registry uninstall keys."""
    if not _IS_WINDOWS:
        return _win_only("list_software")
    raw = _run(
        'powershell -NoProfile -c "'
        'Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* |'
        'Select-Object DisplayName,DisplayVersion,Publisher | ConvertTo-Json"', timeout=20
    )
    try:
        software = json.loads(raw) if raw.strip().startswith("[") else []
    except Exception:
        software = [{"raw": raw[:4096]}]
    IOC_SW = ["ngrok", "teamviewer", "anydesk", "psexec", "processhacker", "wireshark"]
    suspicious = [s for s in software if isinstance(s, dict) and any(
        ioc in str(s.get("DisplayName", "")).lower() for ioc in IOC_SW
    )]
    return {
        "ok": True,
        "primitive": "list_software",
        "count": len(software),
        "suspicious": suspicious,
        "software": software[:200],
        "_suspicious": len(suspicious),
    }


def list_environment(args: dict, ctx: dict) -> dict:
    """Environment variables."""
    env = dict(os.environ)
    # Redact credential-adjacent vars
    REDACT = {"PASSWORD", "TOKEN", "SECRET", "API_KEY", "AWS_SECRET"}
    redacted = {
        k: ("***REDACTED***" if any(r in k.upper() for r in REDACT) else v)
        for k, v in env.items()
    }
    return {"ok": True, "primitive": "list_environment",
            "count": len(redacted), "env": redacted, "_suspicious": 0}


def list_timezone(args: dict, ctx: dict) -> dict:
    """System timezone + current UTC offset."""
    import time as _time
    tz_name = _time.tzname
    utc_off = -_time.timezone // 3600
    return {
        "ok": True,
        "primitive": "list_timezone",
        "timezone": tz_name,
        "utc_offset_hours": utc_off,
        "_suspicious": 0,
    }
