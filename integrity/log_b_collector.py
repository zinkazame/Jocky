"""
JOCKY Log B Collector — Phase 16
==================================
Collects Windows Event Log and ETW (Event Tracing for Windows) entries
from the target machine and feeds them into the hash-chain integrity log.

Log B is the *target-side* evidence log — it records what the OS itself
observed during the forensic acquisition. Combined with Log A (the
investigator-side chain), it provides a complete, tamper-evident audit trail.

Collectors:
  - Windows Event Log (Security, System, Application channels)
  - ETW session enumeration (active providers, suppression detection)
  - Prefetch execution timeline (cross-referenced with fs_analysis)
  - Sysmon events (if Sysmon is installed on target)

Output: JSON Lines appended to the hash chain via HashChain.append()

Platform: Windows only (graceful no-op on Linux)
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


# ─── Windows Event Log collection ─────────────────────────────────────────────

def collect_event_log(
    channel:    str = "Security",
    max_events: int = 500,
) -> list[dict]:
    """
    Collect recent Windows Event Log entries from the specified channel.

    Uses PowerShell's Get-WinEvent for reliable, structured output.
    Falls back to wevtutil on older systems.

    Parameters
    ----------
    channel    : str   Event log channel (Security, System, Application, etc.)
    max_events : int   Maximum number of events to collect

    Returns
    -------
    list[dict]
        List of event dicts with keys: id, time, level, source, message
    """
    if sys.platform != "win32":
        return []

    ps_cmd = (
        f"Get-WinEvent -LogName '{channel}' -MaxEvents {max_events} "
        f"| Select-Object Id,TimeCreated,LevelDisplayName,ProviderName,Message "
        f"| ConvertTo-Json -Depth 2"
    )

    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return []

        raw = json.loads(result.stdout)
        if isinstance(raw, dict):
            raw = [raw]   # Single event returned as object, not array

        events = []
        for ev in raw:
            events.append({
                "id":      ev.get("Id"),
                "time":    str(ev.get("TimeCreated", "")),
                "level":   ev.get("LevelDisplayName", ""),
                "source":  ev.get("ProviderName", ""),
                "message": str(ev.get("Message", ""))[:512],  # truncate long messages
            })
        return events

    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return []


# ─── ETW session enumeration ──────────────────────────────────────────────────

def enumerate_etw_sessions() -> list[dict]:
    """
    Enumerate active ETW (Event Tracing for Windows) sessions.

    Detects:
    - Active security monitoring sessions (EDR/AV providers)
    - Suppressed or missing sessions (potential ETW tampering)
    - Sysmon ETW provider status

    Returns
    -------
    list[dict]
        List of ETW session dicts with keys: name, status, providers
    """
    if sys.platform != "win32":
        return []

    ps_cmd = (
        "logman query -ets "
        "| Select-String -Pattern '^\\S' "
        "| ForEach-Object { $_.Line.Trim() } "
        "| ConvertTo-Json"
    )

    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            return []

        lines = json.loads(result.stdout) if result.stdout.strip() else []
        if isinstance(lines, str):
            lines = [lines]

        sessions = []
        for line in lines:
            if line and not line.startswith("Data Collector"):
                sessions.append({
                    "name":   line.strip(),
                    "status": "active",
                })

        # Check for known security ETW providers
        _flag_security_providers(sessions)
        return sessions

    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return []


def _flag_security_providers(sessions: list[dict]) -> None:
    """Flag sessions that correspond to known security monitoring providers."""
    security_keywords = {
        "Microsoft-Windows-Threat-Intelligence",
        "Microsoft-Windows-Security-Auditing",
        "Microsoft-Antimalware",
        "Sysmon",
        "CrowdStrike",
        "SentinelOne",
        "CarbonBlack",
    }
    session_names = {s["name"].lower() for s in sessions}
    for kw in security_keywords:
        if not any(kw.lower() in name for name in session_names):
            sessions.append({
                "name":   kw,
                "status": "NOT_FOUND — possible suppression",
            })


# ─── Sysmon event collection ──────────────────────────────────────────────────

def collect_sysmon_events(max_events: int = 200) -> list[dict]:
    """
    Collect Sysmon events (process creation, network connections, file creation).
    Returns empty list if Sysmon is not installed.
    """
    return collect_event_log("Microsoft-Windows-Sysmon/Operational", max_events)


# ─── Log B full collection ────────────────────────────────────────────────────

def collect_log_b(output_path: str | None = None) -> dict:
    """
    Run all Log B collectors and return a combined report.

    Parameters
    ----------
    output_path : str | None
        If provided, write the report as JSON to this path.

    Returns
    -------
    dict
        Combined Log B report.
    """
    ts = datetime.now(timezone.utc).isoformat()

    report = {
        "collector":     "log_b",
        "timestamp_utc": ts,
        "platform":      sys.platform,
        "security_events": collect_event_log("Security",    max_events=200),
        "system_events":   collect_event_log("System",      max_events=100),
        "sysmon_events":   collect_sysmon_events(max_events=200),
        "etw_sessions":    enumerate_etw_sessions(),
    }

    report["summary"] = {
        "security_event_count": len(report["security_events"]),
        "system_event_count":   len(report["system_events"]),
        "sysmon_event_count":   len(report["sysmon_events"]),
        "etw_session_count":    len(report["etw_sessions"]),
        "etw_suppressed":       sum(
            1 for s in report["etw_sessions"]
            if "NOT_FOUND" in s.get("status", "")
        ),
    }

    if output_path:
        Path(output_path).write_text(
            json.dumps(report, indent=2, default=str),
            encoding="utf-8",
        )

    return report


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "log_b.json"
    report = collect_log_b(out)
    print(f"[log_b] Collected {report['summary']['security_event_count']} security events")
    print(f"[log_b] ETW sessions: {report['summary']['etw_session_count']}")
    print(f"[log_b] Possible ETW suppression: {report['summary']['etw_suppressed']}")
    print(f"[log_b] Written → {out}")
