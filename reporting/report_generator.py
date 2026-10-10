"""
JOCKY Report Generator — Phase 13.6 / v1.0
reporting/report_generator.py

Generates a self-contained HTML forensic intelligence report from a JOCKY
evidence directory.  Reads both the raw acquired artifact JSON files and the
new parsing-layer output under evidence/<ts>/parsed/.

Usage:
    python reporting/report_generator.py --evidence-dir evidence/20261002_143022
    python reporting/report_generator.py --evidence-dir evidence/20261002_143022 \\
        --out report_20261002.html --title "NTRO Case 2026-001"

Output: one fully self-contained HTML file (all CSS + JS inlined, no external deps).

Sections rendered:
  1.  Summary                  — case metadata, agent info, collection timestamp
  2.  Processes                — procs.json
  3.  Network Connections      — connections.json
  4.  Services                 — services.json
  5.  Persistence              — persistence.json
  6.  USB History              — usb_history.json  (from forensics primitives)
  7.  Loaded Modules           — modules_*.json
  8.  DNS Cache                — dns_cache.json
  9.  ARP / Routes             — arp.json / routes.json
  10. Typed URLs               — typed_urls.json
  11. Scheduled Tasks          — tasks.json
  12. Prefetch (raw)           — prefetch.json
  13. Suspicious Files         — suspicious_*.json
  14. Parsed Evidence          ← NEW: reads evidence/<ts>/parsed/
      14a. EVTX Events         — evtx_*_parsed.json   (filterable table)
      14b. Prefetch Timeline   — prefetch_parsed.json  (timeline bar)
      14c. Browser History     — browser_*_parsed.json (URL table, red = suspicious)
      14d. Registry Artifacts  — registry_*_parsed.json
      14e. LNK Files           — lnk_parsed.json
      14f. Shimcache           — shimcache_parsed.json
      14g. AmCache             — amcache_parsed.json
      14h. SRUM Network        — srum_*_parsed.json
      14i. Activity Timeline   — timeline_parsed.json
      14j. $I30 Deleted Files  — i30_parsed.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib  import Path
from typing   import Any, Dict, List, Optional, Tuple

# ─── Helpers ──────────────────────────────────────────────────────────────────

def _safe_load(path: Path) -> Any:
    """Load JSON file, return None on any error."""
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def _esc(s: Any) -> str:
    """HTML-escape a value (convert to str first)."""
    s = str(s) if s is not None else ""
    return (s
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;"))


def _fmt_ts(ts: Any) -> str:
    if not ts:
        return "—"
    s = str(ts)
    # already ISO: trim microseconds for display
    if "T" in s:
        return s[:19].replace("T", " ")
    return s


def _row(*cells, cls: str = "") -> str:
    inner = "".join(f"<td>{_esc(c)}</td>" for c in cells)
    if cls:
        return f'<tr class="{cls}">{inner}</tr>\n'
    return f"<tr>{inner}</tr>\n"


def _header_row(*headers) -> str:
    inner = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    return f"<tr>{inner}</tr>\n"


def _table(headers: List[str], rows_html: str, table_id: str = "", extra_cls: str = "") -> str:
    id_attr  = f' id="{table_id}"' if table_id else ""
    cls_attr = f' class="{extra_cls}"' if extra_cls else ""
    thead    = _header_row(*headers)
    return (f'<div class="tbl-wrap">'
            f'<table{id_attr}{cls_attr}>'
            f'<thead>{thead}</thead>'
            f'<tbody>{rows_html}</tbody>'
            f'</table></div>\n')


def _section(title: str, content: str, section_id: str = "") -> str:
    id_attr = f' id="{section_id}"' if section_id else ""
    return (f'<section{id_attr}>'
            f'<h2>{_esc(title)}</h2>'
            f'{content}'
            f'</section>\n')


def _empty(msg: str = "No data.") -> str:
    return f'<p class="empty">{_esc(msg)}</p>'


# ─── Evidence-dir discovery ───────────────────────────────────────────────────

def _find_json(evidence_dir: Path, stem_glob: str) -> List[Path]:
    """Return all json files matching *stem_glob* directly in evidence_dir."""
    results = []
    for p in sorted(evidence_dir.glob(f"{stem_glob}")):
        if p.is_file() and p.suffix == ".json":
            results.append(p)
    return results


def _find_parsed(evidence_dir: Path, pattern: str) -> List[Path]:
    parsed_dir = evidence_dir / "parsed"
    if not parsed_dir.is_dir():
        return []
    results = []
    for p in sorted(parsed_dir.glob(pattern)):
        if p.is_file():
            results.append(p)
    return results


def _load_parsed_records(files: List[Path]) -> List[Dict]:
    """Unwrap JOCKY envelope and return flat list of records."""
    out = []
    for f in files:
        data = _safe_load(f)
        if not data:
            continue
        if isinstance(data, dict) and "records" in data:
            records = data["records"]
        elif isinstance(data, list):
            records = data
        else:
            continue
        if isinstance(records, list):
            out.extend(records)
    return out


# ─── Section renderers ────────────────────────────────────────────────────────

def _render_summary(evidence_dir: Path, title: str) -> str:
    # Try to load any metadata file
    meta = None
    for name in ("metadata.json", "meta.json", "collection_meta.json"):
        p = evidence_dir / name
        if p.is_file():
            meta = _safe_load(p)
            break

    lines = []
    lines.append(f'<table class="kv-table">')
    lines.append(f'<tr><th>Report Title</th><td>{_esc(title)}</td></tr>')
    lines.append(f'<tr><th>Evidence Directory</th><td>{_esc(str(evidence_dir))}</td></tr>')
    lines.append(f'<tr><th>Generated</th><td>{datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}</td></tr>')

    if meta and isinstance(meta, dict):
        for k, v in meta.items():
            lines.append(f'<tr><th>{_esc(k)}</th><td>{_esc(str(v))}</td></tr>')

    # count evidence files
    json_count = len(list(evidence_dir.glob("*.json")))
    parsed_dir = evidence_dir / "parsed"
    parsed_count = len(list(parsed_dir.glob("*.json"))) if parsed_dir.is_dir() else 0
    lines.append(f'<tr><th>Raw Evidence Files</th><td>{json_count}</td></tr>')
    lines.append(f'<tr><th>Parsed Artifacts</th><td>{parsed_count}</td></tr>')
    lines.append('</table>')
    return _section("1. Summary", "\n".join(lines), "sec-summary")


def _render_procs(evidence_dir: Path) -> str:
    files = _find_json(evidence_dir, "procs*.json") or _find_json(evidence_dir, "processes*.json")
    if not files:
        return _section("2. Processes", _empty("procs.json not found"))

    rows = ""
    for f in files:
        data = _safe_load(f)
        if not data:
            continue
        items = data if isinstance(data, list) else data.get("processes", data.get("data", []))
        for p in (items or []):
            if not isinstance(p, dict):
                continue
            rows += _row(
                p.get("pid", ""), p.get("ppid", ""), p.get("name", ""),
                p.get("path", p.get("image_path", "")),
                p.get("user", p.get("username", "")),
                _fmt_ts(p.get("start_time", "")),
                p.get("cmdline", p.get("command_line", "")),
            )

    if not rows:
        return _section("2. Processes", _empty("No process records found."))

    tbl = _table(["PID", "PPID", "Name", "Path", "User", "Start Time", "Command Line"], rows, "tbl-procs")
    return _section("2. Processes", tbl, "sec-procs")


def _render_connections(evidence_dir: Path) -> str:
    files = _find_json(evidence_dir, "connections*.json") or _find_json(evidence_dir, "sockets*.json")
    if not files:
        return _section("3. Network Connections", _empty("connections.json not found"))

    rows = ""
    for f in files:
        data = _safe_load(f)
        if not data:
            continue
        items = data if isinstance(data, list) else data.get("connections", data.get("data", []))
        for c in (items or []):
            if not isinstance(c, dict):
                continue
            rows += _row(
                c.get("proto", c.get("protocol", "")),
                c.get("local_addr", c.get("local", "")),
                c.get("local_port", ""),
                c.get("remote_addr", c.get("remote", "")),
                c.get("remote_port", ""),
                c.get("state", ""),
                c.get("pid", ""),
                c.get("process", c.get("process_name", "")),
            )

    if not rows:
        return _section("3. Network Connections", _empty("No connection records found."))

    tbl = _table(["Proto", "Local Addr", "L.Port", "Remote Addr", "R.Port", "State", "PID", "Process"], rows, "tbl-conn")
    return _section("3. Network Connections", tbl, "sec-conn")


def _render_services(evidence_dir: Path) -> str:
    files = _find_json(evidence_dir, "services*.json")
    if not files:
        return _section("4. Services", _empty("services.json not found"))

    rows = ""
    for f in files:
        data = _safe_load(f)
        if not data:
            continue
        items = data if isinstance(data, list) else data.get("services", data.get("data", []))
        for s in (items or []):
            if not isinstance(s, dict):
                continue
            rows += _row(
                s.get("name", ""), s.get("display_name", ""),
                s.get("state", s.get("status", "")),
                s.get("start_type", ""),
                s.get("binary_path", s.get("path", "")),
                s.get("pid", ""),
            )

    tbl = _table(["Name", "Display Name", "State", "Start Type", "Binary Path", "PID"], rows, "tbl-svc")
    return _section("4. Services", tbl if rows else _empty("No service records."))


def _render_persistence(evidence_dir: Path) -> str:
    files = _find_json(evidence_dir, "persistence*.json")
    if not files:
        return _section("5. Persistence", _empty("persistence.json not found"))

    rows = ""
    for f in files:
        data = _safe_load(f)
        if not data:
            continue
        items = data if isinstance(data, list) else data.get("persistence", data.get("data", []))
        for p in (items or []):
            if not isinstance(p, dict):
                continue
            rows += _row(
                p.get("type", ""), p.get("name", ""), p.get("value", ""),
                p.get("path", p.get("location", "")),
                _fmt_ts(p.get("ts", p.get("timestamp", ""))),
            )

    tbl = _table(["Type", "Name", "Value", "Path/Location", "Timestamp"], rows, "tbl-persist")
    return _section("5. Persistence", tbl if rows else _empty("No persistence records."))


def _render_usb(evidence_dir: Path) -> str:
    files = (_find_json(evidence_dir, "usb_history*.json")
             or _find_json(evidence_dir, "usb*.json"))
    if not files:
        return _section("6. USB History", _empty("usb_history.json not found"))

    rows = ""
    for f in files:
        data = _safe_load(f)
        if not data:
            continue
        items = data if isinstance(data, list) else data.get("usb", data.get("data", []))
        for u in (items or []):
            if not isinstance(u, dict):
                continue
            rows += _row(
                u.get("device_id", u.get("vid_pid", "")),
                u.get("description", u.get("name", "")),
                u.get("serial", ""),
                _fmt_ts(u.get("first_connected", u.get("first_install", ""))),
                _fmt_ts(u.get("last_connected", "")),
                u.get("drive_letter", ""),
            )

    tbl = _table(["Device ID", "Description", "Serial", "First Connected", "Last Connected", "Drive Letter"], rows, "tbl-usb")
    return _section("6. USB History", tbl if rows else _empty("No USB records."))


def _render_modules(evidence_dir: Path) -> str:
    files = _find_json(evidence_dir, "modules*.json")
    if not files:
        return _section("7. Loaded Modules", _empty("modules*.json not found"))

    rows = ""
    for f in files:
        data = _safe_load(f)
        if not data:
            continue
        items = data if isinstance(data, list) else data.get("modules", data.get("data", []))
        for m in (items or [])[:500]:  # cap at 500 for readability
            if not isinstance(m, dict):
                continue
            rows += _row(
                m.get("name", ""), m.get("path", m.get("image_path", "")),
                m.get("base_addr", m.get("base", "")),
                m.get("size", ""), m.get("pid", ""),
            )

    tbl = _table(["Name", "Path", "Base Addr", "Size", "PID"], rows, "tbl-mod")
    return _section("7. Loaded Modules", tbl if rows else _empty("No module records."))


def _render_dns(evidence_dir: Path) -> str:
    files = _find_json(evidence_dir, "dns_cache*.json")
    if not files:
        return _section("8. DNS Cache", _empty("dns_cache.json not found"))

    rows = ""
    for f in files:
        data = _safe_load(f)
        if not data:
            continue
        items = data if isinstance(data, list) else data.get("entries", data.get("data", []))
        for e in (items or []):
            if not isinstance(e, dict):
                continue
            rows += _row(
                e.get("name", e.get("hostname", "")),
                e.get("type", ""), e.get("data", e.get("record", "")),
                e.get("ttl", ""),
            )

    tbl = _table(["Name", "Type", "Data", "TTL"], rows, "tbl-dns")
    return _section("8. DNS Cache", tbl if rows else _empty("No DNS cache records."))


def _render_arp_routes(evidence_dir: Path) -> str:
    content = ""

    arp_files = _find_json(evidence_dir, "arp*.json")
    if arp_files:
        rows = ""
        for f in arp_files:
            data = _safe_load(f)
            items = data if isinstance(data, list) else (data or {}).get("data", [])
            for e in (items or []):
                if not isinstance(e, dict):
                    continue
                rows += _row(e.get("ip", ""), e.get("mac", ""), e.get("type", ""), e.get("iface", ""))
        content += _table(["IP", "MAC", "Type", "Interface"], rows, "tbl-arp") if rows else _empty("No ARP records.")
    else:
        content += _empty("arp.json not found")

    route_files = _find_json(evidence_dir, "route*.json")
    if route_files:
        rows = ""
        for f in route_files:
            data = _safe_load(f)
            items = data if isinstance(data, list) else (data or {}).get("data", [])
            for e in (items or []):
                if not isinstance(e, dict):
                    continue
                rows += _row(
                    e.get("destination", ""), e.get("netmask", ""), e.get("gateway", ""),
                    e.get("metric", ""), e.get("iface", e.get("interface", "")),
                )
        content += "<h3>Route Table</h3>"
        content += _table(["Destination", "Netmask", "Gateway", "Metric", "Interface"], rows, "tbl-routes") if rows else _empty("No route records.")
    else:
        content += "<h3>Route Table</h3>" + _empty("routes.json not found")

    return _section("9. ARP Cache / Routes", content, "sec-arp")


def _render_typed_urls(evidence_dir: Path) -> str:
    files = _find_json(evidence_dir, "typed_urls*.json")
    if not files:
        return _section("10. Typed URLs", _empty("typed_urls.json not found"))

    rows = ""
    for f in files:
        data = _safe_load(f)
        items = data if isinstance(data, list) else (data or {}).get("urls", data)
        if isinstance(items, dict):
            for url, ts in items.items():
                rows += _row(url, _fmt_ts(ts))
        elif isinstance(items, list):
            for e in items:
                if isinstance(e, dict):
                    rows += _row(e.get("url", e.get("value", "")), _fmt_ts(e.get("ts", "")))
                else:
                    rows += _row(str(e), "")

    tbl = _table(["URL", "Timestamp"], rows, "tbl-typed")
    return _section("10. Typed URLs", tbl if rows else _empty("No typed URL records."))


def _render_scheduled_tasks(evidence_dir: Path) -> str:
    files = _find_json(evidence_dir, "tasks*.json") or _find_json(evidence_dir, "scheduled_tasks*.json")
    if not files:
        return _section("11. Scheduled Tasks", _empty("tasks.json not found"))

    rows = ""
    for f in files:
        data = _safe_load(f)
        items = data if isinstance(data, list) else (data or {}).get("tasks", data.get("data", []))
        for t in (items or []):
            if not isinstance(t, dict):
                continue
            rows += _row(
                t.get("name", ""), t.get("state", t.get("status", "")),
                t.get("last_run", ""), t.get("next_run", ""),
                t.get("action", t.get("command", t.get("exec", ""))),
                t.get("user", ""), t.get("trigger", ""),
            )

    tbl = _table(["Name", "State", "Last Run", "Next Run", "Action", "User", "Trigger"], rows, "tbl-tasks")
    return _section("11. Scheduled Tasks", tbl if rows else _empty("No task records."))


def _render_prefetch_raw(evidence_dir: Path) -> str:
    files = _find_json(evidence_dir, "prefetch*.json")
    if not files:
        return _section("12. Prefetch (raw)", _empty("prefetch.json not found"))

    rows = ""
    for f in files:
        data = _safe_load(f)
        items = data if isinstance(data, list) else (data or {}).get("data", [])
        for e in (items or []):
            if not isinstance(e, dict):
                continue
            rows += _row(
                e.get("name", e.get("executable", "")),
                e.get("run_count", ""),
                _fmt_ts(e.get("last_run", "")),
                e.get("path", ""),
            )

    tbl = _table(["Executable", "Run Count", "Last Run", "Path"], rows, "tbl-pf-raw")
    return _section("12. Prefetch (raw)", tbl if rows else _empty("No prefetch records."))


def _render_suspicious(evidence_dir: Path) -> str:
    files = _find_json(evidence_dir, "suspicious*.json")
    if not files:
        return _section("13. Suspicious Files", _empty("suspicious*.json not found"))

    rows = ""
    for f in files:
        data = _safe_load(f)
        items = data if isinstance(data, list) else (data or {}).get("data", [])
        for e in (items or []):
            if not isinstance(e, dict):
                continue
            rows += _row(
                e.get("path", e.get("file", "")),
                e.get("reason", e.get("flag", "")),
                _fmt_ts(e.get("ts", e.get("modified", ""))),
                e.get("hash", e.get("sha256", "")),
            )

    tbl = _table(["Path", "Reason", "Timestamp", "SHA-256"], rows, "tbl-susp")
    return _section("13. Suspicious Files", tbl if rows else _empty("No suspicious file records."))


# ─── Section 14: Parsed Evidence ─────────────────────────────────────────────

def _render_evtx_parsed(evidence_dir: Path) -> str:
    """14a — EVTX events with filter bar."""
    files = _find_parsed(evidence_dir, "evtx_*_parsed.json")
    records = _load_parsed_records(files)
    if not records:
        return _empty("No parsed EVTX records found.")

    # Build suspicious event IDs set (known high-value IDs)
    _SUSPICIOUS_IDS = {
        "4624", "4625", "4634", "4648", "4688", "4698",
        "4720", "4776", "7045", "2003", "2004",
    }

    rows = ""
    for r in records:
        if not isinstance(r, dict) or "error" in r:
            continue
        eid   = str(r.get("event_id", ""))
        is_hi = eid in _SUSPICIOUS_IDS
        cls   = "suspicious" if is_hi else ""
        rows += _row(
            _fmt_ts(r.get("ts", "")),
            r.get("source_file", r.get("channel", "")),
            eid,
            r.get("level", ""),
            r.get("computer", ""),
            r.get("user_id", ""),
            r.get("process_id", ""),
            r.get("message", r.get("task_category", ""))[:200],
            cls=cls,
        )

    if not rows:
        return _empty("No EVTX records after parsing.")

    # Include filter controls; JS is injected in the page <script> block
    filter_bar = (
        '<div class="filter-bar">'
        '<input id="evtx-filter-eid" placeholder="Event ID (e.g. 4624)" oninput="evtxFilter()">'
        '<input id="evtx-filter-ch"  placeholder="Channel / Source" oninput="evtxFilter()">'
        '<input id="evtx-filter-q"   placeholder="Full-text search" oninput="evtxFilter()">'
        '<label><input type="checkbox" id="evtx-filter-hi" onchange="evtxFilter()"> Suspicious only</label>'
        '</div>\n'
    )
    tbl = _table(
        ["Timestamp", "Channel", "Event ID", "Level", "Computer", "User", "PID", "Message"],
        rows, "tbl-evtx"
    )
    return filter_bar + tbl


def _render_prefetch_parsed(evidence_dir: Path) -> str:
    """14b — Prefetch runs as a horizontal timeline bar."""
    files = _find_parsed(evidence_dir, "prefetch_parsed.json")
    records = _load_parsed_records(files)
    if not records:
        return _empty("No parsed prefetch records found.")

    # Build timeline items — only records that have last_run_times
    items = []
    for r in records:
        if not isinstance(r, dict) or "error" in r:
            continue
        name = r.get("executable_name", r.get("name", "UNKNOWN"))
        run_count = int(r.get("run_count", 0) or 0)
        last_runs = r.get("last_run_times", [])
        if isinstance(last_runs, list) and last_runs:
            latest = max((t for t in last_runs if t), default="")
        else:
            latest = r.get("last_run", "")
        if latest:
            items.append((latest, name, run_count))

    if not items:
        return _empty("No prefetch run timestamps found.")

    # Sort by timestamp descending
    items.sort(key=lambda x: x[0], reverse=True)

    # Table view (timeline bar is JS-rendered)
    rows = ""
    for ts, name, rc in items:
        rows += _row(_fmt_ts(ts), name, rc)

    tbl = _table(["Last Run", "Executable", "Run Count"], rows, "tbl-pf-parsed")

    # Build JSON array for the SVG timeline bar (rendered client-side)
    tl_data = json.dumps([
        {"ts": ts, "name": name, "count": rc}
        for ts, name, rc in items[:50]  # cap at 50 for rendering
    ])
    timeline_div = (
        f'<div id="pf-timeline-container" class="timeline-container">'
        f'<canvas id="pf-timeline-canvas" width="1200" height="180"></canvas>'
        f'</div>\n'
        f'<script>window._jockyPfData = {tl_data};</script>\n'
    )
    return timeline_div + tbl


def _render_browser_parsed(evidence_dir: Path) -> str:
    """14c — Browser history; suspicious rows highlighted red."""
    files = _find_parsed(evidence_dir, "browser_*_parsed.json")
    records = _load_parsed_records(files)
    if not records:
        return _empty("No parsed browser records found.")

    rows = ""
    for r in records:
        if not isinstance(r, dict) or "error" in r:
            continue
        susp = bool(r.get("suspicious", False))
        cls  = "suspicious" if susp else ""
        rows += _row(
            _fmt_ts(r.get("ts", "")),
            r.get("browser", ""),
            r.get("url", "")[:160],
            r.get("title", "")[:100],
            r.get("visit_count", ""),
            _fmt_ts(r.get("last_visit_ts", "")),
            "⚠ YES" if susp else "",
            cls=cls,
        )

    if not rows:
        return _empty("No browser records after parsing.")

    return _table(
        ["Timestamp", "Browser", "URL", "Title", "Visits", "Last Visit", "Suspicious"],
        rows, "tbl-browser"
    )


def _render_registry_parsed(evidence_dir: Path) -> str:
    """14d — Registry artifacts (run keys, USB, userassist)."""
    files = _find_parsed(evidence_dir, "registry_*_parsed.json")
    records = _load_parsed_records(files)
    if not records:
        return _empty("No parsed registry records found.")

    rows = ""
    for r in records:
        if not isinstance(r, dict) or "error" in r:
            continue
        rows += _row(
            r.get("category", r.get("type", "")),
            r.get("hive", ""),
            r.get("key_path", ""),
            r.get("name", ""),
            str(r.get("value", ""))[:200],
            _fmt_ts(r.get("ts", "")),
        )

    if not rows:
        return _empty("No registry records after parsing.")

    return _table(["Category", "Hive", "Key Path", "Name", "Value", "Timestamp"], rows, "tbl-reg")


def _render_lnk_parsed(evidence_dir: Path) -> str:
    """14e — LNK shell link files."""
    files = _find_parsed(evidence_dir, "lnk_parsed.json")
    records = _load_parsed_records(files)
    if not records:
        return _empty("No parsed LNK records found.")

    rows = ""
    for r in records:
        if not isinstance(r, dict) or "error" in r:
            continue
        susp = bool(r.get("suspicious", False))
        cls  = "suspicious" if susp else ""
        rows += _row(
            r.get("source_file", ""),
            r.get("target_path", r.get("local_base_path", "")),
            r.get("machine_id", ""),
            r.get("mac_address", ""),
            _fmt_ts(r.get("target_mtime", "")),
            "⚠ YES" if susp else "",
            cls=cls,
        )

    if not rows:
        return _empty("No LNK records after parsing.")

    return _table(["LNK File", "Target Path", "Machine ID", "MAC Address", "Target Mtime", "Suspicious"], rows, "tbl-lnk")


def _render_shimcache_parsed(evidence_dir: Path) -> str:
    """14f — AppCompatCache (Shimcache)."""
    files = _find_parsed(evidence_dir, "shimcache_parsed.json")
    records = _load_parsed_records(files)
    if not records:
        return _empty("No parsed Shimcache records found.")

    rows = ""
    for r in records:
        if not isinstance(r, dict) or "error" in r:
            continue
        rows += _row(
            r.get("index", ""),
            r.get("path", ""),
            _fmt_ts(r.get("last_modified", r.get("ts", ""))),
            "Yes" if r.get("executed") else "No" if r.get("executed") is False else "—",
        )

    if not rows:
        return _empty("No shimcache records after parsing.")

    return _table(["Index", "Path", "Last Modified", "Executed"], rows, "tbl-shim")


def _render_amcache_parsed(evidence_dir: Path) -> str:
    """14g — AmCache application entries."""
    files = _find_parsed(evidence_dir, "amcache_parsed.json")
    records = _load_parsed_records(files)
    if not records:
        return _empty("No parsed AmCache records found.")

    rows = ""
    for r in records:
        if not isinstance(r, dict) or "error" in r:
            continue
        rows += _row(
            r.get("path", r.get("full_path", "")),
            r.get("sha1", r.get("file_id", "")),
            r.get("publisher", ""),
            r.get("product_name", ""),
            r.get("product_version", ""),
            _fmt_ts(r.get("link_date", r.get("ts", ""))),
        )

    if not rows:
        return _empty("No AmCache records after parsing.")

    return _table(["Path", "SHA-1", "Publisher", "Product", "Version", "Link Date"], rows, "tbl-amc")


def _render_srum_parsed(evidence_dir: Path) -> str:
    """14h — SRUM network + app resource usage."""
    files = _find_parsed(evidence_dir, "srum_*_parsed.json")
    records = _load_parsed_records(files)
    if not records:
        return _empty("No parsed SRUM records found.")

    rows = ""
    for r in records:
        if not isinstance(r, dict) or "error" in r:
            continue
        rows += _row(
            _fmt_ts(r.get("ts", "")),
            r.get("app_id", r.get("app", "")),
            r.get("user_id", ""),
            r.get("bytes_sent", ""),
            r.get("bytes_recv", r.get("bytes_received", "")),
            r.get("face_type", r.get("iface", "")),
            r.get("table", ""),
        )

    if not rows:
        return _empty("No SRUM records after parsing.")

    return _table(["Timestamp", "App ID", "User", "Bytes Sent", "Bytes Recv", "Interface", "Table"], rows, "tbl-srum")


def _render_timeline_parsed(evidence_dir: Path) -> str:
    """14i — Windows Activity Timeline (ActivitiesCache.db)."""
    files = _find_parsed(evidence_dir, "timeline_parsed.json")
    records = _load_parsed_records(files)
    if not records:
        return _empty("No parsed Activity Timeline records found.")

    rows = ""
    for r in records:
        if not isinstance(r, dict) or "error" in r:
            continue
        rows += _row(
            _fmt_ts(r.get("ts", r.get("start_ts", ""))),
            _fmt_ts(r.get("end_ts", "")),
            r.get("app_id", ""),
            r.get("display_text", r.get("content_uri", ""))[:140],
            r.get("app_name", ""),
            r.get("duration_secs", ""),
            r.get("platform_device", ""),
        )

    if not rows:
        return _empty("No timeline records after parsing.")

    return _table(
        ["Start", "End", "App ID", "Document / URI", "App Name", "Duration (s)", "Device"],
        rows, "tbl-timeline"
    )


def _render_i30_parsed(evidence_dir: Path) -> str:
    """14j — $I30 NTFS index entries including deleted-file slack."""
    files = _find_parsed(evidence_dir, "i30_parsed.json")
    records = _load_parsed_records(files)
    if not records:
        return _empty("No parsed $I30 records found.")

    rows = ""
    for r in records:
        if not isinstance(r, dict) or "error" in r:
            continue
        is_del  = bool(r.get("deleted", False))
        is_slk  = bool(r.get("from_slack", False))
        cls = ""
        if is_del or is_slk:
            cls = "suspicious"
        rows += _row(
            r.get("filename", ""),
            _fmt_ts(r.get("mft_modified", r.get("ts", ""))),
            _fmt_ts(r.get("created", "")),
            _fmt_ts(r.get("accessed", "")),
            r.get("real_size", ""),
            r.get("file_attrs", ""),
            "⚠ DELETED" if is_del else ("SLACK" if is_slk else "active"),
            r.get("source_file", ""),
            cls=cls,
        )

    if not rows:
        return _empty("No $I30 records after parsing.")

    return _table(
        ["Filename", "MFT Modified", "Created", "Accessed", "Size", "Attrs", "Status", "Source"],
        rows, "tbl-i30"
    )


def _render_parsed_evidence(evidence_dir: Path) -> str:
    """Section 14 — full Parsed Evidence section."""
    content = ""

    content += "<h3>14a. EVTX Events</h3>"
    content += _render_evtx_parsed(evidence_dir)

    content += "<h3>14b. Prefetch Timeline</h3>"
    content += _render_prefetch_parsed(evidence_dir)

    content += "<h3>14c. Browser History</h3>"
    content += _render_browser_parsed(evidence_dir)

    content += "<h3>14d. Registry Artifacts</h3>"
    content += _render_registry_parsed(evidence_dir)

    content += "<h3>14e. LNK Shell Links</h3>"
    content += _render_lnk_parsed(evidence_dir)

    content += "<h3>14f. AppCompatCache (Shimcache)</h3>"
    content += _render_shimcache_parsed(evidence_dir)

    content += "<h3>14g. AmCache</h3>"
    content += _render_amcache_parsed(evidence_dir)

    content += "<h3>14h. SRUM Usage</h3>"
    content += _render_srum_parsed(evidence_dir)

    content += "<h3>14i. Activity Timeline</h3>"
    content += _render_timeline_parsed(evidence_dir)

    content += "<h3>14j. $I30 Deleted Files</h3>"
    content += _render_i30_parsed(evidence_dir)

    return _section("14. Parsed Evidence", content, "sec-parsed")


# ─── CSS ──────────────────────────────────────────────────────────────────────

_CSS = """
/* ── JOCKY report stylesheet ── */
:root {
    --bg:       #0d0d0d;
    --bg2:      #141414;
    --bg3:      #1c1c1c;
    --border:   #2a2a2a;
    --text:     #d8d8d8;
    --muted:    #7a7a7a;
    --accent:   #00e5ff;
    --accent2:  #b967ff;
    --warn:     #ff4646;
    --warn-bg:  #2a0a0a;
    --hi-bg:    #0a1e2a;
    --th-bg:    #1e1e1e;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 13px;
    line-height: 1.5;
}

/* ── top bar ── */
.topbar {
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
    padding: 14px 24px;
    display: flex;
    align-items: center;
    gap: 12px;
    position: sticky;
    top: 0;
    z-index: 100;
}
.topbar .logo {
    font-size: 18px;
    font-weight: 700;
    letter-spacing: 3px;
    color: var(--accent);
}
.topbar .subtitle {
    color: var(--muted);
    font-size: 12px;
}
.topbar .ts {
    margin-left: auto;
    color: var(--muted);
    font-size: 11px;
}

/* ── layout ── */
.layout {
    display: flex;
    min-height: calc(100vh - 46px);
}

/* ── sidebar nav ── */
.sidebar {
    width: 220px;
    min-width: 220px;
    background: var(--bg2);
    border-right: 1px solid var(--border);
    padding: 16px 0;
    position: sticky;
    top: 46px;
    height: calc(100vh - 46px);
    overflow-y: auto;
}
.sidebar a {
    display: block;
    padding: 6px 18px;
    color: var(--muted);
    text-decoration: none;
    font-size: 12px;
    border-left: 3px solid transparent;
    transition: color .15s, border-color .15s;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}
.sidebar a:hover, .sidebar a.active {
    color: var(--accent);
    border-left-color: var(--accent);
    background: var(--hi-bg);
}
.sidebar .nav-group {
    font-size: 10px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 1.5px;
    padding: 12px 18px 4px;
}

/* ── main content ── */
.content {
    flex: 1;
    padding: 24px 32px;
    overflow-x: hidden;
}

/* ── sections ── */
section {
    margin-bottom: 48px;
}
section h2 {
    font-size: 15px;
    color: var(--accent);
    border-bottom: 1px solid var(--border);
    padding-bottom: 8px;
    margin-bottom: 16px;
    letter-spacing: 1px;
}
section h3 {
    font-size: 13px;
    color: var(--accent2);
    margin: 24px 0 10px;
    letter-spacing: .5px;
}

/* ── tables ── */
.tbl-wrap {
    overflow-x: auto;
    border: 1px solid var(--border);
    border-radius: 4px;
}
table {
    width: 100%;
    border-collapse: collapse;
}
thead {
    background: var(--th-bg);
    position: sticky;
    top: 0;
}
th {
    padding: 8px 10px;
    text-align: left;
    font-size: 11px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: .8px;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
}
td {
    padding: 6px 10px;
    border-bottom: 1px solid var(--border);
    font-size: 12px;
    word-break: break-word;
    max-width: 320px;
    vertical-align: top;
}
tr:last-child td { border-bottom: none; }
tr:nth-child(even) { background: var(--bg3); }
tr:hover { background: var(--hi-bg); }

/* suspicious rows */
tr.suspicious td {
    color: var(--warn);
    background: var(--warn-bg);
}
tr.suspicious:hover td {
    background: #3a1010;
}

/* key-value table (summary) */
.kv-table { width: 100%; max-width: 640px; }
.kv-table th {
    width: 200px;
    color: var(--muted);
    font-weight: normal;
    background: none;
    text-transform: none;
    letter-spacing: 0;
    font-size: 12px;
}
.kv-table td { font-size: 12px; color: var(--text); }

/* ── filter bar (EVTX) ── */
.filter-bar {
    display: flex;
    gap: 10px;
    margin-bottom: 12px;
    align-items: center;
    flex-wrap: wrap;
}
.filter-bar input[type=text],
.filter-bar input:not([type=checkbox]) {
    background: var(--bg3);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 5px 10px;
    border-radius: 3px;
    font-size: 12px;
    font-family: inherit;
    min-width: 160px;
}
.filter-bar input:focus { outline: 1px solid var(--accent); }
.filter-bar label {
    color: var(--muted);
    font-size: 12px;
    display: flex;
    align-items: center;
    gap: 5px;
}

/* ── timeline canvas ── */
.timeline-container {
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 8px;
    margin-bottom: 16px;
    overflow-x: auto;
}
canvas { display: block; }

/* ── misc ── */
.empty {
    color: var(--muted);
    font-style: italic;
    padding: 8px 0;
}
"""

# ─── JavaScript ───────────────────────────────────────────────────────────────

_JS = r"""
/* ── EVTX filter ── */
function evtxFilter() {
    const eidInput = document.getElementById("evtx-filter-eid");
    const chInput  = document.getElementById("evtx-filter-ch");
    const qInput   = document.getElementById("evtx-filter-q");
    const hiCheck  = document.getElementById("evtx-filter-hi");
    if (!eidInput) return;

    const eid   = eidInput.value.trim().toLowerCase();
    const ch    = chInput.value.trim().toLowerCase();
    const q     = qInput.value.trim().toLowerCase();
    const hiOnly = hiCheck.checked;

    const tbl  = document.getElementById("tbl-evtx");
    if (!tbl) return;
    const rows = tbl.querySelectorAll("tbody tr");
    rows.forEach(function(row) {
        const cells = row.querySelectorAll("td");
        if (cells.length < 8) return;
        const rowEid = cells[2].textContent.toLowerCase();
        const rowCh  = cells[1].textContent.toLowerCase();
        const rowAll = row.textContent.toLowerCase();
        const isSusp = row.classList.contains("suspicious");

        let show = true;
        if (eid   && rowEid.indexOf(eid) === -1) show = false;
        if (ch    && rowCh.indexOf(ch)   === -1) show = false;
        if (q     && rowAll.indexOf(q)   === -1) show = false;
        if (hiOnly && !isSusp)                   show = false;
        row.style.display = show ? "" : "none";
    });
}

/* ── Prefetch timeline ── */
(function renderPfTimeline() {
    var data = window._jockyPfData;
    if (!data || data.length === 0) return;
    var canvas = document.getElementById("pf-timeline-canvas");
    if (!canvas) return;

    // Parse timestamps to Date objects; filter valid
    var items = data.map(function(d) {
        return { ts: new Date(d.ts), name: d.name, count: d.count };
    }).filter(function(d) { return !isNaN(d.ts.getTime()); });

    if (items.length === 0) return;
    items.sort(function(a, b) { return a.ts - b.ts; });

    var minTs = items[0].ts.getTime();
    var maxTs = items[items.length - 1].ts.getTime();
    var span  = maxTs - minTs || 1;

    var ctx    = canvas.getContext("2d");
    var W      = canvas.width;
    var H      = canvas.height;
    var padL   = 8, padR = 8, padT = 30, padB = 40;
    var trackH = (H - padT - padB);
    var laneH  = Math.max(14, Math.min(22, trackH));

    ctx.clearRect(0, 0, W, H);

    /* background */
    ctx.fillStyle = "#141414";
    ctx.fillRect(0, 0, W, H);

    /* title */
    ctx.fillStyle = "#7a7a7a";
    ctx.font      = "11px Consolas, monospace";
    ctx.fillText("Prefetch Execution Timeline (" + items.length + " entries)", padL, 16);

    /* axis */
    ctx.strokeStyle = "#2a2a2a";
    ctx.lineWidth   = 1;
    ctx.beginPath();
    ctx.moveTo(padL, H - padB);
    ctx.lineTo(W - padR, H - padB);
    ctx.stroke();

    /* tick labels */
    var tickCount = 6;
    for (var t = 0; t <= tickCount; t++) {
        var x = padL + (W - padL - padR) * t / tickCount;
        var ts = new Date(minTs + span * t / tickCount);
        var label = ts.toISOString().slice(0, 16).replace("T", " ");
        ctx.fillStyle = "#555";
        ctx.font      = "9px Consolas, monospace";
        ctx.save();
        ctx.translate(x, H - padB + 4);
        ctx.rotate(-Math.PI / 6);
        ctx.fillText(label, 0, 0);
        ctx.restore();
    }

    /* items */
    var palette = ["#00e5ff", "#b967ff", "#00ff88", "#ff9f00", "#ff4646", "#e0e0e0"];
    items.forEach(function(d, i) {
        var x   = padL + (W - padL - padR) * (d.ts.getTime() - minTs) / span;
        var lane = i % Math.max(1, Math.floor(trackH / laneH));
        var y   = padT + lane * laneH;
        var col = palette[i % palette.length];

        /* stem */
        ctx.strokeStyle = col;
        ctx.globalAlpha = 0.35;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(x, H - padB);
        ctx.lineTo(x, y + laneH / 2);
        ctx.stroke();
        ctx.globalAlpha = 1;

        /* dot */
        ctx.fillStyle = col;
        ctx.beginPath();
        ctx.arc(x, y + laneH / 2, 3, 0, Math.PI * 2);
        ctx.fill();

        /* label */
        ctx.fillStyle = col;
        ctx.font = "9px Consolas, monospace";
        var label = d.name.split("\\").pop();
        if (label.length > 18) label = label.slice(0, 17) + "…";
        ctx.fillText(label, x + 5, y + laneH / 2 + 3);
    });
})();

/* ── sidebar active highlight on scroll ── */
(function sidebarScroll() {
    var sections = document.querySelectorAll("section[id]");
    var links    = document.querySelectorAll(".sidebar a[href^='#']");
    window.addEventListener("scroll", function() {
        var cur = "";
        sections.forEach(function(s) {
            if (s.getBoundingClientRect().top <= 80) cur = s.id;
        });
        links.forEach(function(a) {
            a.classList.toggle("active", a.getAttribute("href") === "#" + cur);
        });
    }, {passive: true});
})();
"""

# ─── Sidebar nav ─────────────────────────────────────────────────────────────

_NAV_LINKS = [
    ("#sec-summary",  "1. Summary"),
    ("#sec-procs",    "2. Processes"),
    ("#sec-conn",     "3. Connections"),
    ("",              "4. Services"),
    ("",              "5. Persistence"),
    ("",              "6. USB History"),
    ("",              "7. Modules"),
    ("",              "8. DNS Cache"),
    ("#sec-arp",      "9. ARP / Routes"),
    ("",              "10. Typed URLs"),
    ("",              "11. Tasks"),
    ("",              "12. Prefetch Raw"),
    ("",              "13. Suspicious"),
    ("#sec-parsed",   "── Parsed Evidence ──"),
    ("#sec-parsed",   "14a. EVTX Events"),
    ("#sec-parsed",   "14b. Prefetch Timeline"),
    ("#sec-parsed",   "14c. Browser History"),
    ("#sec-parsed",   "14d. Registry"),
    ("#sec-parsed",   "14e. LNK Files"),
    ("#sec-parsed",   "14f. Shimcache"),
    ("#sec-parsed",   "14g. AmCache"),
    ("#sec-parsed",   "14h. SRUM"),
    ("#sec-parsed",   "14i. Activity Timeline"),
    ("#sec-parsed",   "14j. $I30 Deleted"),
]


def _build_sidebar() -> str:
    links = ""
    for href, label in _NAV_LINKS:
        if not href:
            links += f'<a style="color:#4a4a4a;pointer-events:none">{_esc(label)}</a>\n'
        else:
            links += f'<a href="{_esc(href)}">{_esc(label)}</a>\n'
    return f'<nav class="sidebar">{links}</nav>'


# ─── Main builder ─────────────────────────────────────────────────────────────

def build_report(evidence_dir: Path, title: str) -> str:
    ev = evidence_dir

    sections = (
        _render_summary(ev, title)
        + _render_procs(ev)
        + _render_connections(ev)
        + _render_services(ev)
        + _render_persistence(ev)
        + _render_usb(ev)
        + _render_modules(ev)
        + _render_dns(ev)
        + _render_arp_routes(ev)
        + _render_typed_urls(ev)
        + _render_scheduled_tasks(ev)
        + _render_prefetch_raw(ev)
        + _render_suspicious(ev)
        + _render_parsed_evidence(ev)
    )

    sidebar = _build_sidebar()
    ts_now  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)} — JOCKY Report</title>
<style>{_CSS}</style>
</head>
<body>
<div class="topbar">
  <span class="logo">JOCKY</span>
  <span class="subtitle">Forensic Intelligence Platform — Evidence Report</span>
  <span class="ts">Generated {_esc(ts_now)}</span>
</div>
<div class="layout">
{sidebar}
<main class="content">
{sections}
</main>
</div>
<script>{_JS}</script>
</body>
</html>
"""
    return html


# ─── CLI entry point ──────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="JOCKY Report Generator — produce a self-contained HTML forensic report."
    )
    ap.add_argument(
        "--evidence-dir",
        required=True,
        metavar="DIR",
        help="Path to a JOCKY evidence directory (contains *.json + parsed/ subdir).",
    )
    ap.add_argument(
        "--out",
        default="",
        metavar="FILE",
        help="Output HTML file path.  Default: <evidence-dir>/report_<ts>.html",
    )
    ap.add_argument(
        "--title",
        default="",
        metavar="TITLE",
        help="Report title (e.g. 'NTRO Case 2026-001').  Default: auto from dir name.",
    )
    args = ap.parse_args()

    evidence_dir = Path(args.evidence_dir).resolve()
    if not evidence_dir.is_dir():
        print(f"[ERROR] evidence-dir not found: {evidence_dir}", file=sys.stderr)
        sys.exit(1)

    title = args.title or f"JOCKY Report — {evidence_dir.name}"

    ts_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = Path(args.out) if args.out else (evidence_dir / f"report_{ts_str}.html")

    print(f"[*] Building report from: {evidence_dir}")
    html = build_report(evidence_dir, title)

    out_path.write_text(html, encoding="utf-8")
    print(f"[+] Report written: {out_path}  ({len(html):,} bytes)")


if __name__ == "__main__":
    main()
