"""
JOCKY EVTX Parser — parses Windows Event Log (.evtx) files.

Deps: python-evtx (pip install python-evtx)
      Falls back to lxml-based XML parsing if python-evtx absent.

Output: evidence/<ts>/parsed/<stem>_parsed.json per EVTX file.
"""

import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime, timezone

from parsing._utils import (
    make_envelope, write_envelope, parsed_output_path, sha256_file
)

# ─── Suspicious Event IDs ────────────────────────────────────────────────────
_SUSPICIOUS_IDS = {
    4624, 4625, 4634, 4648, 4688, 4698, 4720, 4776, 7045, 2003, 2004,
}

# ─── XML namespace used in EVTX ──────────────────────────────────────────────
_NS_EVT  = "http://schemas.microsoft.com/win/2004/08/events/event"
_NS_EVTD = "http://schemas.microsoft.com/win/2004/08/events/event"


def _parse_xml_event(xml_str: str) -> dict:
    """Parse a single EVTX event XML string into a flat dict."""
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    ns = {"e": _NS_EVT}

    def _txt(elem):
        return elem.text.strip() if elem is not None and elem.text else ""

    # System block
    sys_el    = root.find("e:System", ns)
    if sys_el is None:
        # Try without namespace
        sys_el = root.find("System")
        if sys_el is None:
            return None

    def _sfind(tag):
        r = sys_el.find(f"e:{tag}", ns)
        if r is None:
            r = sys_el.find(tag)
        return r

    event_id_el  = _sfind("EventID")
    event_id     = int(_txt(event_id_el)) if event_id_el is not None else -1

    time_el      = _sfind("TimeCreated")
    ts           = ""
    if time_el is not None:
        ts = time_el.get("SystemTime", "")
        if ts and not ts.endswith("+00:00") and not ts.endswith("Z"):
            ts = ts + "Z"

    channel_el   = _sfind("Channel")
    computer_el  = _sfind("Computer")
    proc_el      = _sfind("Execution")
    security_el  = _sfind("Security")

    proc_id   = proc_el.get("ProcessID", "")   if proc_el   is not None else ""
    thread_id = proc_el.get("ThreadID",  "")   if proc_el   is not None else ""
    user_id   = security_el.get("UserID", "")  if security_el is not None else ""

    # EventData block
    event_data = {}
    ed_el = root.find("e:EventData", ns)
    if ed_el is None:
        ed_el = root.find("EventData")
    if ed_el is not None:
        for data_el in ed_el:
            name = data_el.get("Name", data_el.tag.split("}")[-1])
            val  = _txt(data_el)
            event_data[name] = val

    # UserData block (for events that use it instead of EventData)
    ud_el = root.find("e:UserData", ns)
    if ud_el is None:
        ud_el = root.find("UserData")
    if ud_el is not None:
        for child in ud_el.iter():
            tag = child.tag.split("}")[-1]
            if tag and child.text and child.text.strip():
                event_data.setdefault(tag, child.text.strip())

    record = {
        "ts":           ts,
        "event_id":     event_id,
        "channel":      _txt(channel_el),
        "computer":     _txt(computer_el),
        "process_id":   proc_id,
        "thread_id":    thread_id,
        "user_id":      user_id,
        "event_data":   event_data,
        "suspicious":   event_id in _SUSPICIOUS_IDS,
    }
    return record


def _parse_evtx_python_evtx(path: Path) -> list:
    """Use python-evtx library to extract records."""
    import Evtx.Evtx as evtx
    import Evtx.Views as evtx_views

    records = []
    with evtx.Evtx(str(path)) as log:
        for record in log.records():
            try:
                xml_str = record.xml()
                rec = _parse_xml_event(xml_str)
                if rec:
                    records.append(rec)
            except Exception:
                pass
    return records


def _parse_evtx_raw(path: Path) -> list:
    """
    Minimal fallback EVTX parser — reads raw XML chunks from the binary file
    without python-evtx. EVTX records are stored as UTF-16LE XML fragments
    prefixed by the ElfChnk signature; we extract them via regex.
    This is a best-effort approach for when python-evtx is unavailable.
    """
    records = []
    try:
        data = open(path, "rb").read()
    except OSError:
        return records

    # Each EVTX chunk starts with b"ElfChnk\x00"
    # Individual records start with b"\x2a\x2a\x00\x00" (record magic 0x00002A2A)
    # After the magic: 4 bytes size, 8 bytes record number, 8 bytes timestamp
    # Then the XML payload (UTF-16LE, null-terminated)

    RECORD_MAGIC = b"\x2a\x2a\x00\x00"
    pos = 0
    while True:
        idx = data.find(RECORD_MAGIC, pos)
        if idx == -1:
            break
        # Offsets within record header (little-endian):
        # 0x00: magic (4)
        # 0x04: total record length (4)
        # 0x08: record number (8)
        # 0x10: written timestamp FILETIME (8)
        # 0x18: XML data starts
        try:
            rec_len   = int.from_bytes(data[idx+4:idx+8],   "little")
            # record number = data[idx+8:idx+16]
            ft_raw    = int.from_bytes(data[idx+16:idx+24], "little")

            xml_start = idx + 24
            xml_end   = idx + rec_len - 4   # last 4 bytes = checksum
            if xml_end <= xml_start or xml_end > len(data):
                pos = idx + 4
                continue

            xml_raw = data[xml_start:xml_end]
            # Try UTF-16-LE first, then UTF-8
            try:
                xml_str = xml_raw.decode("utf-16-le").strip("\x00")
            except Exception:
                try:
                    xml_str = xml_raw.decode("utf-8", errors="replace").strip("\x00")
                except Exception:
                    pos = idx + 4
                    continue

            # Trim to just the <Event> element
            ev_match = re.search(r"<Event[\s>]", xml_str)
            if ev_match:
                xml_str = xml_str[ev_match.start():]
                # Close tag
                end_match = xml_str.find("</Event>")
                if end_match != -1:
                    xml_str = xml_str[:end_match + 8]

            rec = _parse_xml_event(xml_str)
            if rec:
                # Override ts with FILETIME if no timestamp was parsed from XML
                if not rec["ts"] and ft_raw > 0:
                    from parsing._utils import filetime_to_iso
                    rec["ts"] = filetime_to_iso(ft_raw)
                records.append(rec)
        except Exception:
            pass

        pos = idx + max(4, rec_len if 0 < rec_len < 0x100000 else 4)

    return records


def parse_evtx_file(evtx_path: Path) -> list:
    """Parse a single .evtx file, return list of record dicts."""
    try:
        import Evtx.Evtx  # noqa: F401
        return _parse_evtx_python_evtx(evtx_path)
    except ImportError:
        pass
    return _parse_evtx_raw(evtx_path)


def run(evidence_dir: Path) -> dict:
    """
    Main entry point called by parser_runner.
    Parses all .evtx files in evidence_dir/evtx/ and writes JSON output.
    Returns summary dict with record_count and _output_file.
    """
    evidence_dir = Path(evidence_dir)
    evtx_dir     = evidence_dir / "evtx"

    if not evtx_dir.is_dir():
        return {"record_count": 0, "_output_file": "", "_status": "no_evtx_dir"}

    evtx_files = list(evtx_dir.glob("*.evtx")) + list(evtx_dir.glob("*.EVTX"))
    if not evtx_files:
        return {"record_count": 0, "_output_file": "", "_status": "no_evtx_files"}

    total_records = 0
    output_files  = []

    for evtx_path in sorted(evtx_files):
        stem      = evtx_path.stem.lower().replace(" ", "_")
        artifact  = f"evtx_{stem}"
        records   = parse_evtx_file(evtx_path)

        envelope  = make_envelope(
            artifact     = artifact,
            parser       = "evtx_parser",
            source_file  = evtx_path,
            records      = records,
            evidence_dir = evidence_dir,
        )

        out_path = parsed_output_path(evidence_dir, artifact)
        write_envelope(envelope, out_path)

        total_records += len(records)
        output_files.append(str(out_path))

    return {
        "record_count":  total_records,
        "_output_file":  output_files[0] if output_files else "",
        "_output_files": output_files,
        "_status":       "ok",
    }


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="JOCKY EVTX Parser")
    ap.add_argument("--evidence-dir", required=True)
    args = ap.parse_args()
    result = run(Path(args.evidence_dir))
    print(json.dumps(result, indent=2))
