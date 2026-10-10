"""
JOCKY AmCache Parser — parses AmCache.hve registry hive.

Extracts InventoryApplicationFile entries:
  - SHA1 hash of first 31.5KB of PE
  - Full path, file size, link date, language ID, publisher, product name
  - Every PE that has run has an entry here (execution evidence)

Requires regipy (pip install regipy).
Falls back to minimal raw string scan if unavailable.

AmCache hive location: HKLM C:\\Windows\\appcompat\\Programs\\Amcache.hve
Collected by JOCKY_acquire_amcache into evidence/<ts>/hives/Amcache.hve
"""

import json
import struct
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

from parsing._utils import (
    make_envelope, write_envelope, parsed_output_path, filetime_to_iso
)

# ─── InventoryApplicationFile value names ────────────────────────────────────
_IAF_FIELD_MAP = {
    "FileId":              "sha1",           # "0000" + 40 hex chars
    "LowerCaseLongPath":   "path",
    "Name":                "name",
    "Size":                "file_size",
    "LinkDate":            "link_date",
    "LanguageCode":        "language_id",
    "Publisher":           "publisher",
    "ProductName":         "product_name",
    "ProductVersion":      "product_version",
    "FileVersion":         "file_version",
    "BinaryType":          "binary_type",
    "IsPeFile":            "is_pe",
    "IsOsComponent":       "is_os_component",
    "ProgramId":           "program_id",
    "PEMachineType":       "machine_type",
}


def _parse_amcache_regipy(path: Path) -> list:
    """Use regipy to extract InventoryApplicationFile entries."""
    from regipy.registry import RegistryHive

    reg     = RegistryHive(str(path))
    records = []

    # AmCache hive root\Root\InventoryApplicationFile
    iaf_paths = [
        "Root\\InventoryApplicationFile",
        "InventoryApplicationFile",
    ]

    iaf_key = None
    for p in iaf_paths:
        try:
            iaf_key = reg.get_key(p)
            if iaf_key:
                break
        except Exception:
            pass

    # Older AmCache format: Root\File\<volume>\<hash>
    if iaf_key is None:
        old_paths = ["Root\\File", "File"]
        for p in old_paths:
            try:
                file_key = reg.get_key(p)
                if file_key:
                    for vol_key in file_key.iter_subkeys():
                        for entry_key in vol_key.iter_subkeys():
                            rec = _parse_old_amcache_entry(entry_key)
                            if rec:
                                records.append(rec)
                    return records
            except Exception:
                pass
        return records

    # New format (Win10+): iterate InventoryApplicationFile subkeys
    try:
        for entry_key in iaf_key.iter_subkeys():
            rec = _parse_iaf_entry(entry_key)
            if rec:
                records.append(rec)
    except Exception:
        pass

    return records


def _parse_iaf_entry(entry_key) -> dict:
    """Parse one InventoryApplicationFile subkey into a record dict."""
    vals = {}
    try:
        for v in entry_key.iter_values():
            name = v.name
            try:
                vals[name] = str(v.value)
            except Exception:
                vals[name] = ""
    except Exception:
        return None

    # Get last-written timestamp from key header
    ts = ""
    try:
        ft = entry_key.header.last_modified
        if isinstance(ft, datetime):
            if ft.tzinfo is None:
                ft = ft.replace(tzinfo=timezone.utc)
            ts = ft.isoformat()
        elif isinstance(ft, int):
            ts = filetime_to_iso(ft)
    except Exception:
        pass

    rec = {"ts": ts, "key_name": entry_key.name}

    # Map known value names
    for amcache_name, field_name in _IAF_FIELD_MAP.items():
        val = vals.get(amcache_name, "")
        if field_name == "sha1" and val.startswith("0000"):
            val = val[4:]  # strip "0000" prefix
        rec[field_name] = val

    # Parse link_date from hex FILETIME if stored as integer
    if rec.get("link_date"):
        try:
            ft_int = int(rec["link_date"], 16)
            rec["link_date"] = filetime_to_iso(ft_int)
        except Exception:
            pass

    return rec


def _parse_old_amcache_entry(entry_key) -> dict:
    """Parse an older-format AmCache entry (Win7/8 style)."""
    vals = {}
    try:
        for v in entry_key.iter_values():
            try:
                vals[v.name] = str(v.value)
            except Exception:
                vals[v.name] = ""
    except Exception:
        return None

    ts = ""
    try:
        ft = entry_key.header.last_modified
        if isinstance(ft, datetime):
            if ft.tzinfo is None:
                ft = ft.replace(tzinfo=timezone.utc)
            ts = ft.isoformat()
        elif isinstance(ft, int):
            ts = filetime_to_iso(ft)
    except Exception:
        pass

    # Older format value numbers:
    # 0  = product name, 1 = company, 3 = language, 5 = file version
    # 6  = link date (hex FILETIME), 7 = bin file version, 11 = file size
    # 15 = PE machine type, 100 = path, 101 = SHA1 (0000 + hash)
    sha1 = vals.get("101", "")
    if sha1.startswith("0000"):
        sha1 = sha1[4:]

    link_date = vals.get("6", "")
    if link_date:
        try:
            link_date = filetime_to_iso(int(link_date, 16))
        except Exception:
            pass

    return {
        "ts":            ts,
        "key_name":      entry_key.name,
        "sha1":          sha1,
        "path":          vals.get("100", ""),
        "product_name":  vals.get("0", ""),
        "publisher":     vals.get("1", ""),
        "language_id":   vals.get("3", ""),
        "file_version":  vals.get("5", ""),
        "link_date":     link_date,
        "file_size":     vals.get("11", ""),
        "machine_type":  vals.get("15", ""),
    }


def _parse_amcache_raw(path: Path) -> list:
    """Minimal fallback: scan hive binary for SHA1-like strings."""
    records = []
    try:
        data = open(path, "rb").read()
    except OSError:
        return records

    import re
    # Look for 40-hex-char strings preceded by "0000" (FileId pattern)
    pattern = re.compile(rb"0000([0-9a-fA-F]{40})")
    for m in pattern.finditer(data):
        records.append({
            "ts":   "",
            "sha1": m.group(1).decode("ascii"),
            "path": "",
            "note": "raw_scan",
        })

    return records[:1000]


def run(evidence_dir: Path) -> dict:
    evidence_dir = Path(evidence_dir)
    hives_dir    = evidence_dir / "hives"

    # Look for Amcache.hve / amcache.hve
    amcache_path = None
    for candidate in ("Amcache.hve", "amcache.hve", "Amcache.HVE"):
        p = hives_dir / candidate
        if p.is_file():
            amcache_path = p
            break

    if amcache_path is None:
        return {"record_count": 0, "_output_file": "", "_status": "amcache_not_found"}

    try:
        import regipy  # noqa: F401
        records = _parse_amcache_regipy(amcache_path)
    except ImportError:
        records = _parse_amcache_raw(amcache_path)
    except Exception as e:
        records = [{"ts": "", "error": str(e)}]

    envelope = make_envelope(
        artifact     = "amcache",
        parser       = "amcache_parser",
        source_file  = amcache_path,
        records      = records,
        evidence_dir = evidence_dir,
    )
    out_path = parsed_output_path(evidence_dir, "amcache")
    write_envelope(envelope, out_path)

    return {
        "record_count": len(records),
        "_output_file": str(out_path),
        "_status":      "ok",
    }


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="JOCKY AmCache Parser")
    ap.add_argument("--evidence-dir", required=True)
    args = ap.parse_args()
    result = run(Path(args.evidence_dir))
    print(json.dumps(result, indent=2))
