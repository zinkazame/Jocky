"""
JOCKY Registry Parser — parses Windows Registry hive files (.hiv / .hive).

Deps: regipy (pip install regipy)
      Falls back to a minimal raw NK-record scanner if regipy is absent.

Extracts from SYSTEM hive:
  - CurrentControlSet\\Services (services/drivers)
  - CurrentControlSet\\Enum\\USBSTOR (USB device history)
  - Session Manager\\AppCompatCache (ShimCache)

Extracts from SOFTWARE hive:
  - Microsoft\\Windows\\CurrentVersion\\Run + RunOnce (persistence)
  - Microsoft\\Windows\\CurrentVersion\\Uninstall (installed software)
  - Microsoft\\Internet Explorer\\TypedURLs
  - Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs
  - Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist (ROT-13 decoded)

Extracts from NTUSER.DAT:
  - Same Run/RunOnce, RecentDocs, UserAssist
  - MountedDevices (SYSTEM hive too)
  - WordWheelQuery (Explorer search terms)
"""

import json
import struct
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

from parsing._utils import (
    make_envelope, write_envelope, parsed_output_path,
    rot13, filetime_to_iso, sha256_file
)

# ─── Windows FILETIME base ────────────────────────────────────────────────────
_WIN_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# ─── Hive name classification ─────────────────────────────────────────────────
def _classify_hive(path: Path) -> str:
    stem = path.stem.upper()
    name = path.name.upper()
    if "SYSTEM" in name:
        return "SYSTEM"
    if "SOFTWARE" in name:
        return "SOFTWARE"
    if "NTUSER" in name or "NTUSER.DAT" in name:
        return "NTUSER"
    if "AMCACHE" in name:
        return "AMCACHE"
    if "SAM" == stem:
        return "SAM"
    if "SECURITY" == stem:
        return "SECURITY"
    return "UNKNOWN"


# ═══════════════════════════════════════════════════════════════════════════════
# regipy-based parsing (preferred path)
# ═══════════════════════════════════════════════════════════════════════════════

def _regipy_get_key(reg, path: str):
    """Navigate to a registry key by path, return key or None."""
    try:
        return reg.get_key(path)
    except Exception:
        return None


def _regipy_key_values(key) -> dict:
    """Return {name: value_str} for all values in a regipy key."""
    result = {}
    if key is None:
        return result
    try:
        for v in key.iter_values():
            try:
                result[v.name] = str(v.value)
            except Exception:
                result[v.name] = "<unreadable>"
    except Exception:
        pass
    return result


def _regipy_subkey_names(key) -> list:
    if key is None:
        return []
    try:
        return [sk.name for sk in key.iter_subkeys()]
    except Exception:
        return []


def _filetime_from_regipy_key(key) -> str:
    """Extract last-written timestamp from a regipy RegistryKey."""
    try:
        ft = key.header.last_modified
        # regipy may return datetime directly or integer
        if isinstance(ft, datetime):
            if ft.tzinfo is None:
                ft = ft.replace(tzinfo=timezone.utc)
            return ft.isoformat()
        elif isinstance(ft, int):
            return filetime_to_iso(ft)
    except Exception:
        pass
    return ""


def _parse_userassist_regipy(ua_key) -> list:
    """Decode UserAssist subkeys (ROT-13 encoded program names)."""
    records = []
    if ua_key is None:
        return records
    try:
        for guid_key in ua_key.iter_subkeys():
            count_key = None
            for sk in guid_key.iter_subkeys():
                if sk.name.upper() == "COUNT":
                    count_key = sk
                    break
            if count_key is None:
                continue
            for v in count_key.iter_values():
                decoded_name = rot13(v.name)
                entry = {"name": decoded_name, "raw_name": v.name}
                # Value is a 72-byte structure: USERASSISTENTRY
                # Offset 4:  session (DWORD)
                # Offset 8:  count (DWORD)
                # Offset 60: last execution FILETIME (QWORD)
                try:
                    raw = bytes(v.value) if not isinstance(v.value, bytes) else v.value
                    if len(raw) >= 72:
                        count    = struct.unpack_from("<I", raw, 8)[0]
                        ts_raw   = struct.unpack_from("<Q", raw, 60)[0]
                        entry["run_count"] = count
                        entry["ts"]        = filetime_to_iso(ts_raw)
                    elif len(raw) >= 16:
                        count  = struct.unpack_from("<I", raw, 8)[0]
                        entry["run_count"] = count
                        entry["ts"] = ""
                except Exception:
                    entry["ts"] = ""
                records.append(entry)
    except Exception:
        pass
    return records


def _parse_shimcache_regipy(sys_key) -> list:
    """Parse AppCompatCache from SYSTEM hive."""
    records = []
    # Try both ControlSet001 and CurrentControlSet
    for cs in ("CurrentControlSet", "ControlSet001", "ControlSet002"):
        path = f"{cs}\\Control\\Session Manager\\AppCompatCache"
        key = _regipy_get_key(sys_key, path)
        if key is not None:
            break
    if key is None:
        return records

    raw_val = None
    try:
        for v in key.iter_values():
            if v.name == "AppCompatCache":
                raw_val = bytes(v.value) if not isinstance(v.value, bytes) else v.value
                break
    except Exception:
        return records

    if raw_val is None:
        return records

    return _decode_shimcache_binary(raw_val)


def _decode_shimcache_binary(data: bytes) -> list:
    """
    Decode the AppCompatCache binary blob.
    Windows 10/11 format starts with a 128-byte header, then variable-length entries.
    Each entry (simplified):
      Signature: 0x00000030 (Win10 = '10ts')
      Unknown:   DWORD
      Data size: DWORD
      Padding:   DWORD
      Path length:  WORD
      Path:         UTF-16LE string
      Last modified FILETIME: QWORD
    """
    records = []
    if len(data) < 4:
        return records

    sig = struct.unpack_from("<I", data, 0)[0]

    # Windows 10/11 signature: 0x30 at offset 128
    # Actually header bytes: "10ts" = 0x73743130 (little-endian)
    WIN10_SIG = 0x73743130   # '10ts'
    WIN8_SIG  = 0x80         # one common Win8 signature

    if sig == WIN10_SIG:
        # Win10/11 format: 128-byte header
        offset = 128
        entry_idx = 0
        while offset < len(data) - 12:
            try:
                entry_sig  = struct.unpack_from("<I", data, offset)[0]
                if entry_sig != WIN10_SIG:
                    break
                data_size  = struct.unpack_from("<I", data, offset + 8)[0]
                path_len   = struct.unpack_from("<H", data, offset + 12)[0]
                path_raw   = data[offset + 14: offset + 14 + path_len]
                try:
                    path = path_raw.decode("utf-16-le", errors="replace").rstrip("\x00")
                except Exception:
                    path = path_raw.hex()

                ft_off = offset + 14 + path_len
                ts     = ""
                if ft_off + 8 <= len(data):
                    ft_val = struct.unpack_from("<Q", data, ft_off)[0]
                    ts     = filetime_to_iso(ft_val)

                records.append({
                    "ts":         ts,
                    "order":      entry_idx,
                    "path":       path,
                    "data_size":  data_size,
                    "execution_flag": False,  # Win10 removed this flag
                })
                entry_idx += 1
                offset += 12 + data_size  # header(12) + data
            except struct.error:
                break

    else:
        # Attempt generic scan: look for UTF-16LE path-like strings
        # preceded by a WORD length field + QWORD FILETIME after them
        offset = 0
        entry_idx = 0
        while offset < len(data) - 10:
            try:
                path_len = struct.unpack_from("<H", data, offset)[0]
                if 2 <= path_len <= 520 and path_len % 2 == 0:
                    path_end = offset + 2 + path_len
                    if path_end + 8 > len(data):
                        offset += 2
                        continue
                    raw_path = data[offset + 2: path_end]
                    try:
                        path = raw_path.decode("utf-16-le", errors="strict").rstrip("\x00")
                    except UnicodeDecodeError:
                        offset += 2
                        continue
                    # Must look like a Windows path
                    if not (path.startswith("\\") or (len(path) > 2 and path[1] == ":")):
                        offset += 2
                        continue
                    ft_val = struct.unpack_from("<Q", data, path_end)[0]
                    ts     = filetime_to_iso(ft_val)
                    records.append({
                        "ts":            ts,
                        "order":         entry_idx,
                        "path":          path,
                        "execution_flag": False,
                    })
                    entry_idx += 1
                    offset = path_end + 8
                    continue
            except struct.error:
                pass
            offset += 2

    return records


def _parse_system_hive(reg) -> dict:
    """Extract forensic artifacts from the SYSTEM hive."""
    result = {"services": [], "usbstor": [], "shimcache": []}

    # ── Services ────────────────────────────────────────────────────────────
    for cs in ("CurrentControlSet", "ControlSet001"):
        svc_key = _regipy_get_key(reg, f"{cs}\\Services")
        if svc_key:
            try:
                for sk in svc_key.iter_subkeys():
                    svc = {"ts": _filetime_from_regipy_key(sk), "name": sk.name}
                    vals = _regipy_key_values(sk)
                    svc.update({
                        "image_path":  vals.get("ImagePath", ""),
                        "start_type":  vals.get("Start", ""),
                        "service_type": vals.get("Type", ""),
                        "display_name": vals.get("DisplayName", ""),
                        "description":  vals.get("Description", ""),
                    })
                    result["services"].append(svc)
            except Exception:
                pass
            break

    # ── USB Storage ─────────────────────────────────────────────────────────
    for cs in ("CurrentControlSet", "ControlSet001"):
        usb_key = _regipy_get_key(reg, f"{cs}\\Enum\\USBSTOR")
        if usb_key:
            try:
                for dev_class in usb_key.iter_subkeys():
                    for instance in dev_class.iter_subkeys():
                        vals = _regipy_key_values(instance)
                        entry = {
                            "ts":            _filetime_from_regipy_key(instance),
                            "device_class":  dev_class.name,
                            "instance_id":   instance.name,
                            "friendly_name": vals.get("FriendlyName", ""),
                            "hardware_id":   vals.get("HardwareID", ""),
                            "mfg":           vals.get("Mfg", ""),
                        }
                        # First/last connected from Properties subkeys
                        props_key = None
                        for sk in instance.iter_subkeys():
                            if sk.name.lower() == "properties":
                                props_key = sk
                                break
                        if props_key:
                            # GUID for first install: {83da6326-97a6-4088-9453-a1923f573b29}\0064
                            for pk in props_key.iter_subkeys():
                                try:
                                    for prop_inst in pk.iter_subkeys():
                                        for v in prop_inst.iter_values():
                                            try:
                                                raw = bytes(v.value) if not isinstance(v.value, bytes) else v.value
                                                if len(raw) >= 8:
                                                    ft = struct.unpack_from("<Q", raw, 0)[0]
                                                    ts_str = filetime_to_iso(ft)
                                                    if ts_str:
                                                        prop_id = prop_inst.name
                                                        if "0064" in prop_id:
                                                            entry["first_connected"] = ts_str
                                                        elif "0066" in prop_id:
                                                            entry["last_connected"] = ts_str
                                            except Exception:
                                                pass
                                except Exception:
                                    pass
                        result["usbstor"].append(entry)
            except Exception:
                pass
            break

    # ── ShimCache ────────────────────────────────────────────────────────────
    result["shimcache"] = _parse_shimcache_regipy(reg)

    return result


def _parse_software_hive(reg) -> dict:
    """Extract forensic artifacts from the SOFTWARE hive."""
    result = {
        "run_keys":       [],
        "installed_sw":   [],
        "typed_urls":     [],
        "recent_docs":    [],
        "userassist":     [],
    }

    # ── Run / RunOnce ────────────────────────────────────────────────────────
    run_paths = [
        "Microsoft\\Windows\\CurrentVersion\\Run",
        "Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Microsoft\\Windows NT\\CurrentVersion\\Run",
        "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    ]
    for rp in run_paths:
        k = _regipy_get_key(reg, rp)
        if k:
            vals = _regipy_key_values(k)
            ts_k = _filetime_from_regipy_key(k)
            for name, value in vals.items():
                result["run_keys"].append({
                    "ts":      ts_k,
                    "key":     rp,
                    "name":    name,
                    "command": value,
                })

    # ── Installed Software ───────────────────────────────────────────────────
    for base in (
        "Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    ):
        uninstall_key = _regipy_get_key(reg, base)
        if uninstall_key:
            try:
                for app_key in uninstall_key.iter_subkeys():
                    vals = _regipy_key_values(app_key)
                    result["installed_sw"].append({
                        "ts":               _filetime_from_regipy_key(app_key),
                        "key_name":         app_key.name,
                        "display_name":     vals.get("DisplayName", ""),
                        "display_version":  vals.get("DisplayVersion", ""),
                        "publisher":        vals.get("Publisher", ""),
                        "install_date":     vals.get("InstallDate", ""),
                        "install_location": vals.get("InstallLocation", ""),
                        "uninstall_string": vals.get("UninstallString", ""),
                    })
            except Exception:
                pass

    # ── TypedURLs ────────────────────────────────────────────────────────────
    typed_key = _regipy_get_key(reg, "Microsoft\\Internet Explorer\\TypedURLs")
    if typed_key:
        for name, value in _regipy_key_values(typed_key).items():
            result["typed_urls"].append({
                "ts":    _filetime_from_regipy_key(typed_key),
                "name":  name,
                "url":   value,
            })

    # ── RecentDocs ───────────────────────────────────────────────────────────
    rd_key = _regipy_get_key(
        reg, "Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"
    )
    if rd_key:
        vals = _regipy_key_values(rd_key)
        ts_k = _filetime_from_regipy_key(rd_key)
        for name, value in vals.items():
            result["recent_docs"].append({
                "ts":    ts_k,
                "name":  name,
                "value": value,
            })

    # ── UserAssist ───────────────────────────────────────────────────────────
    ua_key = _regipy_get_key(
        reg, "Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"
    )
    result["userassist"] = _parse_userassist_regipy(ua_key)

    return result


def _parse_ntuser_hive(reg) -> dict:
    """Extract forensic artifacts from NTUSER.DAT."""
    result = {
        "run_keys":         [],
        "recent_docs":      [],
        "userassist":       [],
        "word_wheel_query": [],
        "mounted_devices":  [],
        "typed_paths":      [],
    }

    # ── Run / RunOnce ────────────────────────────────────────────────────────
    for rp in (
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    ):
        k = _regipy_get_key(reg, rp)
        if k:
            ts_k = _filetime_from_regipy_key(k)
            for name, value in _regipy_key_values(k).items():
                result["run_keys"].append({
                    "ts": ts_k, "key": rp, "name": name, "command": value
                })

    # ── RecentDocs ───────────────────────────────────────────────────────────
    rd_key = _regipy_get_key(
        reg, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"
    )
    if rd_key:
        ts_k = _filetime_from_regipy_key(rd_key)
        for name, value in _regipy_key_values(rd_key).items():
            result["recent_docs"].append({"ts": ts_k, "name": name, "value": value})

    # ── UserAssist ───────────────────────────────────────────────────────────
    ua_key = _regipy_get_key(
        reg,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
    )
    result["userassist"] = _parse_userassist_regipy(ua_key)

    # ── WordWheelQuery ────────────────────────────────────────────────────────
    wwq_key = _regipy_get_key(
        reg, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery"
    )
    if wwq_key:
        ts_k = _filetime_from_regipy_key(wwq_key)
        for name, value in _regipy_key_values(wwq_key).items():
            # Values may be UTF-16LE bytes stored as REG_BINARY
            if isinstance(value, bytes):
                try:
                    value = value.decode("utf-16-le", errors="replace").rstrip("\x00")
                except Exception:
                    value = value.hex()
            result["word_wheel_query"].append({
                "ts": ts_k, "index": name, "search_term": str(value)
            })

    # ── TypedPaths ───────────────────────────────────────────────────────────
    tp_key = _regipy_get_key(
        reg,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths",
    )
    if tp_key:
        ts_k = _filetime_from_regipy_key(tp_key)
        for name, value in _regipy_key_values(tp_key).items():
            result["typed_paths"].append({"ts": ts_k, "name": name, "path": value})

    return result


def _parse_hive_regipy(path: Path, hive_type: str) -> dict:
    """Use regipy to parse a hive file. Returns a dict of record arrays."""
    from regipy.registry import RegistryHive
    reg = RegistryHive(str(path))

    if hive_type == "SYSTEM":
        return _parse_system_hive(reg)
    elif hive_type == "SOFTWARE":
        return _parse_software_hive(reg)
    elif hive_type in ("NTUSER", "NTUSER.DAT"):
        return _parse_ntuser_hive(reg)
    else:
        # Generic: return root key values
        root_vals = _regipy_key_values(reg.root)
        return {"root_values": [{"ts": "", "key": "ROOT", **root_vals}]}


# ═══════════════════════════════════════════════════════════════════════════════
# Fallback raw NK-record scanner (when regipy is unavailable)
# ═══════════════════════════════════════════════════════════════════════════════

def _raw_scan_strings(data: bytes) -> list:
    """
    Minimal fallback: scan for printable ASCII/UTF-16LE strings that look
    like registry paths or values.  Very limited but better than nothing.
    """
    results = []
    # Scan UTF-16LE strings
    i = 0
    while i < len(data) - 4:
        if data[i+1] == 0 and 0x20 <= data[i] <= 0x7E:
            # Possible start of UTF-16LE string
            j = i
            chars = []
            while j < len(data) - 1:
                lo = data[j]
                hi = data[j+1]
                if hi != 0 or lo < 0x20 or lo > 0x7E:
                    break
                chars.append(chr(lo))
                j += 2
            if len(chars) >= 8:
                s = "".join(chars)
                if "\\" in s or "." in s:
                    results.append({"ts": "", "raw_string": s})
            i = j + 2
        else:
            i += 1
    return results[:500]  # cap at 500


def _parse_hive_raw(path: Path) -> dict:
    """Raw fallback when regipy is unavailable."""
    try:
        data = open(path, "rb").read()
    except OSError as e:
        return {"error": str(e)}
    strings = _raw_scan_strings(data)
    return {"raw_strings": strings}


def _flatten_records(hive_data: dict, hive_type: str) -> list:
    """
    Flatten the per-section dicts into a single records list for the envelope.
    Each record gets a 'section' tag and guaranteed 'ts' field.
    """
    records = []
    for section, items in hive_data.items():
        if isinstance(items, list):
            for item in items:
                rec = dict(item)
                rec["section"]    = section
                rec["hive_type"]  = hive_type
                if "ts" not in rec:
                    rec["ts"] = ""
                records.append(rec)
        elif isinstance(items, dict):
            rec = {"section": section, "hive_type": hive_type, "ts": "", "data": items}
            records.append(rec)
    return records


def parse_hive_file(path: Path) -> tuple:
    """
    Parse a single hive file. Returns (hive_type, records_list).
    """
    hive_type = _classify_hive(path)
    try:
        import regipy  # noqa: F401
        hive_data = _parse_hive_regipy(path, hive_type)
    except ImportError:
        hive_data = _parse_hive_raw(path)
    except Exception as e:
        hive_data = {"error": str(e)}

    records = _flatten_records(hive_data, hive_type)
    return hive_type, records


def run(evidence_dir: Path) -> dict:
    evidence_dir = Path(evidence_dir)
    hives_dir    = evidence_dir / "hives"

    if not hives_dir.is_dir():
        return {"record_count": 0, "_output_file": "", "_status": "no_hives_dir"}

    hive_files = (
        list(hives_dir.glob("*.hiv"))  +
        list(hives_dir.glob("*.hive")) +
        list(hives_dir.glob("*.HIV"))  +
        list(hives_dir.glob("*.dat"))  +
        list(hives_dir.glob("*.DAT"))  +
        list(hives_dir.glob("*.hve"))  +
        list(hives_dir.glob("*.HVE"))
    )
    # Exclude Amcache — handled by amcache_parser
    hive_files = [f for f in hive_files if "amcache" not in f.name.lower()]

    if not hive_files:
        return {"record_count": 0, "_output_file": "", "_status": "no_hive_files"}

    total_records = 0
    output_files  = []

    for hive_path in sorted(hive_files):
        hive_type, records = parse_hive_file(hive_path)
        stem       = hive_path.stem.lower().replace(" ", "_")
        artifact   = f"registry_{stem}"

        envelope = make_envelope(
            artifact     = artifact,
            parser       = "registry_parser",
            source_file  = hive_path,
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
    ap = argparse.ArgumentParser(description="JOCKY Registry Parser")
    ap.add_argument("--evidence-dir", required=True)
    args = ap.parse_args()
    result = run(Path(args.evidence_dir))
    print(json.dumps(result, indent=2))
