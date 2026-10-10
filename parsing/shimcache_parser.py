"""
JOCKY ShimCache Parser — extracts AppCompatCache from SYSTEM hive.

Input:  evidence/<ts>/hives/SYSTEM.hiv  (or any file classified as SYSTEM hive)
Output: evidence/<ts>/parsed/shimcache_parsed.json

ShimCache entry fields:
  - file path
  - last modified time (FILETIME of the PE on disk at time of execution)
  - data size
  - execution flag (older formats only; Win10+ dropped it)
  - order (0 = most recently executed)

Windows format detection:
  Win5.2/XP64  → signature 0xDEADBEEF, entries start at offset 8
  Win6.0/Vista → signature 0xBADC0FFE, entries start at offset 8
  Win6.1/7     → signature 0xBADC0FFE variant
  Win8/8.1     → signature 0x00000080 at offset 0
  Win10/11     → signature '10ts' (0x73743130) at offset 128

This module is standalone: does NOT call registry_parser — it re-parses
the SYSTEM hive directly to extract only AppCompatCache.
"""

import json
import struct
import sys
from pathlib import Path
from datetime import datetime, timezone

from parsing._utils import (
    make_envelope, write_envelope, parsed_output_path, filetime_to_iso
)

# ─── Signatures ───────────────────────────────────────────────────────────────
_SIG_XP64    = 0xDEADBEEF
_SIG_VISTA   = 0xBADC0FFE   # also Win7
_SIG_WIN8    = 0x00000080
_SIG_WIN10   = 0x73743130   # b'10ts' little-endian

# ─── Win10/11 entry signature ─────────────────────────────────────────────────
_ENTRY_SIG_WIN10 = 0x73743130


def _decode_win10_entries(data: bytes) -> list:
    """
    Win10/11 AppCompatCache binary format.
    Header: 128 bytes (first 4 = '10ts').
    Each entry:
      Offset  0: signature DWORD (0x73743130 = '10ts')
      Offset  4: unknown DWORD
      Offset  8: data_length DWORD  — total entry byte length including header
      Offset 12: path_length WORD   — UTF-16LE byte count for path
      Offset 14: path (UTF-16LE, path_length bytes)
      Offset 14+path_length: FILETIME QWORD
      Remainder: variable extra data
    """
    records = []
    offset  = 128   # skip 128-byte file header

    entry_idx = 0
    while offset + 12 < len(data):
        sig = struct.unpack_from("<I", data, offset)[0]
        if sig != _ENTRY_SIG_WIN10:
            break

        data_length = struct.unpack_from("<I", data, offset + 8)[0]
        if data_length < 12 or offset + data_length > len(data):
            break

        path_len_bytes = struct.unpack_from("<H", data, offset + 12)[0]

        path_start = offset + 14
        path_end   = path_start + path_len_bytes
        if path_end > offset + data_length:
            break

        try:
            path = data[path_start:path_end].decode("utf-16-le", errors="replace").rstrip("\x00")
        except Exception:
            path = ""

        ts = ""
        ft_off = path_end
        if ft_off + 8 <= offset + data_length:
            ft_val = struct.unpack_from("<Q", data, ft_off)[0]
            ts     = filetime_to_iso(ft_val)

        records.append({
            "ts":             ts,
            "order":          entry_idx,
            "path":           path,
            "execution_flag": False,
            "data_length":    data_length,
        })
        entry_idx += 1
        offset    += data_length

    return records


def _decode_win8_entries(data: bytes) -> list:
    """
    Win8/8.1 AppCompatCache format.
    Header: 128 bytes.
    Each entry:
      Offset  0: WORD  path_length (UTF-16LE byte count)
      Offset  2: WORD  max_path_length (ignored)
      Offset  4: DWORD padding / flags
      Offset  8: QWORD path offset from start of blob
      Offset 16: QWORD last modified FILETIME
      Offset 24: DWORD data_length
      Offset 28: QWORD data offset
      = 36 bytes per header entry in the entry array
    Entries are packed sequentially after the 128-byte header.
    """
    records = []
    # Win8 header at offset 0: DWORD count at offset 4, entries start at 128
    if len(data) < 8:
        return records

    entry_count = struct.unpack_from("<I", data, 4)[0]
    offset      = 128
    entry_size  = 32   # Win8 entry header size

    for idx in range(entry_count):
        if offset + entry_size > len(data):
            break

        path_len  = struct.unpack_from("<H", data, offset)[0]
        path_off  = struct.unpack_from("<Q", data, offset + 8)[0]
        ft_val    = struct.unpack_from("<Q", data, offset + 16)[0]
        exec_flag = bool(struct.unpack_from("<I", data, offset + 26)[0] & 2)

        path = ""
        if path_off and path_off + path_len <= len(data):
            try:
                path = data[int(path_off):int(path_off) + path_len].decode(
                    "utf-16-le", errors="replace"
                ).rstrip("\x00")
            except Exception:
                pass

        records.append({
            "ts":             filetime_to_iso(ft_val),
            "order":          idx,
            "path":           path,
            "execution_flag": exec_flag,
        })
        offset += entry_size

    return records


def _decode_win7_entries(data: bytes) -> list:
    """
    Win7 / Vista AppCompatCache format.
    Header: 8 bytes (signature DWORD + count DWORD).
    Each entry (variable length):
      Offset  0: WORD  path_length
      Offset  2: WORD  max_path_length
      Offset  4: DWORD path offset (from start of data)
      Offset  8: QWORD last modified FILETIME
      Offset 16: QWORD file_size
      Offset 24: QWORD exec_time (FILETIME; 0 on Vista)
      = 28 bytes on Win7; 24 on Vista
    """
    records = []
    if len(data) < 8:
        return records

    count  = struct.unpack_from("<I", data, 4)[0]
    offset = 8
    entry_size = 28

    for idx in range(min(count, 4096)):
        if offset + entry_size > len(data):
            break

        path_len = struct.unpack_from("<H", data, offset)[0]
        path_off = struct.unpack_from("<I", data, offset + 4)[0]
        ft_val   = struct.unpack_from("<Q", data, offset + 8)[0]

        path = ""
        if path_off and path_off + path_len <= len(data):
            try:
                path = data[int(path_off):int(path_off) + path_len].decode(
                    "utf-16-le", errors="replace"
                ).rstrip("\x00")
            except Exception:
                pass

        exec_time_ft = struct.unpack_from("<Q", data, offset + 24)[0] if offset + 32 <= len(data) else 0

        records.append({
            "ts":             filetime_to_iso(ft_val),
            "order":          idx,
            "path":           path,
            "execution_flag": exec_time_ft != 0,
            "exec_time":      filetime_to_iso(exec_time_ft) if exec_time_ft else "",
        })
        offset += entry_size

    return records


def _decode_xp64_entries(data: bytes) -> list:
    """
    XP 64-bit / Server 2003 AppCompatCache.
    Header: 8 bytes.
    Each entry: WORD path_len, WORD pad, DWORD path_off, QWORD FILETIME, QWORD file_size
    """
    return _decode_win7_entries(data)   # layout is the same


def decode_shimcache(raw: bytes) -> list:
    """
    Auto-detect Windows version from AppCompatCache binary blob and decode entries.
    Returns list of record dicts.
    """
    if len(raw) < 4:
        return []

    sig = struct.unpack_from("<I", raw, 0)[0]

    if sig == _SIG_WIN10:
        return _decode_win10_entries(raw)
    elif sig == _SIG_WIN8:
        return _decode_win8_entries(raw)
    elif sig in (_SIG_VISTA, _SIG_XP64):
        return _decode_win7_entries(raw)
    else:
        # Try Win10 at offset 128
        if len(raw) > 132:
            sig128 = struct.unpack_from("<I", raw, 128)[0]
            if sig128 == _ENTRY_SIG_WIN10:
                return _decode_win10_entries(raw)
        # Fallback: generic path-string scan (same as registry_parser._decode_shimcache_binary)
        from parsing.registry_parser import _decode_shimcache_binary
        return _decode_shimcache_binary(raw)


def _extract_shimcache_raw_regipy(system_hive_path: Path) -> bytes | None:
    """Use regipy to pull the AppCompatCache binary value from a SYSTEM hive."""
    try:
        from regipy.registry import RegistryHive
        reg = RegistryHive(str(system_hive_path))

        for cs in ("CurrentControlSet", "ControlSet001", "ControlSet002"):
            path = f"{cs}\\Control\\Session Manager\\AppCompatCache"
            try:
                key = reg.get_key(path)
            except Exception:
                continue
            for v in key.iter_values():
                if v.name == "AppCompatCache":
                    val = v.value
                    if isinstance(val, (bytes, bytearray)):
                        return bytes(val)
                    # regipy may return a list of ints
                    if isinstance(val, list):
                        return bytes(val)
        return None
    except Exception:
        return None


def _extract_shimcache_raw_manual(system_hive_path: Path) -> bytes | None:
    """
    Minimal NK-record scanner to extract AppCompatCache value without regipy.
    Scans the hive for the literal UTF-16LE key name and then reads the value data.
    """
    try:
        data = open(system_hive_path, "rb").read()
    except OSError:
        return None

    # Look for the UTF-16LE encoded value name "AppCompatCache"
    needle = "AppCompatCache".encode("utf-16-le")
    pos = 0
    while True:
        idx = data.find(needle, pos)
        if idx == -1:
            break
        # The VK record starts before the name; scan backwards for VK signature
        vk_off = idx - 6
        if vk_off >= 0 and data[vk_off:vk_off+2] == b"vk":
            name_len  = struct.unpack_from("<H", data, vk_off + 2)[0]
            data_len  = struct.unpack_from("<I", data, vk_off + 4)[0]
            data_off  = struct.unpack_from("<I", data, vk_off + 8)[0]
            data_type = struct.unpack_from("<I", data, vk_off + 12)[0]

            # data_off is relative to hive base + 4096 bytes
            abs_off = data_off + 4096
            if 0 < data_len < 0x400000 and abs_off + data_len <= len(data):
                return data[abs_off: abs_off + data_len]
        pos = idx + 2

    return None


def run(evidence_dir: Path) -> dict:
    evidence_dir = Path(evidence_dir)
    hives_dir    = evidence_dir / "hives"

    system_hive = None
    for candidate in (
        "SYSTEM.hiv", "System.hiv", "system.hiv",
        "SYSTEM.hive", "System.hive", "system.hive",
        "SYSTEM", "system",
    ):
        p = hives_dir / candidate
        if p.is_file():
            system_hive = p
            break

    if system_hive is None:
        return {"record_count": 0, "_output_file": "", "_status": "system_hive_not_found"}

    # Try regipy first, then manual scan
    raw = _extract_shimcache_raw_regipy(system_hive)
    if raw is None:
        raw = _extract_shimcache_raw_manual(system_hive)

    if raw is None:
        records = [{"ts": "", "error": "AppCompatCache value not found in SYSTEM hive"}]
    else:
        records = decode_shimcache(raw)

    envelope = make_envelope(
        artifact     = "shimcache",
        parser       = "shimcache_parser",
        source_file  = system_hive,
        records      = records,
        evidence_dir = evidence_dir,
    )
    out_path = parsed_output_path(evidence_dir, "shimcache")
    write_envelope(envelope, out_path)

    return {
        "record_count": len(records),
        "_output_file": str(out_path),
        "_status":      "ok",
    }


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="JOCKY ShimCache Parser")
    ap.add_argument("--evidence-dir", required=True)
    args = ap.parse_args()
    result = run(Path(args.evidence_dir))
    print(json.dumps(result, indent=2))
