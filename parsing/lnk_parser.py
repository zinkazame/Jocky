"""
JOCKY LNK Parser — parses Windows Shell Link (.lnk) files (MS-SHLLINK spec).

Extracts:
  - Target path, file size, created/modified/accessed timestamps
  - Volume serial number, volume label, drive type
  - NetBIOS name, MAC address (from TrackerDataBlock)
  - Relative path, working dir, arguments
  - Flags suspicious (.ps1 / .bat / .vbs / .js / .cmd targets)

No external dependencies — pure binary parsing from spec.
Reference: [MS-SHLLINK] — Shell Link Binary File Format
"""

import json
import struct
import sys
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

from parsing._utils import (
    make_envelope, write_envelope, parsed_output_path, filetime_to_iso
)

# ─── Shell Link Header ────────────────────────────────────────────────────────
_SHLLINK_SIG = 0x0000004C
_SHLLINK_CLSID = b'\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F'

# LinkFlags (offset 20, DWORD)
_LF_HAS_LINK_TARGET_IDLIST    = 0x00000001
_LF_HAS_LINK_INFO             = 0x00000002
_LF_HAS_NAME                  = 0x00000004
_LF_HAS_RELATIVE_PATH         = 0x00000008
_LF_HAS_WORKING_DIR           = 0x00000010
_LF_HAS_ARGUMENTS             = 0x00000020
_LF_HAS_ICON_LOCATION         = 0x00000040
_LF_IS_UNICODE                = 0x00000080

# FileAttributes (offset 24, DWORD)
_FA_DIRECTORY = 0x00000010

# DriveType constants
_DRIVE_TYPES = {
    0: "DRIVE_UNKNOWN",
    1: "DRIVE_NO_ROOT_DIR",
    2: "DRIVE_REMOVABLE",
    3: "DRIVE_FIXED",
    4: "DRIVE_REMOTE",
    5: "DRIVE_CDROM",
    6: "DRIVE_RAMDISK",
}

# ─── Suspicious extensions ────────────────────────────────────────────────────
_SUSPICIOUS_EXTS = {".ps1", ".bat", ".vbs", ".js", ".cmd", ".hta", ".wsf", ".jse", ".vbe"}


def _read_counted_string(data: bytes, off: int, is_unicode: bool) -> tuple:
    """
    Read a CountedString structure: 2-byte count (char count) + string.
    Returns (string, new_offset).
    """
    count = struct.unpack_from("<H", data, off)[0]
    off += 2
    if is_unicode:
        raw = data[off: off + count * 2]
        try:
            s = raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        except Exception:
            s = raw.hex()
        off += count * 2
    else:
        raw = data[off: off + count]
        try:
            s = raw.decode("cp1252", errors="replace").rstrip("\x00")
        except Exception:
            s = raw.hex()
        off += count
    return s, off


def _parse_link_info(data: bytes, off: int) -> dict:
    """Parse the LinkInfo structure at offset off."""
    info = {}
    if off + 28 > len(data):
        return info

    li_size       = struct.unpack_from("<I", data, off)[0]
    li_hdr_size   = struct.unpack_from("<I", data, off + 4)[0]
    li_flags      = struct.unpack_from("<I", data, off + 8)[0]
    vol_id_off_rel = struct.unpack_from("<I", data, off + 12)[0]
    local_bp_off  = struct.unpack_from("<I", data, off + 16)[0]
    cni_off       = struct.unpack_from("<I", data, off + 20)[0]
    cni_bp_off    = struct.unpack_from("<I", data, off + 24)[0]

    has_vol  = (li_flags & 0x1) != 0
    has_net  = (li_flags & 0x2) != 0

    # VolumeID structure
    if has_vol and vol_id_off_rel and off + vol_id_off_rel + 16 <= len(data):
        vid_off    = off + vol_id_off_rel
        drive_type = struct.unpack_from("<I", data, vid_off + 4)[0]
        drive_sn   = struct.unpack_from("<I", data, vid_off + 8)[0]
        label_off  = struct.unpack_from("<I", data, vid_off + 12)[0]

        info["drive_type"]    = _DRIVE_TYPES.get(drive_type, f"0x{drive_type:X}")
        info["drive_serial"]  = f"{drive_sn:08X}"

        abs_label_off = vid_off + label_off
        if abs_label_off < len(data):
            end = data.find(b"\x00", abs_label_off)
            if end == -1:
                end = abs_label_off + 64
            try:
                info["volume_label"] = data[abs_label_off:end].decode(
                    "cp1252", errors="replace"
                )
            except Exception:
                info["volume_label"] = ""

    # Local base path
    if local_bp_off and off + local_bp_off < len(data):
        end = data.find(b"\x00", off + local_bp_off)
        if end == -1:
            end = off + local_bp_off + 260
        try:
            info["local_base_path"] = data[off + local_bp_off: end].decode(
                "cp1252", errors="replace"
            )
        except Exception:
            info["local_base_path"] = ""

    # CommonNetworkRelativeLink
    if has_net and cni_off and off + cni_off + 20 <= len(data):
        cni_base     = off + cni_off
        net_name_off = struct.unpack_from("<I", data, cni_base + 8)[0]
        abs_nn_off   = cni_base + net_name_off
        if abs_nn_off < len(data):
            end = data.find(b"\x00", abs_nn_off)
            if end == -1:
                end = abs_nn_off + 260
            try:
                info["net_name"] = data[abs_nn_off:end].decode("cp1252", errors="replace")
            except Exception:
                info["net_name"] = ""

    return info


def _parse_tracker_data_block(data: bytes, off: int) -> dict:
    """
    Parse a TrackerDataBlock at offset off.
    Structure:
      BlockSize     DWORD
      BlockSig      DWORD  (0xA0000003)
      Length        DWORD
      Version       DWORD
      MachineID     20 bytes (NetBIOS name, null-padded)
      Droid1        GUID (16 bytes) — volume GUID
      Droid2        GUID (16 bytes) — file GUID
      DroidBirth1   GUID (16 bytes)
      DroidBirth2   GUID (16 bytes)
    """
    result = {}
    if off + 88 > len(data):
        return result

    block_sig = struct.unpack_from("<I", data, off + 4)[0]
    if block_sig != 0xA0000003:
        return result

    machine_id_raw = data[off + 16: off + 36]
    try:
        machine_id = machine_id_raw.split(b"\x00")[0].decode("ascii", errors="replace")
    except Exception:
        machine_id = machine_id_raw.hex()

    result["machine_id"] = machine_id

    # Droid2 GUID contains the MAC address in the last 6 bytes (for v1 UUIDs)
    droid2_raw = data[off + 52: off + 68]
    if len(droid2_raw) == 16:
        try:
            droid2 = uuid.UUID(bytes_le=droid2_raw)
            result["droid2_guid"] = str(droid2)
            # UUID v1: node = last 6 bytes (bytes 10-15 in RFC4122 byte order)
            if droid2.version == 1:
                node = droid2.node
                mac  = ":".join(f"{(node >> (8 * i)) & 0xFF:02x}" for i in range(5, -1, -1))
                result["mac_address"] = mac
        except Exception:
            result["droid2_guid"] = droid2_raw.hex()

    return result


def parse_lnk_file(lnk_path: Path) -> dict:
    """
    Parse a single .lnk file. Returns a flat metadata dict.
    """
    try:
        data = open(lnk_path, "rb").read()
    except OSError as e:
        return {"error": str(e)}

    if len(data) < 76:
        return {"error": "file too small"}

    # Header validation
    header_size = struct.unpack_from("<I", data, 0)[0]
    sig         = struct.unpack_from("<I", data, 4)[0]
    if header_size < 76 or sig != _SHLLINK_SIG:
        return {"error": "invalid shell link header"}

    link_clsid  = data[8:24]
    link_flags  = struct.unpack_from("<I", data, 20)[0]
    file_attrs  = struct.unpack_from("<I", data, 24)[0]

    # Timestamps (FILETIME, 8 bytes each)
    ts_created  = filetime_to_iso(struct.unpack_from("<Q", data, 28)[0])
    ts_accessed = filetime_to_iso(struct.unpack_from("<Q", data, 36)[0])
    ts_modified = filetime_to_iso(struct.unpack_from("<Q", data, 44)[0])

    file_size   = struct.unpack_from("<I", data, 52)[0]

    is_unicode  = bool(link_flags & _LF_IS_UNICODE)

    # Current parse offset
    off = header_size

    # ── IDList (skip) ─────────────────────────────────────────────────────────
    if link_flags & _LF_HAS_LINK_TARGET_IDLIST:
        if off + 2 > len(data):
            return {"error": "truncated IDList"}
        idlist_size = struct.unpack_from("<H", data, off)[0]
        off += 2 + idlist_size

    # ── LinkInfo ─────────────────────────────────────────────────────────────
    link_info = {}
    if link_flags & _LF_HAS_LINK_INFO:
        if off + 4 > len(data):
            return {"error": "truncated LinkInfo"}
        li_size  = struct.unpack_from("<I", data, off)[0]
        link_info = _parse_link_info(data, off)
        off += li_size

    # ── StringData ────────────────────────────────────────────────────────────
    strings = {}
    for flag, key in (
        (_LF_HAS_NAME,          "name"),
        (_LF_HAS_RELATIVE_PATH, "relative_path"),
        (_LF_HAS_WORKING_DIR,   "working_dir"),
        (_LF_HAS_ARGUMENTS,     "arguments"),
        (_LF_HAS_ICON_LOCATION, "icon_location"),
    ):
        if link_flags & flag:
            if off + 2 > len(data):
                break
            s, off = _read_counted_string(data, off, is_unicode)
            strings[key] = s

    # ── Extra Data (search for TrackerDataBlock) ──────────────────────────────
    tracker = {}
    while off + 8 <= len(data):
        block_size = struct.unpack_from("<I", data, off)[0]
        if block_size < 8:
            break
        block_sig = struct.unpack_from("<I", data, off + 4)[0]
        if block_sig == 0xA0000003:
            tracker = _parse_tracker_data_block(data, off)
        if off + block_size > len(data):
            break
        off += block_size

    # ── Assemble result ───────────────────────────────────────────────────────
    target_path = link_info.get("local_base_path", link_info.get("net_name", ""))

    # Determine if suspicious
    suspicious = False
    if target_path:
        ext = Path(target_path).suffix.lower()
        if ext in _SUSPICIOUS_EXTS:
            suspicious = True
    if strings.get("relative_path"):
        ext = Path(strings["relative_path"]).suffix.lower()
        if ext in _SUSPICIOUS_EXTS:
            suspicious = True

    result = {
        "ts":              ts_modified or ts_created,
        "ts_created":      ts_created,
        "ts_modified":     ts_modified,
        "ts_accessed":     ts_accessed,
        "target_path":     target_path,
        "target_file_size": file_size,
        "drive_type":      link_info.get("drive_type", ""),
        "drive_serial":    link_info.get("drive_serial", ""),
        "volume_label":    link_info.get("volume_label", ""),
        "net_name":        link_info.get("net_name", ""),
        "relative_path":   strings.get("relative_path", ""),
        "working_dir":     strings.get("working_dir", ""),
        "arguments":       strings.get("arguments", ""),
        "icon_location":   strings.get("icon_location", ""),
        "name":            strings.get("name", ""),
        "machine_id":      tracker.get("machine_id", ""),
        "mac_address":     tracker.get("mac_address", ""),
        "droid2_guid":     tracker.get("droid2_guid", ""),
        "suspicious":      suspicious,
        "source_file":     lnk_path.name,
    }
    return result


def run(evidence_dir: Path) -> dict:
    evidence_dir = Path(evidence_dir)
    lnk_dir      = evidence_dir / "lnk"

    if not lnk_dir.is_dir():
        return {"record_count": 0, "_output_file": "", "_status": "no_lnk_dir"}

    lnk_files = list(lnk_dir.glob("*.lnk")) + list(lnk_dir.glob("*.LNK"))
    if not lnk_files:
        return {"record_count": 0, "_output_file": "", "_status": "no_lnk_files"}

    records = []
    for lnk_path in sorted(lnk_files):
        info = parse_lnk_file(lnk_path)
        records.append(info)

    envelope = make_envelope(
        artifact     = "lnk",
        parser       = "lnk_parser",
        source_file  = lnk_dir,
        records      = records,
        evidence_dir = evidence_dir,
    )
    envelope["source_file"]   = "lnk/"
    envelope["source_sha256"] = "directory"

    out_path = parsed_output_path(evidence_dir, "lnk")
    write_envelope(envelope, out_path)

    return {
        "record_count":  len(records),
        "_output_file":  str(out_path),
        "_status":       "ok",
    }


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="JOCKY LNK Parser")
    ap.add_argument("--evidence-dir", required=True)
    args = ap.parse_args()
    result = run(Path(args.evidence_dir))
    print(json.dumps(result, indent=2))
