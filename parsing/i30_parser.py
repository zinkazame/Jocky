"""
JOCKY $I30 Parser — extracts NTFS directory index slack entries.

$I30 = $INDEX_ALLOCATION attribute of an NTFS directory.
Each entry = NTFS Index Entry (INDX record structure).
Slack space between active entries may contain residual data from
previously deleted files.

Input modes:
  1. evidence/<ts>/i30/*.i30     — raw $INDEX_ALLOCATION dumps
  2. evidence/<ts>/i30/*.indx    — INDX block dumps (4096 bytes each)
  3. Live mode (Windows only):   CreateFile on \\\\.\\ volume with BACKUP_READ
     and extract raw INDX blocks

Each index entry contains:
  - File reference (MFT record number + sequence)
  - Created / modified / accessed / MFT-changed timestamps (FILETIME)
  - File size (allocated + real)
  - File name (UTF-16LE, stored in entry)
  - File attributes flags

Entries found only in slack (not in the active live filesystem) are
flagged with "deleted": true.

INDX block structure (per Microsoft NTFS specification):
  Offset  0:  Signature "INDX" (4 bytes)
  Offset  4:  Update Sequence Array (USA) offset (WORD)
  Offset  6:  USA size in words (WORD)
  Offset  8:  Log File Sequence Number (QWORD)
  Offset 16:  VCN of this INDX buffer (QWORD)
  Offset 24:  Index Entries Offset (DWORD) — relative to offset 24
  Offset 28:  Index Entries End (DWORD)
  Offset 32:  Index Entries Allocated (DWORD)
  Offset 36:  Leaf flag (BYTE)
  ...followed by Index Entries at offset 24 + IndexEntriesOffset

Index Entry (FILE_NAME attribute):
  Offset  0:  File reference (8 bytes: 6-byte MFN + 2-byte seq)
  Offset  8:  Length of index entry (WORD)
  Offset 10:  Length of stream (WORD)
  Offset 12:  Index entry flags (BYTE)
  Offset 13:  Padding (3 bytes)
  Offset 16:  Parent file reference (8 bytes)
  Offset 24:  Created time (FILETIME QWORD)
  Offset 32:  Modified time (FILETIME QWORD)
  Offset 40:  MFT changed time (FILETIME QWORD)
  Offset 48:  Last access time (FILETIME QWORD)
  Offset 56:  Allocated size (QWORD)
  Offset 64:  Real size (QWORD)
  Offset 72:  File attributes (DWORD)
  Offset 76:  Extended data (DWORD)
  Offset 80:  File name length (BYTE, in chars)
  Offset 81:  File name namespace (BYTE)
  Offset 82:  File name (UTF-16LE, variable length)
"""

import ctypes
import json
import os
import struct
import sys
from pathlib import Path
from datetime import datetime, timezone

from parsing._utils import (
    make_envelope, write_envelope, parsed_output_path, filetime_to_iso
)

# ─── INDX block signature ─────────────────────────────────────────────────────
INDX_SIG = b"INDX"
INDX_BLOCK_SIZE = 4096   # default; can be 8192 on large-sector disks

# ─── Index entry flags ────────────────────────────────────────────────────────
INDEX_ENTRY_NODE  = 0x01   # has child VCN
INDEX_ENTRY_END   = 0x02   # last entry in node

# ─── File attribute flags ─────────────────────────────────────────────────────
FA_READONLY     = 0x0001
FA_HIDDEN       = 0x0002
FA_SYSTEM       = 0x0004
FA_DIRECTORY    = 0x0010
FA_ARCHIVE      = 0x0020
FA_REPARSE      = 0x0400
FA_COMPRESSED   = 0x0800
FA_ENCRYPTED    = 0x4000


def _apply_usa(block: bytes, usa_off: int, usa_count: int) -> bytes:
    """Apply Update Sequence Array fixup to a raw INDX block."""
    data = bytearray(block)
    if usa_off + usa_count * 2 > len(data):
        return bytes(data)

    usn = struct.unpack_from("<H", data, usa_off)[0]   # Update Sequence Number

    # Fixup: replace last 2 bytes of each 512-byte sector with the original value
    for i in range(1, usa_count):
        sector_end = i * 512 - 2
        if sector_end + 2 > len(data):
            break
        # Verify sector end matches USN
        if struct.unpack_from("<H", data, sector_end)[0] == usn:
            original = struct.unpack_from("<H", data, usa_off + i * 2)[0]
            struct.pack_into("<H", data, sector_end, original)

    return bytes(data)


def _parse_file_attributes(fa: int) -> list:
    flags = []
    if fa & FA_READONLY:   flags.append("READONLY")
    if fa & FA_HIDDEN:     flags.append("HIDDEN")
    if fa & FA_SYSTEM:     flags.append("SYSTEM")
    if fa & FA_DIRECTORY:  flags.append("DIRECTORY")
    if fa & FA_ARCHIVE:    flags.append("ARCHIVE")
    if fa & FA_REPARSE:    flags.append("REPARSE_POINT")
    if fa & FA_COMPRESSED: flags.append("COMPRESSED")
    if fa & FA_ENCRYPTED:  flags.append("ENCRYPTED")
    return flags


def _parse_file_ref(raw8: bytes) -> dict:
    """Parse a FILE_REFERENCE (8 bytes): 6-byte MFT number + 2-byte sequence."""
    mft_lo  = struct.unpack_from("<I", raw8, 0)[0]
    mft_hi  = struct.unpack_from("<H", raw8, 4)[0]
    seq     = struct.unpack_from("<H", raw8, 6)[0]
    mft_num = mft_lo | (mft_hi << 32)
    return {"mft_number": mft_num, "sequence": seq}


def _parse_index_entry(data: bytes, off: int) -> dict | None:
    """
    Parse one NTFS Index Entry starting at off.
    Returns entry dict or None if invalid / end marker.
    """
    if off + 16 > len(data):
        return None

    entry_len   = struct.unpack_from("<H", data, off + 8)[0]
    stream_len  = struct.unpack_from("<H", data, off + 10)[0]
    flags       = data[off + 12]

    if flags & INDEX_ENTRY_END:
        return None   # End of active entries marker

    if entry_len < 16 or off + entry_len > len(data):
        return None

    file_ref_raw    = data[off:     off + 8]
    parent_ref_raw  = data[off + 16: off + 24] if off + 24 <= len(data) else b"\x00" * 8

    file_ref  = _parse_file_ref(file_ref_raw)
    parent_ref = _parse_file_ref(parent_ref_raw)

    if stream_len < 66:   # minimum to hold timestamps and name length
        return {
            "mft_number": file_ref["mft_number"],
            "sequence":   file_ref["sequence"],
            "parent_mft": parent_ref["mft_number"],
            "entry_len":  entry_len,
            "stream_len": stream_len,
            "ts":         "",
            "ts_created": "",
            "ts_modified": "",
            "ts_accessed": "",
            "ts_mft_change": "",
            "file_size_real": 0,
            "file_size_alloc": 0,
            "file_attributes": [],
            "name": "",
            "deleted": False,
        }

    stream_off = off + 16   # stream starts after the 16-byte entry header

    ts_created   = filetime_to_iso(struct.unpack_from("<Q", data, stream_off +  8)[0])
    ts_modified  = filetime_to_iso(struct.unpack_from("<Q", data, stream_off + 16)[0])
    ts_mft_chg   = filetime_to_iso(struct.unpack_from("<Q", data, stream_off + 24)[0])
    ts_accessed  = filetime_to_iso(struct.unpack_from("<Q", data, stream_off + 32)[0])

    alloc_size   = struct.unpack_from("<Q", data, stream_off + 40)[0]
    real_size    = struct.unpack_from("<Q", data, stream_off + 48)[0]
    file_attrs   = struct.unpack_from("<I", data, stream_off + 56)[0]

    name_len_chars = data[stream_off + 64] if stream_off + 64 < len(data) else 0
    # namespace at stream_off + 65
    name_off     = stream_off + 66
    name_raw     = data[name_off: name_off + name_len_chars * 2]
    try:
        name = name_raw.decode("utf-16-le", errors="replace").rstrip("\x00")
    except Exception:
        name = ""

    return {
        "ts":              ts_modified or ts_created,
        "ts_created":      ts_created,
        "ts_modified":     ts_modified,
        "ts_accessed":     ts_accessed,
        "ts_mft_change":   ts_mft_chg,
        "mft_number":      file_ref["mft_number"],
        "sequence":        file_ref["sequence"],
        "parent_mft":      parent_ref["mft_number"],
        "parent_sequence": parent_ref["sequence"],
        "name":            name,
        "file_size_real":  real_size,
        "file_size_alloc": alloc_size,
        "file_attributes": _parse_file_attributes(file_attrs),
        "file_attrs_raw":  file_attrs,
        "entry_len":       entry_len,
        "deleted":         False,   # will be set later by live FS comparison
    }


def _parse_indx_block(block: bytes, block_number: int = 0) -> tuple:
    """
    Parse one 4096-byte INDX block.
    Returns (active_entries, slack_entries).
    active_entries: entries in the active portion of the index
    slack_entries:  entries found in slack space after the active end
    """
    if len(block) < 40 or block[:4] != INDX_SIG:
        return [], []

    usa_off   = struct.unpack_from("<H", block, 4)[0]
    usa_count = struct.unpack_from("<H", block, 6)[0]

    block = _apply_usa(block, usa_off, usa_count)

    # Index node header at offset 24
    entries_off    = struct.unpack_from("<I", block, 24)[0]   # relative to offset 24
    entries_end    = struct.unpack_from("<I", block, 28)[0]   # relative to offset 24
    entries_alloc  = struct.unpack_from("<I", block, 32)[0]   # relative to offset 24

    base_off   = 24
    start_off  = base_off + entries_off
    end_off    = base_off + entries_end
    alloc_end  = base_off + entries_alloc

    active_entries = []
    slack_entries  = []

    # ── Parse active entries ──────────────────────────────────────────────────
    off = start_off
    while off < end_off and off < len(block):
        entry = _parse_index_entry(block, off)
        if entry is None:
            # End-of-entries marker; everything after this in the allocated
            # space (up to entries_alloc) is slack
            break
        if entry.get("name"):
            active_entries.append(entry)
        entry_len = entry.get("entry_len", 0)
        if entry_len < 16:
            break
        off += entry_len

    # ── Parse slack space ─────────────────────────────────────────────────────
    # Slack = bytes from end_off to alloc_end
    slack_off = end_off + 8   # skip past the end marker (8 bytes)
    while slack_off < alloc_end and slack_off < len(block):
        entry = _parse_index_entry(block, slack_off)
        if entry is None or not entry.get("name"):
            slack_off += 8
            continue
        entry["deleted"] = True   # presumed deleted (in slack)
        slack_entries.append(entry)
        entry_len = entry.get("entry_len", 0)
        if entry_len < 16:
            slack_off += 8
        else:
            slack_off += entry_len

    return active_entries, slack_entries


def _live_extract_i30_windows(target_dir: str) -> bytes:
    """
    On Windows: use CreateFile with GENERIC_READ + FILE_FLAG_BACKUP_SEMANTICS
    and DeviceIoControl FSCTL_GET_NTFS_FILE_RECORD to read the $I30 stream.
    Falls back to a direct read of \\\\?\\<dir>\\$I30 which works with
    BACKUP_READ on some configurations.

    Returns raw bytes of the $INDEX_ALLOCATION attribute data, or b''.
    """
    if sys.platform != "win32":
        return b""

    try:
        kernel32 = ctypes.windll.kernel32

        GENERIC_READ             = 0x80000000
        FILE_SHARE_READ          = 0x00000001
        FILE_SHARE_WRITE         = 0x00000002
        OPEN_EXISTING            = 3
        FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

        h = kernel32.CreateFileW(
            target_dir,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        INVALID_HANDLE = -1
        if h == INVALID_HANDLE:
            return b""

        # Try BackupRead to stream $I30
        BUFFER_SIZE = 1 << 20   # 1 MiB
        buf         = ctypes.create_string_buffer(BUFFER_SIZE)
        bytes_read  = ctypes.c_ulong(0)
        ctx         = ctypes.c_void_p(0)
        data        = bytearray()

        while True:
            ok = kernel32.BackupRead(
                h, buf, BUFFER_SIZE, ctypes.byref(bytes_read), 0, 0,
                ctypes.byref(ctx)
            )
            if not ok or bytes_read.value == 0:
                break
            chunk = bytes(buf[:bytes_read.value])
            # Look for INDX signatures in chunk
            for i in range(0, len(chunk) - 4, 512):
                if chunk[i:i+4] == INDX_SIG:
                    data.extend(chunk[i: i + INDX_BLOCK_SIZE])
            if bytes_read.value < BUFFER_SIZE:
                break

        kernel32.BackupRead(h, None, 0, None, 1, 0, ctypes.byref(ctx))
        kernel32.CloseHandle(h)
        return bytes(data)
    except Exception:
        return b""


def parse_i30_file(path: Path) -> list:
    """
    Parse a raw $I30 / INDX dump file.
    Returns a combined list of active + slack entries.
    """
    try:
        raw = open(path, "rb").read()
    except OSError:
        return []

    all_active = []
    all_slack  = []

    # Walk through the file in INDX_BLOCK_SIZE chunks
    for block_no in range(0, len(raw) // INDX_BLOCK_SIZE):
        off   = block_no * INDX_BLOCK_SIZE
        block = raw[off: off + INDX_BLOCK_SIZE]
        if len(block) < INDX_BLOCK_SIZE:
            break
        active, slack = _parse_indx_block(block, block_no)
        all_active.extend(active)
        all_slack.extend(slack)

    # Cross-reference: if a slack entry's MFT number is also in active entries,
    # it's NOT deleted.  If it's only in slack, mark deleted=True.
    active_mfts = {e["mft_number"] for e in all_active if e.get("mft_number")}
    for e in all_slack:
        if e.get("mft_number") in active_mfts:
            e["deleted"] = False

    return all_active + all_slack


def _live_check_deleted(entries: list, base_dir: str) -> list:
    """
    On Windows, check if each entry's file still exists in the live filesystem.
    Sets deleted=True for entries whose files can't be found.
    """
    if sys.platform != "win32" or not base_dir:
        return entries

    for e in entries:
        name = e.get("name", "")
        if not name:
            continue
        full_path = os.path.join(base_dir, name)
        try:
            exists = os.path.exists(full_path)
        except Exception:
            exists = False
        if not exists:
            e["deleted"] = True

    return entries


def run(evidence_dir: Path) -> dict:
    evidence_dir = Path(evidence_dir)
    i30_dir      = evidence_dir / "i30"

    records = []

    if i30_dir.is_dir():
        # Parse collected raw dump files
        dump_files = (
            list(i30_dir.glob("*.i30"))  +
            list(i30_dir.glob("*.I30"))  +
            list(i30_dir.glob("*.indx")) +
            list(i30_dir.glob("*.INDX")) +
            list(i30_dir.glob("*.bin"))
        )
        for f in sorted(dump_files):
            entries = parse_i30_file(f)
            for e in entries:
                e["source_dump"] = f.name
            records.extend(entries)
    else:
        i30_dir.mkdir(exist_ok=True)

    # Live extraction on Windows if no dump files found
    if not records and sys.platform == "win32":
        # Attempt to read System32 directory $I30 as a representative example
        target_dirs = [
            "C:\\Windows\\System32",
            "C:\\Users",
            "C:\\Temp",
        ]
        for td in target_dirs:
            raw = _live_extract_i30_windows(td)
            if raw and len(raw) >= INDX_BLOCK_SIZE:
                # Save the dump for reproducibility
                dump_path = i30_dir / (td.replace("\\", "_").replace(":", "") + ".i30")
                try:
                    with open(dump_path, "wb") as fh:
                        fh.write(raw)
                except Exception:
                    pass

                entries = parse_i30_file(dump_path if dump_path.exists() else Path("/dev/null"))
                if not entries:
                    # Parse raw directly
                    for block_no in range(len(raw) // INDX_BLOCK_SIZE):
                        off   = block_no * INDX_BLOCK_SIZE
                        block = raw[off: off + INDX_BLOCK_SIZE]
                        active, slack = _parse_indx_block(block, block_no)
                        for e in active + slack:
                            e["source_dir"] = td
                        entries.extend(active + slack)

                entries = _live_check_deleted(entries, td)
                for e in entries:
                    e.setdefault("source_dir", td)
                records.extend(entries)

    if not records:
        records = [{
            "ts":     "",
            "note":   "no_i30_dumps_found",
            "status": "requires_disk_image_or_windows_live_mode",
        }]

    envelope = make_envelope(
        artifact     = "i30",
        parser       = "i30_parser",
        source_file  = i30_dir,
        records      = records,
        evidence_dir = evidence_dir,
    )
    envelope["source_file"]   = "i30/"
    envelope["source_sha256"] = "directory"

    out_path = parsed_output_path(evidence_dir, "i30")
    write_envelope(envelope, out_path)

    return {
        "record_count": len(records),
        "_output_file": str(out_path),
        "_status":      "ok",
    }


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="JOCKY $I30 Parser")
    ap.add_argument("--evidence-dir", required=True)
    args = ap.parse_args()
    result = run(Path(args.evidence_dir))
    print(json.dumps(result, indent=2))
