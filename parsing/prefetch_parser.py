"""
JOCKY Prefetch Parser — parses Windows Prefetch files (.pf).

Handles:
  - Windows XP/Vista/7 (version 17/23): uncompressed
  - Windows 8/8.1     (version 26):     MAM (LZXPRESS Huffman) compressed
  - Windows 10/11     (version 30/31):  MAM compressed

LZXPRESS Huffman decompressor is implemented from scratch (no external deps).
If python-lzxpress is available it is used preferentially.

Format reference: libscca / ForensicArtifacts / libyal specification.
"""

import json
import os
import struct
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

from parsing._utils import (
    make_envelope, write_envelope, parsed_output_path, filetime_to_iso
)

# ────────────────────────────────────────────────────────────────────────────
# LZXPRESS Huffman decompressor (from scratch)
# ────────────────────────────────────────────────────────────────────────────
# MS-XCA / MS-WMCA LZXPRESS Huffman:
#   - 256-symbol Huffman tree rebuilt every 65536 bytes
#   - 512 bytes of Huffman table (256 symbols × 4-bit code lengths)
#   - Followed by Huffman-encoded data
#   - Matches: back-reference token encodes offset+length
#
# Reference: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-xca

def _build_huffman_tree(lengths: list) -> dict:
    """
    Build a canonical Huffman decode table from a list of code lengths.
    Returns a dict: bit-string → symbol.
    """
    # Count number of codes of each length
    max_len = max(lengths) if lengths else 0
    bl_count = [0] * (max_len + 1)
    for l in lengths:
        if l > 0:
            bl_count[l] += 1

    # Assign smallest codes for each length
    next_code = [0] * (max_len + 2)
    code = 0
    for bits in range(1, max_len + 1):
        code = (code + bl_count[bits - 1]) << 1
        next_code[bits] = code

    # Build symbol table: code_int → (code_len, symbol)
    table = {}
    for sym, l in enumerate(lengths):
        if l == 0:
            continue
        c = next_code[l]
        next_code[l] += 1
        table[(c, l)] = sym

    return table


class _BitReader:
    """Read bits LSB-first from a bytes buffer."""

    def __init__(self, data: bytes, offset: int):
        self._data   = data
        self._offset = offset   # byte offset
        self._buf    = 0        # bit buffer
        self._bits   = 0        # bits available

    def _fill(self):
        while self._bits <= 24 and self._offset + 1 < len(self._data):
            self._buf  |= self._data[self._offset] << self._bits
            self._bits += 8
            self._offset += 1

    def peek(self, n: int) -> int:
        self._fill()
        return self._buf & ((1 << n) - 1)

    def consume(self, n: int):
        self._buf  >>= n
        self._bits  -= n

    def read(self, n: int) -> int:
        v = self.peek(n)
        self.consume(n)
        return v

    @property
    def byte_offset(self) -> int:
        return self._offset


def _lzxpress_huffman_decompress_block(
    src: bytes, src_off: int, dst_size: int
) -> bytes:
    """
    Decompress one LZXPRESS Huffman block.
    src:      full compressed data buffer
    src_off:  offset of the 512-byte Huffman table
    dst_size: expected output size (max 65536)
    """
    # Read 512 bytes of code lengths: 256 symbols, 4 bits each, LE nibble order
    if src_off + 512 > len(src):
        raise ValueError("Truncated Huffman table")

    lengths = []
    for i in range(256):
        byte_val = src[src_off + i // 2]
        if i % 2 == 0:
            lengths.append(byte_val & 0x0F)
        else:
            lengths.append((byte_val >> 4) & 0x0F)

    # Build the decode table
    decode_table = _build_huffman_tree(lengths)
    max_code_len = max(lengths) if any(l > 0 for l in lengths) else 0

    bits = _BitReader(src, src_off + 512)
    output = bytearray()

    while len(output) < dst_size:
        # Decode one symbol by scanning all possible code lengths
        sym = None
        for cl in range(1, max_code_len + 1):
            candidate = bits.peek(cl)
            if (candidate, cl) in decode_table:
                sym = decode_table[(candidate, cl)]
                bits.consume(cl)
                break

        if sym is None:
            raise ValueError(f"Bad Huffman symbol at output pos {len(output)}")

        if sym < 256:
            # Literal byte
            output.append(sym)
        else:
            # Match token: sym 256..511
            # sym - 256 = length prefix (0..15) + 4-bit extra length fields
            match_sym = sym - 256
            length_prefix = match_sym & 0x0F
            offset_bits   = (match_sym >> 4) & 0x0F

            if length_prefix == 15:
                # Extended length: read additional nibble(s)
                extra = bits.read(4)
                length_prefix += extra
                if length_prefix == 15 + 15:
                    # Read full byte
                    extra2 = bits.read(8)
                    length_prefix += extra2
                    if length_prefix == 15 + 15 + 255:
                        # Read 16-bit value
                        length_prefix = bits.read(16)

            match_length = length_prefix + 3

            # Offset
            if offset_bits == 0:
                match_offset = bits.read(1)
            else:
                match_offset = bits.read(offset_bits) | (1 << offset_bits)
                match_offset -= 1

            match_offset += 1   # offset is negative from current position

            src_pos = len(output) - match_offset
            if src_pos < 0:
                raise ValueError(f"Invalid match offset {match_offset}")

            for k in range(match_length):
                if len(output) >= dst_size:
                    break
                output.append(output[src_pos + k])

    return bytes(output)


def _mam_decompress(data: bytes) -> bytes:
    """
    Decompress a MAM-compressed prefetch file.
    MAM header: signature 'MAM\x04' (4 bytes), decompressed_size (4 bytes LE).
    Remainder: LZXPRESS Huffman blocks of at most 65536 bytes each.
    """
    if data[:3] != b"MAM" or len(data) < 8:
        raise ValueError("Not a MAM stream")

    decompressed_size = struct.unpack_from("<I", data, 4)[0]
    output = bytearray()
    src_off = 8  # skip 8-byte MAM header

    while len(output) < decompressed_size:
        remaining = decompressed_size - len(output)
        block_out_size = min(65536, remaining)
        block = _lzxpress_huffman_decompress_block(data, src_off, block_out_size)
        output.extend(block)

        # Advance: 512 bytes table + compressed block bytes
        # We need to know how many compressed bytes the block consumed.
        # Easiest: measure via bit reader's byte_offset after block
        # Re-run to get offset (cheaper to track via secondary parse)
        # Simple approach: advance src_off to next 512-byte-aligned boundary
        # after consuming the block.  Actually the spec says blocks are
        # independent, so we need to walk each block to find its end.
        # We'll re-scan: build a lightweight scanner to measure block size.
        src_off = _measure_mam_block_end(data, src_off, block_out_size)

    return bytes(output)


def _measure_mam_block_end(src: bytes, src_off: int, dst_size: int) -> int:
    """Return the src byte offset just after the compressed block starting at src_off."""
    if src_off + 512 > len(src):
        return len(src)
    lengths = []
    for i in range(256):
        byte_val = src[src_off + i // 2]
        lengths.append(byte_val & 0x0F if i % 2 == 0 else (byte_val >> 4) & 0x0F)

    decode_table = _build_huffman_tree(lengths)
    max_code_len = max(lengths) if any(l > 0 for l in lengths) else 0
    if max_code_len == 0:
        return src_off + 512

    bits = _BitReader(src, src_off + 512)
    output_len = 0

    while output_len < dst_size:
        sym = None
        for cl in range(1, max_code_len + 1):
            candidate = bits.peek(cl)
            if (candidate, cl) in decode_table:
                sym = decode_table[(candidate, cl)]
                bits.consume(cl)
                break
        if sym is None:
            break

        if sym < 256:
            output_len += 1
        else:
            match_sym = sym - 256
            lp = match_sym & 0x0F
            ob = (match_sym >> 4) & 0x0F

            if lp == 15:
                extra = bits.read(4)
                lp += extra
                if lp == 15 + 15:
                    extra2 = bits.read(8)
                    lp += extra2
                    if lp == 15 + 15 + 255:
                        lp = bits.read(16)
            ml = lp + 3

            if ob == 0:
                bits.read(1)
            else:
                bits.read(ob)

            output_len += ml

    # bits._offset points to the next byte after what was consumed
    return bits.byte_offset


def _decompress_prefetch(data: bytes) -> bytes:
    """Decompress a prefetch file if MAM-compressed, else return as-is."""
    if data[:3] == b"MAM":
        try:
            import lzxpress
            decompressed_size = struct.unpack_from("<I", data, 4)[0]
            return lzxpress.decompress(data[8:], decompressed_size)
        except ImportError:
            pass
        return _mam_decompress(data)
    return data


# ────────────────────────────────────────────────────────────────────────────
# Prefetch binary format parser
# ────────────────────────────────────────────────────────────────────────────

def _parse_prefetch_v17(data: bytes) -> dict:
    """Parse a Windows XP/Vista/7 prefetch (version 17/23)."""
    # Header (84 bytes for v17, 240 for v23/v26 but same beginning)
    version = struct.unpack_from("<I", data, 0)[0]
    sig     = data[4:8]
    if sig != b"SCCA":
        raise ValueError(f"Invalid SCCA signature: {sig!r}")

    exec_name_raw = data[16:76]
    try:
        exec_name = exec_name_raw.decode("utf-16-le").rstrip("\x00")
    except Exception:
        exec_name = exec_name_raw.hex()

    pf_hash = struct.unpack_from("<I", data, 76)[0]

    # Version 17: run count at offset 80 (DWORD), last run time at offset 84 (QWORD)
    # Version 23: run count at offset 96 (DWORD), last 8 run times start at offset 44
    # Version 26/30/31: similar to v23

    run_count    = 0
    run_times_ft = []
    file_ref_off = 0
    file_ref_size = 0
    file_name_off = 0
    file_name_size = 0
    vol_info_off  = 0
    vol_info_size = 0
    vol_count     = 0

    if version == 17:
        run_count        = struct.unpack_from("<I", data, 80)[0]
        ft               = struct.unpack_from("<Q", data, 84)[0]
        run_times_ft     = [ft]
        file_ref_off     = struct.unpack_from("<I", data, 100)[0]
        file_ref_size    = struct.unpack_from("<I", data, 104)[0]
        file_name_off    = struct.unpack_from("<I", data, 108)[0]
        file_name_size   = struct.unpack_from("<I", data, 112)[0]
        vol_info_off     = struct.unpack_from("<I", data, 116)[0]
        vol_count        = struct.unpack_from("<I", data, 120)[0]
        vol_info_size    = struct.unpack_from("<I", data, 124)[0]

    elif version in (23, 26, 30, 31):
        # Last 8 run times: 8 × QWORD at offset 128 (for v23)
        # and offset 128 for v26/30/31
        base = 128
        for i in range(8):
            ft = struct.unpack_from("<Q", data, base + i * 8)[0]
            if ft:
                run_times_ft.append(ft)
        run_count        = struct.unpack_from("<I", data, base + 64)[0] if base + 64 + 4 <= len(data) else 0
        file_ref_off     = struct.unpack_from("<I", data, 100)[0]
        file_ref_size    = struct.unpack_from("<I", data, 104)[0]
        file_name_off    = struct.unpack_from("<I", data, 108)[0]
        file_name_size   = struct.unpack_from("<I", data, 112)[0]
        vol_info_off     = struct.unpack_from("<I", data, 116)[0]
        vol_count        = struct.unpack_from("<I", data, 120)[0]
        vol_info_size    = struct.unpack_from("<I", data, 124)[0]

    run_times_iso = [filetime_to_iso(ft) for ft in run_times_ft if ft]

    # File metrics (accessed files)
    accessed_files = []
    if file_name_off and file_name_size and file_name_off + file_name_size <= len(data):
        fname_blob = data[file_name_off: file_name_off + file_name_size]
        # Strings are separated by null terminators (UTF-16LE)
        pos = 0
        while pos < len(fname_blob) - 1:
            null = fname_blob.find(b"\x00\x00", pos)
            if null == -1:
                break
            # Align to even offset
            if null % 2 != 0:
                null += 1
            try:
                name = fname_blob[pos:null].decode("utf-16-le", errors="replace")
            except Exception:
                name = ""
            if name.strip():
                accessed_files.append(name)
            pos = null + 2

    # Volume device paths
    vol_paths = []
    if vol_info_off and vol_info_size and vol_count and vol_info_off + vol_info_size <= len(data):
        v_off = vol_info_off
        vol_entry_size = vol_info_size // max(vol_count, 1)
        for _ in range(vol_count):
            if v_off + 4 > len(data):
                break
            dev_off_rel  = struct.unpack_from("<I", data, v_off)[0]
            dev_len      = struct.unpack_from("<I", data, v_off + 4)[0] if v_off + 8 <= len(data) else 0
            dev_ft       = struct.unpack_from("<Q", data, v_off + 8)[0] if v_off + 16 <= len(data) else 0
            dev_serial   = struct.unpack_from("<I", data, v_off + 16)[0] if v_off + 20 <= len(data) else 0

            dev_path = ""
            abs_dev_off = vol_info_off + dev_off_rel
            if dev_len and abs_dev_off + dev_len * 2 <= len(data):
                try:
                    dev_path = data[abs_dev_off: abs_dev_off + dev_len * 2].decode(
                        "utf-16-le", errors="replace"
                    ).rstrip("\x00")
                except Exception:
                    pass

            vol_paths.append({
                "device_path":   dev_path,
                "creation_time": filetime_to_iso(dev_ft),
                "serial_number": f"{dev_serial:08X}",
            })
            v_off += vol_entry_size

    return {
        "version":         version,
        "executable_name": exec_name,
        "prefetch_hash":   f"{pf_hash:08X}",
        "run_count":       run_count,
        "last_run_times":  run_times_iso,
        "volumes":         vol_paths,
        "accessed_files":  accessed_files,
    }


def parse_prefetch_file(pf_path: Path) -> dict:
    """Parse a single .pf file. Returns a flat metadata dict."""
    raw = open(pf_path, "rb").read()
    data = _decompress_prefetch(raw)

    if len(data) < 84:
        return {"error": "file too small", "path": str(pf_path)}

    try:
        return _parse_prefetch_v17(data)
    except Exception as e:
        return {"error": str(e), "path": str(pf_path)}


def run(evidence_dir: Path) -> dict:
    evidence_dir = Path(evidence_dir)
    pf_dir       = evidence_dir / "prefetch"

    if not pf_dir.is_dir():
        return {"record_count": 0, "_output_file": "", "_status": "no_prefetch_dir"}

    pf_files = list(pf_dir.glob("*.pf")) + list(pf_dir.glob("*.PF"))
    if not pf_files:
        return {"record_count": 0, "_output_file": "", "_status": "no_pf_files"}

    records = []
    for pf_path in sorted(pf_files):
        info = parse_prefetch_file(pf_path)
        # Use the most recent run time as the ts
        ts = ""
        if info.get("last_run_times"):
            ts = info["last_run_times"][0]
        record = {
            "ts":              ts,
            "source_file":     pf_path.name,
            **info,
        }
        records.append(record)

    envelope = make_envelope(
        artifact     = "prefetch",
        parser       = "prefetch_parser",
        source_file  = pf_dir,
        records      = records,
        evidence_dir = evidence_dir,
    )
    # source_file for the whole directory
    envelope["source_file"]   = "prefetch/"
    envelope["source_sha256"] = "directory"

    out_path = parsed_output_path(evidence_dir, "prefetch")
    write_envelope(envelope, out_path)

    return {
        "record_count":  len(records),
        "_output_file":  str(out_path),
        "_status":       "ok",
    }


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="JOCKY Prefetch Parser")
    ap.add_argument("--evidence-dir", required=True)
    args = ap.parse_args()
    result = run(Path(args.evidence_dir))
    print(json.dumps(result, indent=2))
