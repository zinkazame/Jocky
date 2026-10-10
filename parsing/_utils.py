"""
JOCKY parsing utilities — shared helpers for all parsers.
No external deps; stdlib only.
"""

import hashlib
import json
import os
import struct
from datetime import datetime, timezone, timedelta
from pathlib import Path


# ─── Version constant ────────────────────────────────────────────────────────
JOCKY_VERSION = "1.0"

# ─── Windows FILETIME epoch: 1601-01-01 00:00:00 UTC ─────────────────────────
_WIN_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
# Chrome stores timestamps as microseconds since 1601-01-01 00:00:00 UTC
# (same as FILETIME but in microseconds not 100-ns intervals)

# ─── Unix epoch for comparison ────────────────────────────────────────────────
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def sha256_file(path: Path) -> str:
    """Return lowercase hex SHA-256 of a file, or 'error:<msg>' on failure."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(1 << 20)  # 1 MiB
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return f"error:{e}"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_envelope(artifact: str, parser: str, source_file: Path,
                  records: list, evidence_dir: Path = None) -> dict:
    """Build the standard JOCKY output envelope."""
    if evidence_dir and evidence_dir.is_dir():
        try:
            rel = source_file.relative_to(evidence_dir)
        except ValueError:
            rel = source_file
    else:
        rel = source_file

    return {
        "jocky_version":  JOCKY_VERSION,
        "artifact":       artifact,
        "parser":         parser,
        "parsed_at":      datetime.now(timezone.utc).isoformat(),
        "source_file":    str(rel),
        "source_sha256":  sha256_file(source_file),
        "record_count":   len(records),
        "records":        records,
    }


def write_envelope(envelope: dict, output_path: Path) -> Path:
    """Write envelope JSON to output_path, creating parent dirs. Returns path."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(envelope, fh, indent=2, default=str)
    return output_path


def filetime_to_iso(filetime_100ns: int) -> str:
    """
    Convert a Windows FILETIME (100-nanosecond intervals since 1601-01-01)
    to ISO-8601 string.  Returns '' on error / zero value.
    """
    if filetime_100ns <= 0:
        return ""
    try:
        dt = _WIN_EPOCH + timedelta(microseconds=filetime_100ns // 10)
        return dt.isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


def chrome_epoch_to_iso(chrome_us: int) -> str:
    """
    Convert Chrome timestamp (microseconds since 1601-01-01 UTC) to ISO-8601.
    Returns '' on error / zero value.
    """
    if chrome_us <= 0:
        return ""
    try:
        dt = _WIN_EPOCH + timedelta(microseconds=chrome_us)
        return dt.isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


def unix_ms_to_iso(unix_ms: int) -> str:
    """Convert Unix milliseconds epoch to ISO-8601."""
    if unix_ms <= 0:
        return ""
    try:
        dt = datetime.fromtimestamp(unix_ms / 1000.0, tz=timezone.utc)
        return dt.isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


def unix_us_to_iso(unix_us: int) -> str:
    """Convert Unix microseconds epoch to ISO-8601."""
    if unix_us <= 0:
        return ""
    try:
        dt = datetime.fromtimestamp(unix_us / 1_000_000.0, tz=timezone.utc)
        return dt.isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


def rot13(s: str) -> str:
    """ROT-13 decode/encode (symmetric)."""
    result = []
    for c in s:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(c)
    return "".join(result)


def read_u16le(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def read_u32le(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def read_u64le(data: bytes, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def read_u16be(data: bytes, off: int) -> int:
    return struct.unpack_from(">H", data, off)[0]


def read_u32be(data: bytes, off: int) -> int:
    return struct.unpack_from(">I", data, off)[0]


def read_utf16le(data: bytes, off: int, length_chars: int) -> str:
    """Read a UTF-16LE string of length_chars characters from data at offset."""
    raw = data[off: off + length_chars * 2]
    try:
        return raw.decode("utf-16-le").rstrip("\x00")
    except UnicodeDecodeError:
        return raw.hex()


def read_cstring(data: bytes, off: int, max_len: int = 512) -> str:
    """Read a null-terminated ASCII/UTF-8 string."""
    end = data.find(b"\x00", off, off + max_len)
    if end == -1:
        end = off + max_len
    try:
        return data[off:end].decode("utf-8", errors="replace")
    except Exception:
        return data[off:end].hex()


def parsed_output_path(evidence_dir: Path, artifact_name: str) -> Path:
    """Return the canonical output path: evidence_dir/parsed/<artifact_name>_parsed.json"""
    return evidence_dir / "parsed" / f"{artifact_name}_parsed.json"
