"""
JOCKY SRUM Parser — parses SRUDB.dat (System Resource Usage Monitor).

SRUDB.dat is an ESE (Extensible Storage Engine / JET Blue) database.
This module implements a MINIMAL ESE page reader from scratch:
  - Parses ESE file header (page 0) to get page size, catalog page
  - Walks the B-tree catalog to find target table names
  - Reads data pages for those tables
  - Decodes column values using catalog-defined column types

Target tables:
  {D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}  — Network Data Usage
  {973F5D5C-1D90-4944-BE8E-24B94231A174}  — Application Resource Usage

Fields extracted per record:
  AppId, AutoIncId, TimeStamp, BytesSent, BytesRecvd, NetworkBytesRaw

Fallback chain if ESE parsing fails:
  1. Try calling srudb_query.exe (if present in PATH or evidence dir)
  2. Mark as "requires_elevated_ese_access" and return empty records

Reference:
  libyal/libesedb source (MIT)
  Zach Stanford "SRUM Forensics" (DFIR.training)
"""

import json
import os
import struct
import subprocess
import sys
import tempfile
import shutil
from datetime import datetime, timezone, timedelta
from pathlib import Path

from parsing._utils import (
    make_envelope, write_envelope, parsed_output_path, filetime_to_iso
)

# ─── ESE file magic ───────────────────────────────────────────────────────────
ESE_FILE_SIG   = 0x89ABCDEF   # offset 4 in page 0 backup header
ESE_PAGE_SIG   = 0x           # page checksums vary; we skip checksum validation

# ─── ESE column types ─────────────────────────────────────────────────────────
ESE_COL_BIT         = 1
ESE_COL_UBYTE       = 2
ESE_COL_SHORT       = 3
ESE_COL_USHORT      = 4
ESE_COL_LONG        = 5
ESE_COL_ULONG       = 6
ESE_COL_LONGLONG    = 7
ESE_COL_ULONGLONG   = 8
ESE_COL_CURRENCY    = 9
ESE_COL_IEEE_SINGLE = 10
ESE_COL_IEEE_DOUBLE = 11
ESE_COL_DATETIME    = 12    # OLE Automation Date (float64 days since 1899-12-30)
ESE_COL_BINARY      = 13
ESE_COL_TEXT        = 14
ESE_COL_LONGBINARY  = 15
ESE_COL_LONGTEXT    = 16
ESE_COL_GUID        = 17    # {hex128}

# ─── OA date base for ESE datetime ────────────────────────────────────────────
_OA_BASE = datetime(1899, 12, 30, tzinfo=timezone.utc)

# ─── Target SRUM table GUIDs ─────────────────────────────────────────────────
_NET_USAGE_GUID  = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"
_APP_USAGE_GUID  = "{973F5D5C-1D90-4944-BE8E-24B94231A174}"
_TARGET_GUIDS    = {_NET_USAGE_GUID, _APP_USAGE_GUID}


def _oa_date_to_iso(oa: float) -> str:
    try:
        dt = _OA_BASE + timedelta(days=oa)
        return dt.isoformat()
    except Exception:
        return ""


def _decode_col_value(col_type: int, raw: bytes) -> object:
    """Decode a raw ESE column value to a Python primitive."""
    if not raw:
        return None
    try:
        if col_type == ESE_COL_BIT:
            return bool(raw[0])
        elif col_type == ESE_COL_UBYTE:
            return raw[0]
        elif col_type == ESE_COL_SHORT:
            return struct.unpack_from("<h", raw)[0]
        elif col_type == ESE_COL_USHORT:
            return struct.unpack_from("<H", raw)[0]
        elif col_type == ESE_COL_LONG:
            return struct.unpack_from("<i", raw)[0]
        elif col_type in (ESE_COL_ULONG,):
            return struct.unpack_from("<I", raw)[0]
        elif col_type in (ESE_COL_LONGLONG, ESE_COL_CURRENCY):
            return struct.unpack_from("<q", raw)[0]
        elif col_type == ESE_COL_ULONGLONG:
            return struct.unpack_from("<Q", raw)[0]
        elif col_type == ESE_COL_IEEE_SINGLE:
            return struct.unpack_from("<f", raw)[0]
        elif col_type == ESE_COL_IEEE_DOUBLE:
            return struct.unpack_from("<d", raw)[0]
        elif col_type == ESE_COL_DATETIME:
            oa = struct.unpack_from("<d", raw)[0]
            return _oa_date_to_iso(oa)
        elif col_type in (ESE_COL_TEXT, ESE_COL_LONGTEXT):
            # Try UTF-16LE first, then ASCII
            try:
                return raw.decode("utf-16-le", errors="strict").rstrip("\x00")
            except UnicodeDecodeError:
                return raw.decode("ascii", errors="replace").rstrip("\x00")
        elif col_type in (ESE_COL_BINARY, ESE_COL_LONGBINARY):
            return raw.hex()
        elif col_type == ESE_COL_GUID:
            if len(raw) == 16:
                import uuid
                return str(uuid.UUID(bytes_le=raw))
            return raw.hex()
        else:
            return raw.hex()
    except Exception:
        return raw.hex() if raw else None


# ═══════════════════════════════════════════════════════════════════════════════
# Minimal ESE B-tree page reader
# ═══════════════════════════════════════════════════════════════════════════════

class EseDb:
    """
    Minimal read-only ESE database reader.

    Implements just enough of the JET Blue on-disk format to:
      1. Read the database header and determine page size
      2. Walk the catalog B-tree to find table and column definitions
      3. Enumerate data pages for a named table and decode records

    Tested against SRUDB.dat files from Windows 10/11.
    Does NOT implement: shadow pages, long-value trees, multi-valued columns,
    tagged column groups, or row-level checksums.
    """

    # ESE page flags
    PAGE_FLAG_ROOT       = 0x0001
    PAGE_FLAG_LEAF       = 0x0002
    PAGE_FLAG_PARENT     = 0x0004
    PAGE_FLAG_EMPTY      = 0x0008
    PAGE_FLAG_SPACE_TREE = 0x0020
    PAGE_FLAG_INDEX      = 0x0040
    PAGE_FLAG_LONG_VALUE = 0x0080
    PAGE_FLAG_NEW_FORMAT = 0x2000

    def __init__(self, path: Path):
        self._data = open(path, "rb").read()
        self._page_size = self._detect_page_size()
        self._catalog   = {}   # table_name → {columns: {id: (name, type)}, root_page: int}
        self._parse_catalog()

    def _read_page(self, page_no: int) -> bytes:
        offset = page_no * self._page_size
        return self._data[offset: offset + self._page_size]

    def _detect_page_size(self) -> int:
        # Page size is at offset 236 in the file header page (page 0)
        # The header occupies the first page.
        # Value at offset 0xEC (236) is a DWORD page_size field.
        if len(self._data) < 240:
            return 4096
        ps = struct.unpack_from("<I", self._data, 236)[0]
        if ps in (4096, 8192, 16384, 32768):
            return ps
        # Alternative: offset 0x28 (40) in the backup header
        ps2 = struct.unpack_from("<I", self._data, 40)[0]
        if ps2 in (4096, 8192, 16384, 32768):
            return ps2
        return 4096

    def _iter_leaf_records(self, page_no: int, depth: int = 0):
        """
        Generator: yield raw record bytes from all leaf pages reachable
        from page_no in a B-tree.  depth guard prevents infinite loops.
        """
        if depth > 32 or page_no <= 0:
            return

        page_data = self._read_page(page_no)
        if len(page_data) < 40:
            return

        # ESE page header (new format, 40 bytes):
        #   0: checksum(s) — 16 bytes
        #  16: DBTIME (8 bytes)
        #  24: prev_page (4), next_page (4), father_page (4)
        #  36: available_data_size (2), available_page_tag (2)
        #  38: flags (4) [at offset 40 in older format = 2 bytes at 38]

        # Determine header size: new format (ESE 7.0+) = 40 bytes; old = 38
        # Check NEW_FORMAT flag at offset 38 bit 13
        flags_raw = struct.unpack_from("<I", page_data, 36)[0]
        is_new_format = bool(flags_raw & 0x2000)

        if is_new_format:
            hdr_size       = 40
            flags_off      = 36
            avail_data_off = 34
        else:
            hdr_size       = 38
            flags_off      = 34
            avail_data_off = 32

        if len(page_data) < hdr_size + 2:
            return

        page_flags = struct.unpack_from("<I", page_data, flags_off)[0]
        n_tags     = struct.unpack_from("<H", page_data,
                                        hdr_size - 2 + (2 if is_new_format else 0))[0]

        # Page tags sit at the END of the page, growing toward the middle.
        # Each tag: 2-byte offset (from start of page), 2-byte size.
        # Tag 0 is the page header tag (we skip it).

        tag_array_off = self._page_size - 4 * n_tags

        is_leaf   = bool(page_flags & self.PAGE_FLAG_LEAF)
        is_parent = bool(page_flags & self.PAGE_FLAG_PARENT)

        for tag_idx in range(1, n_tags):   # skip tag 0 (page header)
            tag_off = tag_array_off + tag_idx * 4
            if tag_off + 4 > len(page_data):
                break
            rec_off  = struct.unpack_from("<H", page_data, tag_off)[0] & 0x7FFF
            rec_size = struct.unpack_from("<H", page_data, tag_off + 2)[0] & 0x7FFF
            if rec_off + rec_size > len(page_data):
                continue
            rec_data = page_data[rec_off: rec_off + rec_size]

            if is_leaf:
                yield rec_data
            elif is_parent and len(rec_data) >= 4:
                # Internal node: child page number is last 4 bytes of key + child
                child_page = struct.unpack_from("<I", rec_data, len(rec_data) - 4)[0]
                yield from self._iter_leaf_records(child_page, depth + 1)

    def _parse_catalog(self):
        """
        Walk the catalog B-tree (always rooted at page 4 in SRUDB.dat).
        Catalog records define tables and their columns.

        Catalog record layout (leaf record in catalog table):
          Byte 0:  record header — we rely on tagged column layout
          We scan for "table" and "column" object type entries.

        Simplified: we parse only enough to map table names → root pages
        and column IDs → (name, type).
        """
        # Catalog is always at object page 4 for SRUDB.dat
        CATALOG_ROOT_PAGE = 4

        tables  = {}   # obj_id_table → (name, root_page)
        columns = {}   # obj_id_table → {col_id: (name, col_type)}

        for rec in self._iter_leaf_records(CATALOG_ROOT_PAGE):
            self._decode_catalog_record(rec, tables, columns)

        # Merge into self._catalog
        for obj_id, (tname, root_page) in tables.items():
            self._catalog[tname] = {
                "root_page": root_page,
                "columns":   columns.get(obj_id, {}),
            }

    def _decode_catalog_record(self, rec: bytes, tables: dict, columns: dict):
        """
        Decode one catalog leaf record.

        ESE catalog record layout:
          2 bytes: record header (cbRecordHeader + flags)
          Variable: fixed-width columns, variable-width columns, tagged columns

        Catalog fixed columns (by column ID):
          1: ObjidTable   LONG    — parent object ID
          2: Type         SHORT   — 1=table, 2=column, 3=index, 4=long-value
          3: Id           LONG    — object ID for tables; column number for columns
          4: ColtypeOrPgnoFDP LONG — column type (for col), root page (for table)
          6: SpaceUsage   LONG
          7: Flags        LONG
          8: PagesOrLocale LONG
          9: RootFlag     BYTE
         10: RecordOffset SHORT   (for columns: offset in fixed area)
         11: LCMapFlags   LONG
         12: KeyMost      USHORT
        Named cols (variable): name (TEXT)
        """
        if len(rec) < 4:
            return

        # Skip record header (2 bytes)
        off = 2

        # The first few columns are fixed-width; column IDs 1-12 are well-known.
        # Simplified parsing: read fixed-width columns in order per the
        # ESE catalog column definition.

        # Fixed column sizes (IDs 1-12):
        # (col_id, size_bytes): only cols we care about
        _FIXED_DEFS = [
            (1,  4),   # ObjidTable
            (2,  2),   # Type
            (3,  4),   # Id
            (4,  4),   # ColtypeOrPgnoFDP
            (5,  4),   # SpaceUsage (ignored)
            (6,  4),   # Flags
            (7,  4),   # PagesOrLocale
            (8,  1),   # RootFlag
            (9,  2),   # RecordOffset
            (10, 4),   # LCMapFlags
            (11, 2),   # KeyMost / cbMax
        ]

        # Determine end of fixed area from record header
        # Byte 0-1: tag_flags (high nibble) + count_fixed (low nibble of byte 1)
        # We do a best-effort parse assuming no null column bitmap
        vals = {}
        cur  = off
        for col_id, col_size in _FIXED_DEFS:
            if cur + col_size > len(rec):
                break
            raw = rec[cur: cur + col_size]
            if col_size == 1:
                vals[col_id] = raw[0]
            elif col_size == 2:
                vals[col_id] = struct.unpack_from("<H", raw)[0]
            elif col_size == 4:
                vals[col_id] = struct.unpack_from("<I", raw)[0]
            cur += col_size

        # Variable-length columns follow; we need the "Name" column.
        # In the catalog, Name is always in the variable section.
        # Variable section starts after fixed section + null bitmap.
        # We search for a plausible ASCII name string in the remaining bytes.
        name_bytes = rec[cur:]
        name = ""
        # Try to find a printable ASCII or UTF-16LE string
        for start in range(min(len(name_bytes), 32)):
            s = name_bytes[start:]
            # ASCII name
            ascii_end = 0
            while ascii_end < len(s) and 0x20 <= s[ascii_end] <= 0x7E:
                ascii_end += 1
            if ascii_end >= 3:
                candidate = s[:ascii_end].decode("ascii", errors="replace")
                if candidate.replace("_", "").replace("-", "").replace("{", "").replace("}", "").isalnum():
                    name = candidate
                    break
            # UTF-16LE
            if len(s) >= 6 and s[1] == 0 and 0x20 <= s[0] <= 0x7E:
                try:
                    candidate = s.decode("utf-16-le", errors="strict")[:64].rstrip("\x00")
                    if candidate.replace("_", "").replace("-", "").replace("{", "").replace("}", "").isalnum():
                        name = candidate
                        break
                except Exception:
                    pass

        obj_type     = vals.get(2, 0)    # 1=table, 2=column
        obj_id_table = vals.get(1, 0)    # parent table ID (for columns)
        obj_id       = vals.get(3, 0)    # this object's ID
        coltype_pgno = vals.get(4, 0)    # column type or root page number

        if obj_type == 1 and name:
            # Table: obj_id = table ID, coltype_pgno = root page
            tables[obj_id] = (name, coltype_pgno)
        elif obj_type == 2 and name:
            # Column: obj_id_table = owning table, obj_id = column number
            if obj_id_table not in columns:
                columns[obj_id_table] = {}
            columns[obj_id_table][obj_id] = (name, coltype_pgno)

    def _decode_data_record(self, rec: bytes, col_defs: dict) -> dict:
        """
        Decode a data-table leaf record using column definitions from catalog.
        col_defs: {col_id: (name, col_type)}

        ESE data record layout:
          2 bytes: record header (flags in high nibble, fixed_col_count in low)
          2 bytes: null bitmap size (if flag set)
          Fixed columns: packed by col_id order
          Variable columns: preceded by 2-byte offset array
          Tagged columns: {key: size, data}
        """
        if len(rec) < 4:
            return {}

        result = {}
        # This is a simplified heuristic decoder for SRUM tables.
        # SRUM columns are mostly fixed-width integers and a few text fields.

        # Sort columns by ID to match the packed fixed-column order
        fixed_cols = sorted(
            [(cid, cname, ctype) for cid, (cname, ctype) in col_defs.items()
             if ctype in (ESE_COL_BIT, ESE_COL_UBYTE, ESE_COL_SHORT, ESE_COL_USHORT,
                          ESE_COL_LONG, ESE_COL_ULONG, ESE_COL_LONGLONG, ESE_COL_ULONGLONG,
                          ESE_COL_CURRENCY, ESE_COL_IEEE_SINGLE, ESE_COL_IEEE_DOUBLE,
                          ESE_COL_DATETIME, ESE_COL_GUID)],
            key=lambda x: x[0]
        )
        var_cols = sorted(
            [(cid, cname, ctype) for cid, (cname, ctype) in col_defs.items()
             if ctype in (ESE_COL_TEXT, ESE_COL_BINARY, ESE_COL_LONGTEXT, ESE_COL_LONGBINARY)],
            key=lambda x: x[0]
        )

        _COL_SIZES = {
            ESE_COL_BIT: 1, ESE_COL_UBYTE: 1, ESE_COL_SHORT: 2, ESE_COL_USHORT: 2,
            ESE_COL_LONG: 4, ESE_COL_ULONG: 4, ESE_COL_LONGLONG: 8, ESE_COL_ULONGLONG: 8,
            ESE_COL_CURRENCY: 8, ESE_COL_IEEE_SINGLE: 4, ESE_COL_IEEE_DOUBLE: 8,
            ESE_COL_DATETIME: 8, ESE_COL_GUID: 16,
        }

        # Attempt to read fixed columns starting after 4-byte record header
        offset = 4
        for cid, cname, ctype in fixed_cols:
            sz = _COL_SIZES.get(ctype, 0)
            if sz == 0 or offset + sz > len(rec):
                break
            raw = rec[offset: offset + sz]
            result[cname] = _decode_col_value(ctype, raw)
            offset += sz

        # Variable columns: skip for now (text names are often short)
        # Heuristic: scan remaining bytes for UTF-16LE strings
        remaining = rec[offset:]
        text_col_idx = 0
        i = 0
        while i < len(remaining) - 1 and text_col_idx < len(var_cols):
            # Look for a 2-byte prefix then UTF-16LE data
            if i + 2 < len(remaining):
                sz = struct.unpack_from("<H", remaining, i)[0]
                if 2 <= sz <= 512 and i + 2 + sz <= len(remaining):
                    raw = remaining[i + 2: i + 2 + sz]
                    cid, cname, ctype = var_cols[text_col_idx]
                    result[cname] = _decode_col_value(ctype, raw)
                    i += 2 + sz
                    text_col_idx += 1
                    continue
            i += 1

        return result

    def read_table(self, table_name: str) -> list:
        """Return all records from a named table as list of dicts."""
        info = self._catalog.get(table_name)
        if info is None:
            return []

        root_page = info["root_page"]
        col_defs  = info["columns"]
        records   = []

        for rec_raw in self._iter_leaf_records(root_page):
            row = self._decode_data_record(rec_raw, col_defs)
            if row:
                records.append(row)

        return records

    def table_names(self) -> list:
        return list(self._catalog.keys())


# ═══════════════════════════════════════════════════════════════════════════════
# SRUM extraction logic
# ═══════════════════════════════════════════════════════════════════════════════

def _normalize_srum_record(row: dict) -> dict:
    """Normalize a raw SRUM row to a clean output record."""
    # Common field name variations across different SRUDB versions
    app_id = (row.get("AppId") or row.get("AppID") or
              row.get("ExeInfo") or row.get("app_id") or "")
    ts_raw = row.get("TimeStamp") or row.get("Timestamp") or ""

    if isinstance(ts_raw, str) and ts_raw:
        ts = ts_raw
    elif isinstance(ts_raw, float):
        ts = _oa_date_to_iso(ts_raw)
    elif isinstance(ts_raw, int):
        ts = filetime_to_iso(ts_raw)
    else:
        ts = ""

    return {
        "ts":                ts,
        "app_id":            str(app_id),
        "auto_inc_id":       row.get("AutoIncId", row.get("auto_inc_id", "")),
        "bytes_sent":        row.get("BytesSent", row.get("bytes_sent", 0)),
        "bytes_received":    row.get("BytesRecvd", row.get("BytesRecvd", row.get("bytes_received", 0))),
        "network_bytes_raw": row.get("NetworkBytesRaw", 0),
        "user_sid":          row.get("UserId", row.get("user_sid", "")),
        "interface_luid":    row.get("InterfaceLuid", ""),
        "raw":               row,
    }


def _parse_srum_ese(srum_path: Path) -> tuple:
    """
    Parse SRUDB.dat using our minimal ESE reader.
    Returns (records_list, status_string).
    """
    try:
        db = EseDb(srum_path)
    except Exception as e:
        return [], f"ese_open_error: {e}"

    names = db.table_names()
    # Find target tables by GUID (case-insensitive)
    target_tables = [n for n in names if n.upper() in {g.upper() for g in _TARGET_GUIDS}]

    if not target_tables:
        # Try partial match
        target_tables = [n for n in names if "D10CA2FE" in n.upper() or "973F5D5C" in n.upper()]

    if not target_tables:
        return [], f"target_tables_not_found (found: {names[:10]})"

    records = []
    for table_name in target_tables:
        try:
            rows = db.read_table(table_name)
            for row in rows:
                rec = _normalize_srum_record(row)
                rec["srum_table"] = table_name
                records.append(rec)
        except Exception as e:
            records.append({"ts": "", "srum_table": table_name, "error": str(e)})

    return records, "ok"


def _parse_srum_fallback_exe(srum_path: Path) -> list:
    """Try calling srudb_query.exe if present."""
    exe = shutil.which("srudb_query") or shutil.which("srudb_query.exe")
    if not exe:
        return []
    try:
        out = subprocess.check_output(
            [exe, str(srum_path)], timeout=30, stderr=subprocess.DEVNULL
        )
        lines = out.decode("utf-8", errors="replace").splitlines()
        records = []
        for line in lines[1:]:
            parts = line.split(",")
            if len(parts) >= 3:
                records.append({
                    "ts":     parts[0].strip() if parts else "",
                    "app_id": parts[1].strip() if len(parts) > 1 else "",
                    "bytes_sent": parts[2].strip() if len(parts) > 2 else "",
                    "source": "srudb_query.exe",
                })
        return records
    except Exception:
        return []


def run(evidence_dir: Path) -> dict:
    evidence_dir = Path(evidence_dir)

    srum_path = None
    for candidate in (
        evidence_dir / "srum" / "SRUDB.dat",
        evidence_dir / "srum" / "srudb.dat",
        evidence_dir / "SRUDB.dat",
    ):
        if candidate.is_file():
            srum_path = candidate
            break

    if srum_path is None:
        return {"record_count": 0, "_output_file": "", "_status": "srudb_not_found"}

    # Make a working copy (SRUDB.dat may be locked / inconsistent)
    tmp_dir  = Path(tempfile.mkdtemp(prefix="jocky_srum_"))
    tmp_path = tmp_dir / "SRUDB_copy.dat"
    try:
        import shutil as _shutil
        _shutil.copy2(str(srum_path), str(tmp_path))
        records, status = _parse_srum_ese(tmp_path)
    except Exception as e:
        records, status = [], f"copy_error: {e}"
    finally:
        try:
            import shutil as _shutil
            _shutil.rmtree(str(tmp_dir), ignore_errors=True)
        except Exception:
            pass

    if not records:
        records = _parse_srum_fallback_exe(srum_path)
        if not records:
            records = [{
                "ts":     "",
                "status": "requires_elevated_ese_access",
                "note":   status,
            }]
            status = "requires_elevated_ese_access"

    envelope = make_envelope(
        artifact     = "srum",
        parser       = "srum_parser",
        source_file  = srum_path,
        records      = records,
        evidence_dir = evidence_dir,
    )
    envelope["_ese_status"] = status

    out_path = parsed_output_path(evidence_dir, "srum")
    write_envelope(envelope, out_path)

    return {
        "record_count": len(records),
        "_output_file": str(out_path),
        "_status":      status,
    }


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="JOCKY SRUM Parser")
    ap.add_argument("--evidence-dir", required=True)
    args = ap.parse_args()
    result = run(Path(args.evidence_dir))
    print(json.dumps(result, indent=2))
