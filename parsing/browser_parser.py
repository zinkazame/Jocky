"""
JOCKY Browser History Parser — Chrome, Edge, Firefox.

Inputs (collected by JOCKY_acquire_browser_history):
  evidence/<ts>/browser/chrome_history      — Chrome History SQLite
  evidence/<ts>/browser/chrome_cookies      — Chrome Cookies SQLite
  evidence/<ts>/browser/edge_history        — Edge History SQLite
  evidence/<ts>/browser/firefox_places      — Firefox places.sqlite

Chrome/Edge History: urls + visits JOIN
Chrome/Edge Cookies: cookies table
Firefox: moz_places + moz_historyvisits JOIN

Chrome epoch: microseconds since 1601-01-01 00:00:00 UTC (same as Windows FILETIME)
All timestamps converted to ISO-8601.

Suspicious flag: URL matches known exfiltration domains.
"""

import json
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

from parsing._utils import (
    make_envelope, write_envelope, parsed_output_path, chrome_epoch_to_iso, unix_us_to_iso
)

# ─── Known exfiltration domains ───────────────────────────────────────────────
_EXFIL_DOMAINS = {
    "pastebin.com",
    "transfer.sh",
    "anonfiles.com",
    "wetransfer.com",
    "mega.nz",
    "gofile.io",
    "file.io",
    "0x0.st",
    "pixeldrain.com",
    "anonymfile.com",
    "ufile.io",
    "sendspace.com",
    "filedropper.com",
    "justpaste.it",
    "ghostbin.co",
    "hastebin.com",
    "termbin.com",
    "sprunge.us",
    "ix.io",
}


def _is_suspicious_url(url: str) -> bool:
    if not url:
        return False
    url_lower = url.lower()
    for domain in _EXFIL_DOMAINS:
        if domain in url_lower:
            return True
    return False


def _safe_sqlite_copy(src: Path) -> Path:
    """
    Copy a SQLite file to a temp location so we can open it
    even if the original is locked (Chrome running).
    Returns the temp path; caller must delete it.
    """
    tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
    tmp.close()
    try:
        shutil.copy2(str(src), tmp.name)
        # Also copy WAL and SHM files if present
        for ext in ("-wal", "-shm"):
            wal = Path(str(src) + ext)
            if wal.is_file():
                shutil.copy2(str(wal), tmp.name + ext)
    except Exception:
        pass
    return Path(tmp.name)


def _open_sqlite(path: Path):
    """Open a SQLite connection in read-only mode with timeout."""
    tmp_path = _safe_sqlite_copy(path)
    uri = f"file:{tmp_path}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
        return conn, tmp_path
    except Exception as e:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        raise e


def _cleanup_tmp(tmp_path: Path):
    for ext in ("", "-wal", "-shm"):
        p = Path(str(tmp_path) + ext)
        try:
            os.unlink(str(p))
        except Exception:
            pass


# ─── Chrome / Edge History ────────────────────────────────────────────────────

_CHROME_HISTORY_SQL = """
SELECT
    u.url,
    u.title,
    u.visit_count,
    u.last_visit_time,
    u.typed_count,
    v.visit_time,
    v.from_visit,
    v.transition
FROM urls u
JOIN visits v ON u.id = v.url
ORDER BY v.visit_time DESC
"""

_CHROME_HISTORY_SQL_SIMPLE = """
SELECT url, title, visit_count, last_visit_time, typed_count
FROM urls
ORDER BY last_visit_time DESC
"""


def _parse_chrome_history(path: Path, browser: str) -> list:
    records = []
    conn = None
    tmp_path = None
    try:
        conn, tmp_path = _open_sqlite(path)
        cur = conn.cursor()

        try:
            cur.execute(_CHROME_HISTORY_SQL)
            rows = cur.fetchall()
            for row in rows:
                ts = chrome_epoch_to_iso(row["visit_time"]) if row["visit_time"] else ""
                url = row["url"] or ""
                records.append({
                    "ts":            ts,
                    "url":           url,
                    "title":         row["title"] or "",
                    "visit_count":   row["visit_count"] or 0,
                    "last_visit_ts": chrome_epoch_to_iso(row["last_visit_time"]),
                    "typed_count":   row["typed_count"] or 0,
                    "transition":    row["transition"] if "transition" in row.keys() else "",
                    "browser":       browser,
                    "suspicious":    _is_suspicious_url(url),
                })
        except sqlite3.OperationalError:
            # Try simple query without visits join
            cur.execute(_CHROME_HISTORY_SQL_SIMPLE)
            for row in cur.fetchall():
                url = row["url"] or ""
                records.append({
                    "ts":            chrome_epoch_to_iso(row["last_visit_time"]),
                    "url":           url,
                    "title":         row["title"] or "",
                    "visit_count":   row["visit_count"] or 0,
                    "browser":       browser,
                    "suspicious":    _is_suspicious_url(url),
                })
    except Exception as e:
        records.append({"ts": "", "error": str(e), "browser": browser})
    finally:
        if conn:
            conn.close()
        if tmp_path:
            _cleanup_tmp(tmp_path)

    return records


# ─── Chrome / Edge Cookies ────────────────────────────────────────────────────

_CHROME_COOKIES_SQL = """
SELECT
    host_key,
    name,
    path,
    expires_utc,
    last_access_utc,
    is_secure,
    is_httponly,
    samesite
FROM cookies
ORDER BY last_access_utc DESC
"""

_CHROME_COOKIES_SQL_SIMPLE = """
SELECT host_key, name, path, expires_utc, last_access_utc, is_secure, is_httponly
FROM cookies
ORDER BY last_access_utc DESC
"""


def _parse_chrome_cookies(path: Path, browser: str) -> list:
    records = []
    conn = None
    tmp_path = None
    try:
        conn, tmp_path = _open_sqlite(path)
        cur = conn.cursor()

        try:
            cur.execute(_CHROME_COOKIES_SQL)
        except sqlite3.OperationalError:
            cur.execute(_CHROME_COOKIES_SQL_SIMPLE)

        for row in cur.fetchall():
            records.append({
                "ts":              chrome_epoch_to_iso(row["last_access_utc"]),
                "host":            row["host_key"] or "",
                "name":            row["name"] or "",
                "path":            row["path"] or "",
                "expires_ts":      chrome_epoch_to_iso(row["expires_utc"]),
                "last_access_ts":  chrome_epoch_to_iso(row["last_access_utc"]),
                "is_secure":       bool(row["is_secure"]),
                "is_httponly":     bool(row["is_httponly"]),
                "samesite":        row["samesite"] if "samesite" in row.keys() else "",
                "browser":         browser,
                "suspicious":      _is_suspicious_url(row["host_key"] or ""),
            })
    except Exception as e:
        records.append({"ts": "", "error": str(e), "browser": browser})
    finally:
        if conn:
            conn.close()
        if tmp_path:
            _cleanup_tmp(tmp_path)

    return records


# ─── Firefox places.sqlite ────────────────────────────────────────────────────

_FIREFOX_HISTORY_SQL = """
SELECT
    p.url,
    p.title,
    p.visit_count,
    p.last_visit_date,
    p.rev_host,
    h.visit_date,
    h.visit_type
FROM moz_places p
JOIN moz_historyvisits h ON p.id = h.place_id
ORDER BY h.visit_date DESC
"""

_FIREFOX_HISTORY_SQL_SIMPLE = """
SELECT url, title, visit_count, last_visit_date
FROM moz_places
ORDER BY last_visit_date DESC
"""


def _parse_firefox_history(path: Path) -> list:
    records = []
    conn = None
    tmp_path = None
    try:
        conn, tmp_path = _open_sqlite(path)
        cur = conn.cursor()

        try:
            cur.execute(_FIREFOX_HISTORY_SQL)
            rows = cur.fetchall()
            for row in rows:
                # Firefox timestamps: microseconds since Unix epoch (1970)
                visit_ts = unix_us_to_iso(row["visit_date"]) if row["visit_date"] else ""
                last_ts  = unix_us_to_iso(row["last_visit_date"]) if row["last_visit_date"] else ""
                url = row["url"] or ""
                records.append({
                    "ts":            visit_ts or last_ts,
                    "url":           url,
                    "title":         row["title"] or "",
                    "visit_count":   row["visit_count"] or 0,
                    "last_visit_ts": last_ts,
                    "visit_type":    row["visit_type"] if "visit_type" in row.keys() else "",
                    "browser":       "firefox",
                    "suspicious":    _is_suspicious_url(url),
                })
        except sqlite3.OperationalError:
            cur.execute(_FIREFOX_HISTORY_SQL_SIMPLE)
            for row in cur.fetchall():
                url = row["url"] or ""
                records.append({
                    "ts":          unix_us_to_iso(row["last_visit_date"]),
                    "url":         url,
                    "title":       row["title"] or "",
                    "visit_count": row["visit_count"] or 0,
                    "browser":     "firefox",
                    "suspicious":  _is_suspicious_url(url),
                })
    except Exception as e:
        records.append({"ts": "", "error": str(e), "browser": "firefox"})
    finally:
        if conn:
            conn.close()
        if tmp_path:
            _cleanup_tmp(tmp_path)

    return records


# ─── Orchestrator ─────────────────────────────────────────────────────────────

# Mapping: evidence file stem / name → (parser_fn, args)
_BROWSER_FILES = [
    # Chrome history
    ("chrome_history",  "chrome",  _parse_chrome_history,  "chrome"),
    ("chrome_History",  "chrome",  _parse_chrome_history,  "chrome"),
    # Edge history
    ("edge_history",    "edge",    _parse_chrome_history,  "edge"),
    ("edge_History",    "edge",    _parse_chrome_history,  "edge"),
    # Chrome cookies
    ("chrome_cookies",  "chrome_cookies", _parse_chrome_cookies, "chrome"),
    ("chrome_Cookies",  "chrome_cookies", _parse_chrome_cookies, "chrome"),
    # Edge cookies
    ("edge_cookies",    "edge_cookies",   _parse_chrome_cookies, "edge"),
    # Firefox
    ("firefox_places",  "firefox",  _parse_firefox_history, None),
    ("places",          "firefox",  _parse_firefox_history, None),
    ("places.sqlite",   "firefox",  _parse_firefox_history, None),
]


def run(evidence_dir: Path) -> dict:
    evidence_dir = Path(evidence_dir)
    browser_dir  = evidence_dir / "browser"

    if not browser_dir.is_dir():
        return {"record_count": 0, "_output_file": "", "_status": "no_browser_dir"}

    # Discover files
    all_files = list(browser_dir.iterdir())
    if not all_files:
        return {"record_count": 0, "_output_file": "", "_status": "no_browser_files"}

    all_records       = []
    output_files      = []
    processed_stems   = set()

    for file_path in sorted(all_files):
        if not file_path.is_file():
            continue
        fname = file_path.name.lower()

        matched = False
        for (pattern, artifact_tag, parser_fn, browser_arg) in _BROWSER_FILES:
            if pattern.lower() == fname or file_path.stem.lower() == pattern.lower().replace(".sqlite", ""):
                if artifact_tag in processed_stems:
                    continue
                processed_stems.add(artifact_tag)

                try:
                    if browser_arg is not None:
                        records = parser_fn(file_path, browser_arg)
                    else:
                        records = parser_fn(file_path)
                except Exception as e:
                    records = [{"ts": "", "error": str(e), "browser": artifact_tag}]

                artifact_name = f"browser_{artifact_tag}"
                envelope = make_envelope(
                    artifact     = artifact_name,
                    parser       = "browser_parser",
                    source_file  = file_path,
                    records      = records,
                    evidence_dir = evidence_dir,
                )
                out_path = parsed_output_path(evidence_dir, artifact_name)
                write_envelope(envelope, out_path)
                all_records.extend(records)
                output_files.append(str(out_path))
                matched = True
                break

        if not matched:
            # Try to open as SQLite generically
            if fname.endswith(".sqlite") or fname.endswith(".db"):
                try:
                    conn, tmp_path = _open_sqlite(file_path)
                    conn.close()
                    _cleanup_tmp(tmp_path)
                    # Try as chrome history
                    records = _parse_chrome_history(file_path, file_path.stem)
                    if not records:
                        records = _parse_firefox_history(file_path)
                    if records:
                        artifact_name = f"browser_{file_path.stem}"
                        envelope = make_envelope(
                            artifact     = artifact_name,
                            parser       = "browser_parser",
                            source_file  = file_path,
                            records      = records,
                            evidence_dir = evidence_dir,
                        )
                        out_path = parsed_output_path(evidence_dir, artifact_name)
                        write_envelope(envelope, out_path)
                        all_records.extend(records)
                        output_files.append(str(out_path))
                except Exception:
                    pass

    return {
        "record_count":  len(all_records),
        "_output_file":  output_files[0] if output_files else "",
        "_output_files": output_files,
        "_status":       "ok",
    }


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="JOCKY Browser History Parser")
    ap.add_argument("--evidence-dir", required=True)
    args = ap.parse_args()
    result = run(Path(args.evidence_dir))
    print(json.dumps(result, indent=2))
