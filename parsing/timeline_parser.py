"""
JOCKY Timeline Parser — Windows ActivitiesCache.db (Activity Timeline).

Input:  evidence/<ts>/timeline/ActivitiesCache.db
Output: evidence/<ts>/parsed/timeline_parsed.json

The ActivitiesCache.db is a SQLite database located at:
  %LOCALAPPDATA%\\ConnectedDevicesPlatform\\L.<username>\\ActivitiesCache.db

Tables queried:
  Activity — each row is one recorded user activity (app open, document view)
    Id                TEXT PRIMARY KEY
    AppId             TEXT  — JSON array of app identifiers
    PackageIdHash     TEXT
    AppActivityId     TEXT  — deep-link (e.g. ms-word://...)
    ActivityType      INT
    ActivityStatus    INT
    ParentActivityId  TEXT
    Tag               TEXT
    Group             TEXT
    MatchId           TEXT
    LastModifiedTime  INT   — Unix seconds
    ExpirationTime    INT   — Unix seconds
    Payload           TEXT  — JSON blob (title, content URL, app info)
    Priority          INT
    IsLocalOnly       INT
    PlatformDeviceId  TEXT
    CreatedInCloud    INT
    StartTime         INT   — Unix seconds
    EndTime           INT   — Unix seconds
    LastModifiedOnClient INT
    GroupAppActivityId TEXT
    ClipboardPayload  BLOB
    EnterpriseId      TEXT
    OriginalPayload   BLOB
    OriginalLastModifiedOnClient INT
    ETag              TEXT

The Payload JSON blob contains fields like:
  displayText  — document title / window title
  contentUri   — file:// or https:// URI
  description
  appDisplayName

Duration = EndTime - StartTime (in seconds).
"""

import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from parsing._utils import (
    make_envelope, write_envelope, parsed_output_path, unix_ms_to_iso
)


def _unix_to_iso(ts: int) -> str:
    if not ts or ts <= 0:
        return ""
    try:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt.isoformat()
    except (OSError, OverflowError, ValueError):
        return ""


def _parse_app_id(app_id_str: str) -> str:
    """
    AppId is a JSON array like:
      [{"application":"Microsoft.Office.Word_8wekyb3d8bbwe","platform":"windows_win32_package"},...]
    Extract the primary application name.
    """
    if not app_id_str:
        return ""
    try:
        items = json.loads(app_id_str)
        if isinstance(items, list) and items:
            first = items[0]
            if isinstance(first, dict):
                return first.get("application", "") or first.get("packageId", "")
        return str(items)
    except Exception:
        return app_id_str


def _parse_payload(payload_str: str) -> dict:
    """
    Payload is a JSON blob (may be double-encoded or gzipped base64 in newer builds).
    Extract: displayText, contentUri, appDisplayName, description.
    """
    if not payload_str:
        return {}
    try:
        # Direct JSON
        data = json.loads(payload_str)
        if isinstance(data, dict):
            inner = data
        elif isinstance(data, str):
            inner = json.loads(data)
        else:
            inner = {}

        # Windows 10 Payload schema
        return {
            "display_text":    inner.get("displayText", ""),
            "content_uri":     inner.get("contentUri", ""),
            "app_name":        inner.get("appDisplayName", inner.get("appName", "")),
            "description":     inner.get("description", ""),
            "activity_type":   inner.get("type", ""),
            "window_title":    inner.get("activeDurationSeconds", ""),
        }
    except Exception:
        # Try extracting JSON from embedded string
        start = payload_str.find("{")
        if start != -1:
            try:
                sub = payload_str[start:]
                end = sub.rfind("}")
                if end != -1:
                    inner = json.loads(sub[:end+1])
                    return {
                        "display_text": inner.get("displayText", ""),
                        "content_uri":  inner.get("contentUri", ""),
                        "app_name":     inner.get("appDisplayName", ""),
                    }
            except Exception:
                pass
        return {"raw_payload": payload_str[:256]}


_ACTIVITY_SQL = """
SELECT
    Id,
    AppId,
    AppActivityId,
    ActivityType,
    ActivityStatus,
    StartTime,
    EndTime,
    LastModifiedTime,
    ExpirationTime,
    Payload,
    Priority,
    IsLocalOnly,
    PlatformDeviceId
FROM Activity
ORDER BY StartTime DESC
"""

_ACTIVITY_SQL_MINIMAL = """
SELECT Id, AppId, ActivityType, StartTime, EndTime, Payload
FROM Activity
ORDER BY StartTime DESC
"""


def parse_activities_cache(db_path: Path) -> list:
    records = []
    conn = None
    try:
        # ActivitiesCache.db is not usually locked; open directly
        uri = f"file:{db_path}?mode=ro"
        try:
            conn = sqlite3.connect(uri, uri=True, timeout=5)
        except Exception:
            conn = sqlite3.connect(str(db_path), timeout=5)

        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        try:
            cur.execute(_ACTIVITY_SQL)
        except sqlite3.OperationalError:
            cur.execute(_ACTIVITY_SQL_MINIMAL)

        for row in cur.fetchall():
            start_ts = _unix_to_iso(row["StartTime"])
            end_ts   = _unix_to_iso(row["EndTime"])

            duration_secs = 0
            if row["StartTime"] and row["EndTime"] and row["EndTime"] > row["StartTime"]:
                duration_secs = row["EndTime"] - row["StartTime"]

            app_id   = _parse_app_id(row["AppId"])
            payload  = _parse_payload(row["Payload"] if "Payload" in row.keys() else "")

            record = {
                "ts":              start_ts,
                "id":              row["Id"] or "",
                "app_id":          app_id,
                "raw_app_id":      row["AppId"] or "",
                "activity_type":   row["ActivityType"] if "ActivityType" in row.keys() else "",
                "activity_status": row["ActivityStatus"] if "ActivityStatus" in row.keys() else "",
                "app_activity_id": row["AppActivityId"] if "AppActivityId" in row.keys() else "",
                "start_ts":        start_ts,
                "end_ts":          end_ts,
                "duration_secs":   duration_secs,
                "last_modified_ts": _unix_to_iso(row["LastModifiedTime"] if "LastModifiedTime" in row.keys() else 0),
                "expiration_ts":   _unix_to_iso(row["ExpirationTime"] if "ExpirationTime" in row.keys() else 0),
                "platform_device": row["PlatformDeviceId"] if "PlatformDeviceId" in row.keys() else "",
                "is_local_only":   bool(row["IsLocalOnly"]) if "IsLocalOnly" in row.keys() else False,
                **payload,
            }
            records.append(record)

    except Exception as e:
        records.append({"ts": "", "error": str(e)})
    finally:
        if conn:
            conn.close()

    return records


def run(evidence_dir: Path) -> dict:
    evidence_dir = Path(evidence_dir)

    db_path = None
    for candidate in (
        evidence_dir / "timeline" / "ActivitiesCache.db",
        evidence_dir / "timeline" / "activitiescache.db",
        evidence_dir / "ActivitiesCache.db",
    ):
        if candidate.is_file():
            db_path = candidate
            break

    if db_path is None:
        return {"record_count": 0, "_output_file": "", "_status": "activities_cache_not_found"}

    records = parse_activities_cache(db_path)

    envelope = make_envelope(
        artifact     = "timeline",
        parser       = "timeline_parser",
        source_file  = db_path,
        records      = records,
        evidence_dir = evidence_dir,
    )
    out_path = parsed_output_path(evidence_dir, "timeline")
    write_envelope(envelope, out_path)

    return {
        "record_count": len(records),
        "_output_file": str(out_path),
        "_status":      "ok",
    }


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="JOCKY Activity Timeline Parser")
    ap.add_argument("--evidence-dir", required=True)
    args = ap.parse_args()
    result = run(Path(args.evidence_dir))
    print(json.dumps(result, indent=2))
