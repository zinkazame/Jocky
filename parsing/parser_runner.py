"""
JOCKY Parser Runner — Orchestrates all artifact parsers on an evidence directory.

Usage:
    python parsing/parser_runner.py --evidence-dir evidence/20261002_143022
    python parsing/parser_runner.py --evidence-dir evidence/20261002_143022 --verbose
"""

import argparse
import importlib
import json
import os
import sys
import time
import traceback
from pathlib import Path
from datetime import datetime, timezone

# Ensure parsing/ is importable from both the repo root and when called directly
_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

# ─── Registry of all parsers ──────────────────────────────────────────────────
# Each entry: (module_name, function_name, description, subdirs_to_check)
# subdirs_to_check: list of glob patterns relative to evidence_dir that
# indicate this parser has work to do. If empty list → always run (parser
# decides internally whether artifacts exist).
_PARSER_REGISTRY = [
    ("evtx_parser",     "run",  "Windows Event Logs (EVTX)",          ["evtx/*.evtx"]),
    ("registry_parser", "run",  "Registry Hives (HIV)",               ["hives/*.hiv", "hives/*.hive"]),
    ("prefetch_parser", "run",  "Prefetch Files (PF)",                 ["prefetch/*.pf", "prefetch/*.pf"]),
    ("lnk_parser",      "run",  "Shell Link Files (LNK)",             ["lnk/*.lnk"]),
    ("amcache_parser",  "run",  "AmCache Execution Evidence",         ["hives/Amcache.hve", "hives/amcache.hve"]),
    ("shimcache_parser","run",  "ShimCache (AppCompatCache)",         ["hives/*.hiv", "hives/*.hive"]),
    ("srum_parser",     "run",  "SRUM Network/App Usage (SRUDB.dat)", ["srum/SRUDB.dat", "srum/srudb.dat"]),
    ("browser_parser",  "run",  "Browser History (Chrome/Edge/FF)",   ["browser/"]),
    ("timeline_parser", "run",  "Windows Activity Timeline",          ["timeline/ActivitiesCache.db"]),
    ("i30_parser",      "run",  "NTFS $I30 Directory Index Slack",    ["i30/"]),
]


def _has_artifacts(evidence_dir: Path, patterns: list) -> bool:
    """Return True if at least one matching artifact file exists."""
    if not patterns:
        return True
    for pattern in patterns:
        matches = list(evidence_dir.glob(pattern))
        if matches:
            return True
    return False


def _ensure_parsed_dir(evidence_dir: Path) -> Path:
    parsed = evidence_dir / "parsed"
    parsed.mkdir(exist_ok=True)
    return parsed


def run_all(evidence_dir: Path, verbose: bool = False, only: list = None) -> dict:
    """
    Run every registered parser against evidence_dir.
    Returns a summary dict: {parser_name: {"records": int, "status": str, "elapsed_ms": int}}.
    """
    _ensure_parsed_dir(evidence_dir)
    summary = {}

    for (mod_name, fn_name, description, patterns) in _PARSER_REGISTRY:
        if only and mod_name not in only:
            continue

        if not _has_artifacts(evidence_dir, patterns):
            if verbose:
                print(f"  [SKIP] {mod_name:<22} — no matching artifacts in {evidence_dir}")
            summary[mod_name] = {"records": 0, "status": "skipped", "elapsed_ms": 0}
            continue

        t0 = time.time()
        try:
            mod = importlib.import_module(f"parsing.{mod_name}")
            fn  = getattr(mod, fn_name)
            result = fn(evidence_dir)

            elapsed_ms = int((time.time() - t0) * 1000)
            n_records = result.get("record_count", 0) if isinstance(result, dict) else 0

            summary[mod_name] = {
                "records":    n_records,
                "status":     "ok",
                "elapsed_ms": elapsed_ms,
                "output":     result.get("_output_file", ""),
            }
            print(f"  [OK]   {mod_name:<22} {n_records:>6} records   ({elapsed_ms} ms)")

        except ImportError as e:
            elapsed_ms = int((time.time() - t0) * 1000)
            summary[mod_name] = {"records": 0, "status": f"import_error: {e}", "elapsed_ms": elapsed_ms}
            print(f"  [ERR]  {mod_name:<22} import error: {e}")
        except Exception as e:
            elapsed_ms = int((time.time() - t0) * 1000)
            tb = traceback.format_exc() if verbose else str(e)
            summary[mod_name] = {"records": 0, "status": f"error: {e}", "elapsed_ms": elapsed_ms}
            print(f"  [ERR]  {mod_name:<22} {e}")
            if verbose:
                print(tb)

    return summary


def main():
    ap = argparse.ArgumentParser(
        description="JOCKY Parser Runner — parse all forensic artifacts in an evidence directory",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python parsing/parser_runner.py --evidence-dir evidence/20261002_143022
  python parsing/parser_runner.py --evidence-dir evidence/20261002_143022 --verbose
  python parsing/parser_runner.py --evidence-dir evidence/20261002_143022 --only evtx_parser lnk_parser
        """,
    )
    ap.add_argument("--evidence-dir", required=True, help="Path to evidence/<timestamp>/ directory")
    ap.add_argument("--verbose",      action="store_true", help="Print stack traces and skipped parsers")
    ap.add_argument("--only",         nargs="+", metavar="PARSER",
                    help="Run only these parsers (module names without .py)")
    ap.add_argument("--summary-json", metavar="FILE",
                    help="Write JSON summary to this file")
    args = ap.parse_args()

    evidence_dir = Path(args.evidence_dir).resolve()
    if not evidence_dir.is_dir():
        print(f"[FATAL] Evidence directory not found: {evidence_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"\nJOCKY Parser Runner v1.0")
    print(f"Evidence : {evidence_dir}")
    print(f"Started  : {datetime.now(timezone.utc).isoformat()}")
    print("─" * 60)

    summary = run_all(evidence_dir, verbose=args.verbose, only=args.only)

    print("─" * 60)
    total_records = sum(v["records"] for v in summary.values())
    ok_count      = sum(1 for v in summary.values() if v["status"] == "ok")
    skip_count    = sum(1 for v in summary.values() if v["status"] == "skipped")
    err_count     = sum(1 for v in summary.values() if v["status"] not in ("ok", "skipped"))

    print(f"Parsers : {ok_count} ok  |  {skip_count} skipped  |  {err_count} errors")
    print(f"Records : {total_records} total")
    print(f"Output  : {evidence_dir / 'parsed'}/")

    if args.summary_json:
        with open(args.summary_json, "w", encoding="utf-8") as fh:
            json.dump({
                "run_at":       datetime.now(timezone.utc).isoformat(),
                "evidence_dir": str(evidence_dir),
                "parsers":      summary,
                "totals": {
                    "records": total_records,
                    "ok":      ok_count,
                    "skipped": skip_count,
                    "errors":  err_count,
                },
            }, fh, indent=2)
        print(f"Summary : {args.summary_json}")

    sys.exit(0 if err_count == 0 else 1)


if __name__ == "__main__":
    main()
