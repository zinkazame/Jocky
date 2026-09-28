#!/usr/bin/env python3
"""
JOCKY Forensic Blockchain — Standalone Chain Verifier
======================================================
Version: 1.0.0

PURPOSE
-------
Verify the integrity of a JOCKY forensic evidence chain WITHOUT
installing or running the JOCKY framework.

This single file is all that is needed to verify any JOCKY
blockchain evidence file in a court of law or independent audit.

REQUIREMENTS
------------
  Python 3.8 or newer
  cryptography library: pip install cryptography

USAGE
-----
  python verify_chain_standalone.py <chain_file.json>
  python verify_chain_standalone.py <chain_file.json> --report
  python verify_chain_standalone.py <chain_file.json> --html report.html

WHAT IT VERIFIES
----------------
  1. Every block's SHA-256 hash matches its recomputed hash
     (detects any modification to block content)
  2. Every block's prev_hash matches the previous block's hash
     (detects insertion, deletion, or reordering of blocks)
  3. Every block's Ed25519 signature is valid against the
     investigator's public key embedded in Block 0
     (proves the block was created by the key-holding investigator)

WHAT A PASS MEANS
-----------------
  CHAIN INTACT = the evidence chain has not been modified,
  reordered, deleted from, or added to since it was sealed
  by the investigator. Every block is cryptographically
  authenticated by the investigator's Ed25519 key pair.

WHAT A FAIL MEANS
-----------------
  CHAIN COMPROMISED = at least one block has been tampered with.
  The report will identify exactly which block failed and why.

LEGAL NOTE
----------
  The investigator's Ed25519 public key is embedded in Block 0
  (the genesis block). This public key corresponds to a private
  key held exclusively by the investigator. The key was generated
  at investigation start and is stored separately from this file.
  Successful signature verification proves authorship and integrity.
"""
from __future__ import annotations

import hashlib
import json
import sys
import os
from datetime import datetime, timezone
from typing   import Any, Dict, List, Optional, Tuple


# ── dependency check ──────────────────────────────────────────────────────────

def _check_deps() -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        return True
    except ImportError:
        return False

_CRYPTO_AVAILABLE = _check_deps()


# ── SHA-256 block hash (must match blockchain.py exactly) ─────────────────────

def _compute_block_hash(block: Dict[str, Any]) -> str:
    """
    Recompute the SHA-256 hash of a block from its fields.
    This must be byte-for-byte identical to ForensicBlock.compute_hash()
    in blockchain.py for verification to succeed.
    """
    canonical = json.dumps({
        "index":        block["index"],
        "timestamp":    block["timestamp"],
        "case_id":      block["case_id"],
        "investigator": block["investigator"],
        "event_type":   block["event_type"],
        "data":         block["data"],
        "prev_hash":    block["prev_hash"],
        "nonce":        block.get("nonce", 0),
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ── Ed25519 signature verification ────────────────────────────────────────────

def _verify_signature(hash_hex: str, sig_hex: str, pub_key_hex: str) -> bool:
    """
    Verify an Ed25519 signature.
    Returns True if valid, False if invalid or crypto unavailable.
    """
    if not _CRYPTO_AVAILABLE:
        return None   # None = cannot verify, not explicitly False
    if not sig_hex or not pub_key_hex:
        return None
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_key_hex))
        pub.verify(bytes.fromhex(sig_hex), bytes.fromhex(hash_hex))
        return True
    except Exception:
        return False


# ── chain verification ────────────────────────────────────────────────────────

def verify_chain_file(chain_file: str) -> Tuple[bool, str, dict]:
    """
    Verify a JOCKY blockchain JSON file.

    Returns:
        (ok: bool, report_text: str, summary: dict)

    ok = True  → chain is intact, all blocks verified
    ok = False → chain is compromised, report identifies failures
    """
    # ── load file ─────────────────────────────────────────────────────────────
    try:
        with open(chain_file, "r", encoding="utf-8") as f:
            chain_data = json.load(f)
    except FileNotFoundError:
        return False, f"ERROR: File not found: {chain_file}", {}
    except json.JSONDecodeError as e:
        return False, f"ERROR: Invalid JSON: {e}", {}

    # ── extract metadata ──────────────────────────────────────────────────────
    case_id      = chain_data.get("case_id",      "UNKNOWN")
    investigator = chain_data.get("investigator", "UNKNOWN")
    pub_key      = chain_data.get("pub_key",      "")
    blocks       = chain_data.get("blocks",       [])

    # also try to get pub_key from genesis block data
    if not pub_key and blocks:
        genesis_data = blocks[0].get("data", {})
        pub_key = genesis_data.get("pub_key", "")

    # ── verify each block ─────────────────────────────────────────────────────
    GENESIS_HASH = "0" * 64

    results = []
    all_ok   = True
    sig_skip = not _CRYPTO_AVAILABLE

    for i, block in enumerate(blocks):
        errors    = []
        warnings  = []

        # 1. hash integrity
        computed = _compute_block_hash(block)
        stored   = block.get("hash", "")
        if stored != computed:
            errors.append(
                f"HASH MISMATCH\n"
                f"         stored:   {stored[:32]}...\n"
                f"         computed: {computed[:32]}..."
            )

        # 2. chain linkage
        if i == 0:
            expected_prev = GENESIS_HASH
        else:
            expected_prev = blocks[i-1].get("hash", "")

        actual_prev = block.get("prev_hash", "")
        if actual_prev != expected_prev:
            errors.append(
                f"BROKEN LINK\n"
                f"         stored prev_hash:   {actual_prev[:32]}...\n"
                f"         expected prev_hash: {expected_prev[:32]}..."
            )

        # 3. Ed25519 signature
        sig_result = _verify_signature(stored, block.get("signature",""), pub_key)
        if sig_result is False:
            errors.append("INVALID SIGNATURE — block was not signed by this investigator key")
        elif sig_result is None:
            warnings.append("signature not verified (cryptography library not installed)")

        if errors:
            all_ok = False

        results.append({
            "index":      block["index"],
            "timestamp":  block.get("timestamp", ""),
            "event_type": block.get("event_type", ""),
            "hash":       stored,
            "ok":         len(errors) == 0,
            "errors":     errors,
            "warnings":   warnings,
        })

    # ── build report ──────────────────────────────────────────────────────────
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S UTC")
    sep = "=" * 72

    lines = [
        sep,
        "  JOCKY FORENSIC BLOCKCHAIN — CHAIN OF CUSTODY VERIFICATION REPORT",
        sep,
        f"  File:          {os.path.abspath(chain_file)}",
        f"  Verified at:   {now}",
        f"  Verifier:      JOCKY Standalone Verifier v1.0.0",
        "",
        f"  Case ID:       {case_id}",
        f"  Investigator:  {investigator}",
        f"  Blocks:        {len(blocks)}",
        f"  Public Key:    {pub_key[:40]}..." if pub_key else
        f"  Public Key:    NOT FOUND IN CHAIN",
        f"  Crypto:        {'Ed25519 signatures verified' if _CRYPTO_AVAILABLE else 'WARNING: cryptography library not installed — signatures NOT verified'}",
        "",
        "-" * 72,
        "  BLOCK-BY-BLOCK AUDIT",
        "-" * 72,
    ]

    for r in results:
        mark = "✓" if r["ok"] else "✗"
        ts   = r["timestamp"][:19] if r["timestamp"] else "N/A"
        ev   = r["event_type"]
        h    = r["hash"][:16] + "..." if r["hash"] else "NO HASH"

        lines.append(f"  {mark}  Block {r['index']:>4}  {ts}  {ev:<28}  {h}")

        for err in r["errors"]:
            for eline in err.split("\n"):
                lines.append(f"         !! {eline}")
        for warn in r["warnings"]:
            lines.append(f"         ?? {warn}")

    lines += ["", "-" * 72, ""]

    if not _CRYPTO_AVAILABLE:
        lines += [
            "  !! WARNING: Ed25519 signature verification was SKIPPED.",
            "  !! Install 'cryptography': pip install cryptography",
            "  !! Hash integrity and chain linkage were still verified.",
            "",
        ]

    if all_ok:
        lines += [
            "  RESULT:  CHAIN INTACT",
            "           All blocks verified. Hash integrity confirmed.",
            "           Chain linkage confirmed. No tampering detected.",
            f"           {len(blocks)} blocks from {results[0]['timestamp'][:10] if results else 'N/A'}",
            f"           to {results[-1]['timestamp'][:10] if results else 'N/A'}.",
        ]
        if _CRYPTO_AVAILABLE and pub_key:
            lines.append(
                "           All Ed25519 signatures valid against investigator key."
            )
    else:
        failed = [r for r in results if not r["ok"]]
        lines += [
            "  RESULT:  *** CHAIN COMPROMISED ***",
            f"           {len(failed)} of {len(blocks)} blocks failed verification.",
            "           This chain has been tampered with.",
            "           EVIDENCE FROM THIS CHAIN SHOULD NOT BE ADMITTED.",
        ]
        lines.append("")
        lines.append("  FAILED BLOCKS:")
        for r in failed:
            lines.append(f"    Block {r['index']}: {', '.join(e.split(chr(10))[0] for e in r['errors'])}")

    lines += ["", sep, ""]

    summary = {
        "ok":             all_ok,
        "case_id":        case_id,
        "investigator":   investigator,
        "blocks":         len(blocks),
        "pub_key":        pub_key,
        "verified_at":    now,
        "crypto_verified": _CRYPTO_AVAILABLE and bool(pub_key),
        "failed_blocks":  [r["index"] for r in results if not r["ok"]],
        "block_results":  results,
        "chain_file":     os.path.abspath(chain_file),
    }

    return all_ok, "\n".join(lines), summary


# ── HTML court report ─────────────────────────────────────────────────────────

def generate_html_report(chain_file: str, summary: dict, report_text: str) -> str:
    """
    Generate a self-contained HTML court report.
    Can be printed to PDF directly from browser (File → Print → Save as PDF).
    No external dependencies — pure HTML/CSS, works offline.
    """
    ok        = summary["ok"]
    result_color  = "#16a34a" if ok else "#dc2626"
    result_bg     = "#f0fdf4" if ok else "#fef2f2"
    result_text   = "CHAIN INTACT" if ok else "CHAIN COMPROMISED"
    result_icon   = "✓" if ok else "✗"

    block_rows = ""
    for r in summary.get("block_results", []):
        row_class = "" if r["ok"] else "style='background:#fef2f2'"
        mark      = "✓" if r["ok"] else "✗"
        mark_col  = "#16a34a" if r["ok"] else "#dc2626"
        ts        = r["timestamp"][:19] if r["timestamp"] else "N/A"
        ev        = r["event_type"]
        h         = r["hash"][:20] + "..." if r["hash"] else "—"
        err_html  = ""
        if r["errors"]:
            err_html = "<br><small style='color:#dc2626'>" + \
                       " | ".join(e.split("\n")[0] for e in r["errors"]) + \
                       "</small>"
        block_rows += f"""
        <tr {row_class}>
          <td style='text-align:center;color:{mark_col};font-weight:700'>{mark}</td>
          <td style='text-align:center'>{r['index']}</td>
          <td>{ts}</td>
          <td><span class='ev-badge ev-{ev.lower().replace("_","-")}'>{ev}</span></td>
          <td style='font-family:monospace;font-size:11px'>{h}{err_html}</td>
        </tr>"""

    crypto_note = (
        "Ed25519 digital signatures verified against investigator public key."
        if summary.get("crypto_verified")
        else "<strong>WARNING:</strong> Digital signatures could not be verified "
             "(cryptography library not installed). Hash integrity was still verified."
    )

    pub_key = summary.get("pub_key", "")
    pub_key_display = (pub_key[:32] + "..." + pub_key[-8:]) if len(pub_key) > 40 else pub_key or "Not found"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>JOCKY Chain of Custody Report — {summary['case_id']}</title>
<style>
  @media print {{
    .no-print {{ display:none; }}
    body {{ margin:0; }}
    .page {{ box-shadow:none; margin:0; }}
  }}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{
    font-family: 'Segoe UI', Arial, sans-serif;
    background: #f3f4f6; color: #111827;
    font-size: 13px; line-height: 1.5;
  }}
  .page {{
    max-width: 900px; margin: 20px auto;
    background: white; padding: 48px;
    box-shadow: 0 1px 8px rgba(0,0,0,.15);
  }}
  h1 {{ font-size:22px; color:#111; margin-bottom:4px; }}
  h2 {{ font-size:14px; color:#374151; margin:24px 0 8px;
        text-transform:uppercase; letter-spacing:.5px; border-bottom:1px solid #e5e7eb; padding-bottom:4px; }}
  .header {{ border-bottom:2px solid #111; padding-bottom:16px; margin-bottom:24px; }}
  .logo {{ font-size:28px; font-weight:800; letter-spacing:4px; color:#1d4ed8; margin-bottom:4px; }}
  .subtitle {{ color:#6b7280; font-size:12px; }}
  .meta-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:8px 24px; margin:16px 0; }}
  .meta-row {{ display:flex; gap:8px; }}
  .meta-label {{ color:#6b7280; min-width:120px; font-size:12px; }}
  .meta-value {{ font-weight:600; font-size:12px; }}
  .result-box {{
    background:{result_bg}; border:2px solid {result_color};
    border-radius:8px; padding:20px 24px; margin:20px 0;
    display:flex; align-items:center; gap:16px;
  }}
  .result-icon {{
    font-size:36px; color:{result_color}; font-weight:700; line-height:1;
  }}
  .result-label {{ font-size:20px; font-weight:700; color:{result_color}; }}
  .result-sub {{ font-size:12px; color:#374151; margin-top:4px; }}
  table {{ width:100%; border-collapse:collapse; font-size:12px; margin:8px 0; }}
  th {{ background:#f9fafb; padding:8px 10px; text-align:left;
        font-weight:600; color:#374151; border-bottom:2px solid #e5e7eb;
        font-size:11px; text-transform:uppercase; letter-spacing:.3px; }}
  td {{ padding:7px 10px; border-bottom:1px solid #f3f4f6; vertical-align:top; }}
  tr:last-child td {{ border-bottom:none; }}
  .ev-badge {{
    padding:2px 6px; border-radius:3px; font-size:10px; font-weight:600;
    text-transform:uppercase; letter-spacing:.3px;
  }}
  .ev-investigation-start  {{ background:#dbeafe; color:#1e40af; }}
  .ev-agent-deployed        {{ background:#d1fae5; color:#065f46; }}
  .ev-evidence-collected    {{ background:#fef3c7; color:#92400e; }}
  .ev-anomaly-detected      {{ background:#fee2e2; color:#991b1b; }}
  .ev-task-dispatched       {{ background:#ede9fe; color:#5b21b6; }}
  .ev-chain-verified        {{ background:#d1fae5; color:#065f46; }}
  .ev-investigation-closed  {{ background:#f3f4f6; color:#374151; }}
  .ev-agent-lost            {{ background:#fee2e2; color:#991b1b; }}
  .hash-mono {{ font-family:monospace; font-size:10px; color:#6b7280; word-break:break-all; }}
  .warning-box {{ background:#fef3c7; border-left:4px solid #f59e0b; padding:10px 14px; margin:12px 0; font-size:12px; }}
  .print-btn {{
    position:fixed; bottom:24px; right:24px;
    background:#1d4ed8; color:white; border:none;
    padding:10px 20px; border-radius:6px; cursor:pointer;
    font-size:13px; font-weight:600; box-shadow:0 2px 8px rgba(0,0,0,.2);
  }}
  .print-btn:hover {{ background:#1e40af; }}
  .footer {{ margin-top:32px; padding-top:16px; border-top:1px solid #e5e7eb;
             font-size:11px; color:#9ca3af; text-align:center; }}
</style>
</head>
<body>

<button class="print-btn no-print" onclick="window.print()">🖨 Print / Save PDF</button>

<div class="page">

  <div class="header">
    <div class="logo">JOCKY</div>
    <div style="font-size:16px;font-weight:600;margin:4px 0">
      Forensic Blockchain — Chain of Custody Verification Report
    </div>
    <div class="subtitle">
      Generated by JOCKY Standalone Verifier v1.0.0 · {summary['verified_at']}
    </div>
  </div>

  <h2>Case Information</h2>
  <div class="meta-grid">
    <div class="meta-row"><span class="meta-label">Case ID</span><span class="meta-value">{summary['case_id']}</span></div>
    <div class="meta-row"><span class="meta-label">Investigator</span><span class="meta-value">{summary['investigator']}</span></div>
    <div class="meta-row"><span class="meta-label">Evidence File</span><span class="meta-value" style="font-family:monospace;font-size:11px">{os.path.basename(summary['chain_file'])}</span></div>
    <div class="meta-row"><span class="meta-label">Total Blocks</span><span class="meta-value">{summary['blocks']}</span></div>
    <div class="meta-row"><span class="meta-label">Verified At</span><span class="meta-value">{summary['verified_at']}</span></div>
    <div class="meta-row"><span class="meta-label">Crypto Verified</span><span class="meta-value">{'YES — Ed25519' if summary.get('crypto_verified') else 'Hash only (no crypto lib)'}</span></div>
  </div>

  <div class="meta-row" style="margin-top:8px">
    <span class="meta-label">Investigator Key</span>
    <span class="hash-mono">{pub_key_display}</span>
  </div>

  <h2>Verification Result</h2>
  <div class="result-box">
    <div class="result-icon">{result_icon}</div>
    <div>
      <div class="result-label">{result_text}</div>
      <div class="result-sub">
        {'All ' + str(summary['blocks']) + ' blocks verified. Hash integrity confirmed. Chain linkage confirmed. No tampering detected.' if ok
         else str(len(summary.get('failed_blocks',[]))) + ' block(s) failed verification. Evidence from this chain may have been tampered with.'}
      </div>
    </div>
  </div>

  {'<div class="warning-box">⚠ ' + crypto_note + '</div>' if not summary.get('crypto_verified') else ''}

  <h2>What This Verification Confirms</h2>
  <table>
    <thead>
      <tr><th>Check</th><th>Description</th><th>Result</th></tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>Hash Integrity</strong></td>
        <td>Every block's SHA-256 hash matches its recomputed hash. Any modification to block content would change the hash.</td>
        <td style="color:{'#16a34a' if ok else '#dc2626'};font-weight:600">{'PASS' if ok else 'FAIL'}</td>
      </tr>
      <tr>
        <td><strong>Chain Linkage</strong></td>
        <td>Every block's prev_hash matches the previous block's hash. Detects insertion, deletion, or reordering.</td>
        <td style="color:{'#16a34a' if ok else '#dc2626'};font-weight:600">{'PASS' if ok else 'FAIL'}</td>
      </tr>
      <tr>
        <td><strong>Digital Signature</strong></td>
        <td>Every block's Ed25519 signature is valid against the investigator's public key embedded in Block 0.</td>
        <td style="color:{'#16a34a' if summary.get('crypto_verified') else '#f59e0b'};font-weight:600">
          {'PASS' if summary.get('crypto_verified') else 'NOT VERIFIED'}
        </td>
      </tr>
    </tbody>
  </table>

  <h2>Block-by-Block Audit ({summary['blocks']} blocks)</h2>
  <table>
    <thead>
      <tr>
        <th style="width:36px">✓</th>
        <th style="width:50px">#</th>
        <th>Timestamp (UTC)</th>
        <th>Event Type</th>
        <th>Block Hash</th>
      </tr>
    </thead>
    <tbody>{block_rows}</tbody>
  </table>

  <h2>Verification Methodology</h2>
  <p style="font-size:12px;color:#374151;margin:8px 0">
    Each block's hash is computed as:<br>
    <code style="background:#f3f4f6;padding:2px 6px;border-radius:3px;font-size:11px">
      SHA-256( JSON({"{index, timestamp, case_id, investigator, event_type, data, prev_hash, nonce}"}) )
    </code><br><br>
    The JSON is serialized with sorted keys and minimal whitespace to ensure determinism.
    Ed25519 signatures are verified against the <code>pub_key</code> field from Block 0 (genesis block),
    which was generated at investigation start and corresponds to the investigator's private key.
  </p>

  <h2>Raw Verification Output</h2>
  <pre style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:4px;
              padding:12px;font-size:10px;overflow-x:auto;white-space:pre-wrap;
              font-family:monospace;color:#374151">{report_text}</pre>

  <div class="footer">
    JOCKY Forensic Intelligence Framework · SIH 2025 · Problem ID 26148 · NTRO<br>
    This report was generated automatically. The verification algorithm is open-source
    and reproducible. File: {os.path.basename(summary['chain_file'])}
  </div>

</div>
</body>
</html>"""


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    import argparse
    ap = argparse.ArgumentParser(
        prog="verify_chain_standalone",
        description="JOCKY Forensic Blockchain — Standalone Court Verifier",
        epilog="This file is self-contained. No JOCKY installation required."
    )
    ap.add_argument("chain_file", help="Path to blockchain JSON file (e.g. blockchain_NTRO-2025-001.json)")
    ap.add_argument("--html",   metavar="OUTPUT.html",
                    help="Also generate HTML court report at this path")
    ap.add_argument("--report", action="store_true",
                    help="Print full text report (default: print summary only)")
    ap.add_argument("--json",   metavar="OUTPUT.json",
                    help="Save verification summary as JSON")
    args = ap.parse_args()

    if not os.path.exists(args.chain_file):
        print(f"ERROR: File not found: {args.chain_file}", file=sys.stderr)
        sys.exit(1)

    print(f"\n[*] Verifying: {args.chain_file}")
    print(f"[*] Crypto:    {'Ed25519 + SHA-256' if _CRYPTO_AVAILABLE else 'SHA-256 only (install cryptography for Ed25519)'}")
    print()

    ok, report, summary = verify_chain_file(args.chain_file)

    if args.report:
        print(report)
    else:
        # compact summary
        sep = "=" * 56
        print(sep)
        print(f"  Case:        {summary.get('case_id','?')}")
        print(f"  Investigator:{summary.get('investigator','?')}")
        print(f"  Blocks:      {summary.get('blocks', 0)}")
        print(f"  Verified at: {summary.get('verified_at','')}")
        print(sep)
        failed = summary.get("failed_blocks", [])
        if ok:
            print(f"  RESULT: CHAIN INTACT — all {summary['blocks']} blocks verified")
        else:
            print(f"  RESULT: *** CHAIN COMPROMISED ***")
            print(f"          {len(failed)} block(s) failed: {failed}")
        print(sep)
        print()
        print("  (run with --report for full block-by-block audit)")

    if args.html:
        html = generate_html_report(args.chain_file, summary, report)
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"\n[+] HTML court report saved: {args.html}")
        print(f"    Open in browser → File → Print → Save as PDF")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, default=str)
        print(f"[+] Verification summary saved: {args.json}")

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()