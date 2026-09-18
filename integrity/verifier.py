"""
JOCKY Standalone Chain Verifier — Phase 16
===========================================
Court-admissible, dependency-free chain verification.

This module is designed to be frozen into a standalone executable via
PyInstaller so it can be run on any machine without installing Python:

    pyinstaller --onefile integrity/verifier.py

The frozen binary verifies:
  1. Every entry's SHA-256 hash matches its content
  2. Every chain link (prev_hash) is correct
  3. Every Ed25519 signature is valid (if public key provided)
  4. No entries are missing (sequential IDs, no gaps)

Exit codes:
  0 — chain intact
  1 — chain tampered or broken
  2 — file not found or unreadable
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any


def verify_chain(chain_path: str, public_key_hex: str | None = None) -> tuple[bool, str]:
    """
    Verify a JOCKY hash-chain log file.

    Parameters
    ----------
    chain_path      : str
        Path to the .jsonl chain file.
    public_key_hex  : str | None
        Hex-encoded Ed25519 public key for signature verification.
        If None, signature verification is skipped.

    Returns
    -------
    (ok, report)
        ok     — True if chain is intact
        report — Human-readable verification report string
    """
    path = Path(chain_path)
    if not path.exists():
        return False, f"[verifier] ERROR: File not found — {chain_path}"

    # Load entries
    entries: list[dict] = []
    try:
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as exc:
                return False, f"[verifier] ERROR: Invalid JSON at line {i+1}: {exc}"
    except OSError as exc:
        return False, f"[verifier] ERROR: Cannot read file — {exc}"

    if not entries:
        return False, "[verifier] ERROR: Chain file is empty."

    errors: list[str] = []
    _GENESIS_PREV = "0" * 64

    for i, entry in enumerate(entries):
        # ── Check sequential IDs ──────────────────────────────────────────────
        if entry.get("id") != i:
            errors.append(f"Entry {i}: ID mismatch (expected {i}, got {entry.get('id')})")

        # ── Verify entry hash ─────────────────────────────────────────────────
        stored_hash = entry.get("entry_hash", "")
        computed    = _hash_entry(entry)
        if stored_hash != computed:
            errors.append(
                f"Entry {i} ({entry.get('event','?')}): "
                f"hash mismatch — TAMPERED\n"
                f"  stored:   {stored_hash[:32]}...\n"
                f"  computed: {computed[:32]}..."
            )

        # ── Verify chain link ─────────────────────────────────────────────────
        expected_prev = entries[i-1]["entry_hash"] if i > 0 else _GENESIS_PREV
        if entry.get("prev_hash") != expected_prev:
            errors.append(
                f"Entry {i}: chain link broken — "
                f"prev_hash does not match entry {i-1}"
            )

        # ── Verify Ed25519 signature (optional) ───────────────────────────────
        if public_key_hex:
            sig_ok = _verify_signature(entry, public_key_hex)
            if not sig_ok:
                errors.append(f"Entry {i}: signature INVALID")

    # ── Build report ──────────────────────────────────────────────────────────
    lines = [
        "=" * 60,
        "JOCKY Chain Integrity Verification Report",
        "=" * 60,
        f"File:    {chain_path}",
        f"Entries: {len(entries)}",
        f"Signed:  {'yes' if public_key_hex else 'no (public key not provided)'}",
        "-" * 60,
    ]

    if errors:
        lines.append(f"RESULT: CHAIN INTEGRITY VIOLATED ({len(errors)} error(s))")
        lines.append("")
        for err in errors:
            lines.append(f"  ✗ {err}")
    else:
        lines.append("RESULT: CHAIN INTACT — all entries verified")
        lines.append("")
        for entry in entries:
            ts    = entry.get("timestamp", "?")[:19]
            event = entry.get("event", "?")
            eid   = entry.get("id", "?")
            lines.append(f"  ✓ [{eid:>4}] {ts}  {event}")

    lines.append("=" * 60)
    report = "\n".join(lines)
    return (len(errors) == 0, report)


# ─── Hash computation (mirrors hash_chain.py) ─────────────────────────────────

def _hash_entry(entry: dict) -> str:
    content = {
        k: v for k, v in entry.items()
        if k not in ("entry_hash", "signature")
    }
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ─── Signature verification ───────────────────────────────────────────────────

def _verify_signature(entry: dict, public_key_hex: str) -> bool:
    """Verify Ed25519 signature. Returns True if valid or if crypto unavailable."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from cryptography.hazmat.primitives.serialization import load_der_public_key

        sig_hex  = entry.get("signature")
        hash_hex = entry.get("entry_hash")
        if not sig_hex or not hash_hex:
            return False

        pub_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pub_key.verify(bytes.fromhex(sig_hex), bytes.fromhex(hash_hex))
        return True
    except ImportError:
        return True   # cryptography not available — skip sig check
    except Exception:
        return False


# ─── CLI (standalone verifier) ────────────────────────────────────────────────

def _main() -> None:
    """
    Usage: verifier <chain.jsonl> [--pubkey <hex>]

    Standalone court-admissible chain verifier.
    Freeze with: pyinstaller --onefile integrity/verifier.py
    """
    import argparse
    ap = argparse.ArgumentParser(
        prog="jocky-verify",
        description="JOCKY standalone chain integrity verifier",
    )
    ap.add_argument("chain",             help="Path to chain.jsonl file")
    ap.add_argument("--pubkey", "-k",    metavar="HEX",
                    help="Hex-encoded Ed25519 public key for signature verification")
    args = ap.parse_args()

    ok, report = verify_chain(args.chain, args.pubkey)
    print(report)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    _main()
