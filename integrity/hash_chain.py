"""
JOCKY Hash-Chain Integrity Engine — Phase 16
=============================================
Tamper-evident, court-admissible forensic log.

Every log entry contains:
  - Sequential entry ID
  - UTC timestamp (ISO 8601)
  - Event type and payload
  - SHA-256 hash of this entry's content
  - SHA-256 hash of the previous entry (chain link)
  - Ed25519 digital signature (added by ChainSigner)

The chain is stored as a JSON Lines file (.jsonl) — one JSON object per line.
Verification re-computes every hash and checks every chain link.

Design principles:
  - Append-only: entries are never modified or deleted
  - Deterministic: same inputs always produce the same hash
  - Self-contained: the verifier binary (PyInstaller frozen) needs no deps
  - Court-admissible: chain integrity + operator signature proves non-tampering
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ─── Sentinel for the genesis block ───────────────────────────────────────────
_GENESIS_PREV = "0" * 64   # 64 zero hex chars — no previous entry


class HashChain:
    """
    Append-only SHA-256 hash chain log.

    Parameters
    ----------
    path : str
        Path to the .jsonl chain file. Created if it does not exist.
    """

    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self._entries: list[dict] = []
        if self.path.exists():
            self._load()

    # ─── Public API ───────────────────────────────────────────────────────────

    def append(self, event: str, data: dict[str, Any]) -> int:
        """
        Append a new entry to the chain.

        Parameters
        ----------
        event : str
            Event type label (e.g. "compile", "acquire", "transfer").
        data : dict
            Arbitrary JSON-serialisable payload.

        Returns
        -------
        int
            Entry ID (0-indexed, monotonically increasing).
        """
        entry_id  = len(self._entries)
        prev_hash = self._entries[-1]["entry_hash"] if self._entries else _GENESIS_PREV
        ts        = datetime.now(timezone.utc).isoformat()

        # Build the entry (signature field added later by ChainSigner)
        entry: dict[str, Any] = {
            "id":         entry_id,
            "timestamp":  ts,
            "event":      event,
            "data":       data,
            "prev_hash":  prev_hash,
            "signature":  None,   # placeholder — filled by ChainSigner.sign_entry()
        }

        # Compute entry hash over all fields except signature
        entry["entry_hash"] = _hash_entry(entry)

        self._entries.append(entry)
        self._flush_last()
        return entry_id

    def get(self, entry_id: int) -> dict:
        """Return a copy of the entry at the given ID."""
        if entry_id < 0 or entry_id >= len(self._entries):
            raise IndexError(f"Entry {entry_id} not in chain (len={len(self._entries)})")
        return dict(self._entries[entry_id])

    def update_signature(self, entry_id: int, signature_hex: str) -> None:
        """
        Write the Ed25519 signature into an existing entry and re-flush.
        Called by ChainSigner after signing.
        """
        if entry_id < 0 or entry_id >= len(self._entries):
            raise IndexError(f"Entry {entry_id} not in chain")
        self._entries[entry_id]["signature"] = signature_hex
        self._rewrite()

    def verify(self) -> tuple[bool, list[str]]:
        """
        Verify the entire chain.

        Returns
        -------
        (ok, errors)
            ok     — True if chain is intact
            errors — list of human-readable error strings (empty if ok)
        """
        errors: list[str] = []

        for i, entry in enumerate(self._entries):
            # 1. Verify entry hash
            expected_hash = _hash_entry(entry)
            if entry.get("entry_hash") != expected_hash:
                errors.append(
                    f"Entry {i}: hash mismatch "
                    f"(stored={entry.get('entry_hash', 'MISSING')[:16]}... "
                    f"computed={expected_hash[:16]}...)"
                )

            # 2. Verify chain link
            expected_prev = (
                self._entries[i - 1]["entry_hash"] if i > 0 else _GENESIS_PREV
            )
            if entry.get("prev_hash") != expected_prev:
                errors.append(
                    f"Entry {i}: chain link broken "
                    f"(prev_hash does not match entry {i-1})"
                )

        return (len(errors) == 0, errors)

    @property
    def length(self) -> int:
        return len(self._entries)

    # ─── Persistence ──────────────────────────────────────────────────────────

    def _load(self) -> None:
        """Load existing chain from disk."""
        self._entries = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                self._entries.append(json.loads(line))

    def _flush_last(self) -> None:
        """Append the last entry to the file (efficient append-only write)."""
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(self._entries[-1], separators=(",", ":")) + "\n")

    def _rewrite(self) -> None:
        """Rewrite the entire chain file (used after signature update)."""
        lines = [
            json.dumps(e, separators=(",", ":")) for e in self._entries
        ]
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ─── Hash computation ─────────────────────────────────────────────────────────

def _hash_entry(entry: dict) -> str:
    """
    Compute SHA-256 over the entry's canonical JSON representation.
    Excludes the 'entry_hash' and 'signature' fields (they are not part
    of the content being hashed).
    """
    content = {
        k: v for k, v in entry.items()
        if k not in ("entry_hash", "signature")
    }
    # Canonical JSON: sorted keys, no extra whitespace
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
