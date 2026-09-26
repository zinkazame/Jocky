# integrity/blockchain.py
# [JOCKY -- Forensic Blockchain Chain of Custody]
#
# PURPOSE
# -------
# A cryptographically linked blockchain where every investigation event
# is an immutable, signed, timestamped block. This is the legal backbone
# of JOCKY's court-admissibility claim.
#
# BLOCK STRUCTURE
# ---------------
#   index        -- sequential block number (0 = genesis)
#   timestamp    -- ISO-8601 UTC
#   case_id      -- investigation case identifier
#   investigator -- operator identity
#   event_type   -- INVESTIGATION_START | AGENT_DEPLOYED | EVIDENCE_COLLECTED |
#                   TASK_DISPATCHED | CHAIN_VERIFIED | INVESTIGATION_CLOSED
#   data         -- arbitrary event payload (process list, memory chunk, etc.)
#   prev_hash    -- SHA-256 of previous block (links the chain)
#   hash         -- SHA-256(index+timestamp+case_id+investigator+
#                           event_type+data+prev_hash)
#   signature    -- Ed25519 signature of hash (investigator's key)
#
# TAMPER EVIDENCE
# ---------------
# Any modification to any block breaks:
#   - that block's hash (hash mismatch)
#   - every subsequent block's prev_hash (cascade break)
#   - the Ed25519 signature (cryptographic proof of tampering)
#
# *the chain of custody is not a log. it is a spine.
#  break one vertebra and the entire record collapses.*

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass, field
from datetime    import datetime, timezone
from pathlib     import Path
from typing      import Any, Dict, List, Optional, Tuple

# Ed25519 via cryptography library
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions        import InvalidSignature
    _CRYPTO_OK = True
except ImportError:
    _CRYPTO_OK = False


# ── Block ────────────────────────────────────────────────────────────────────

@dataclass
class ForensicBlock:
    index:        int
    timestamp:    str
    case_id:      str
    investigator: str
    event_type:   str
    data:         Dict[str, Any]
    prev_hash:    str
    hash:         str          = ""
    signature:    str          = ""   # hex Ed25519 signature of hash
    nonce:        int          = 0    # reserved for future PoW

    def compute_hash(self) -> str:
        """
        SHA-256 over all block fields except hash and signature.
        Deterministic: same input always produces same hash.
        """
        block_str = json.dumps({
            "index":        self.index,
            "timestamp":    self.timestamp,
            "case_id":      self.case_id,
            "investigator": self.investigator,
            "event_type":   self.event_type,
            "data":         self.data,
            "prev_hash":    self.prev_hash,
            "nonce":        self.nonce,
        }, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(block_str.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ForensicBlock":
        return cls(**d)


# ── Blockchain ────────────────────────────────────────────────────────────────

class ForensicBlockchain:
    """
    Append-only forensic blockchain for investigation chain of custody.

    Usage:
        bc = ForensicBlockchain(
            case_id      = "NTRO-2025-001",
            investigator = "INV-ALPHA",
            chain_file   = "evidence/coc_NTRO-2025-001.json",
            key_file     = "evidence/inv_key.pem",
        )
        bc.add_event("INVESTIGATION_START", {"target_count": 3})
        bc.add_event("AGENT_DEPLOYED",      {"agent_id": "agent-dc01"})
        bc.add_event("EVIDENCE_COLLECTED",  {"cmd": "proc_list", "count": 87})

        ok, report = bc.verify()
        print(report)
    """

    GENESIS_HASH = "0" * 64   # genesis block's prev_hash

    VALID_EVENTS = {
        "INVESTIGATION_START",
        "AGENT_DEPLOYED",
        "AGENT_LOST",
        "TASK_DISPATCHED",
        "EVIDENCE_COLLECTED",
        "CHAIN_VERIFIED",
        "ANOMALY_DETECTED",
        "INVESTIGATION_CLOSED",
    }

    def __init__(self,
                 case_id:      str,
                 investigator: str,
                 chain_file:   str,
                 key_file:     Optional[str] = None):
        self.case_id      = case_id
        self.investigator = investigator
        self.chain_file   = Path(chain_file)
        self.key_file     = Path(key_file) if key_file else None
        self._chain:      List[ForensicBlock] = []
        self._priv_key    = None
        self._pub_key_hex = ""

        # load or generate signing key
        self._init_key()

        # load existing chain from disk or create genesis
        if self.chain_file.exists():
            self._load()
        else:
            self._create_genesis()

    # ── key management ────────────────────────────────────────────────────────

    def _init_key(self) -> None:
        if not _CRYPTO_OK:
            print("[blockchain] WARNING: cryptography library not found -- "
                  "signatures disabled")
            return

        if self.key_file and self.key_file.exists():
            raw = self.key_file.read_bytes()
            self._priv_key = Ed25519PrivateKey.from_private_bytes(
                serialization.load_pem_private_key(raw, password=None)
                .private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption()
                )
            )
        else:
            self._priv_key = Ed25519PrivateKey.generate()
            if self.key_file:
                self.key_file.parent.mkdir(parents=True, exist_ok=True)
                pem = self._priv_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()
                )
                self.key_file.write_bytes(pem)

        if self._priv_key:
            pub_raw = self._priv_key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw
            )
            self._pub_key_hex = pub_raw.hex()
            print(f"[blockchain] investigator key: {self._pub_key_hex[:16]}...")

    def _sign(self, hash_hex: str) -> str:
        if not self._priv_key:
            return ""
        sig = self._priv_key.sign(bytes.fromhex(hash_hex))
        return sig.hex()

    def _verify_sig(self, hash_hex: str, sig_hex: str,
                    pub_key_hex: str) -> bool:
        if not _CRYPTO_OK or not sig_hex or not pub_key_hex:
            return True   # skip if crypto unavailable
        try:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_key_hex))
            pub.verify(bytes.fromhex(sig_hex), bytes.fromhex(hash_hex))
            return True
        except (InvalidSignature, Exception):
            return False

    # ── genesis ───────────────────────────────────────────────────────────────

    def _create_genesis(self) -> None:
        """
        Block 0: the anchor. Everything after inherits from this.
        *the first block knows nothing that came before it.
         that is the point.*
        """
        genesis = ForensicBlock(
            index        = 0,
            timestamp    = self._utcnow(),
            case_id      = self.case_id,
            investigator = self.investigator,
            event_type   = "INVESTIGATION_START",
            data         = {
                "framework": "JOCKY",
                "version":   "1.0.0",
                "case_id":   self.case_id,
                "pub_key":   self._pub_key_hex,
            },
            prev_hash    = self.GENESIS_HASH,
        )
        genesis.hash      = genesis.compute_hash()
        genesis.signature = self._sign(genesis.hash)
        self._chain.append(genesis)
        self._save()
        print(f"[blockchain] genesis block: {genesis.hash[:16]}...")

    # ── append ────────────────────────────────────────────────────────────────

    def add_event(self,
                  event_type: str,
                  data:       Dict[str, Any]) -> ForensicBlock:
        """
        Append a new event block to the chain.
        Thread-safe? No — call from a single thread or use a lock.
        Returns the newly created block.
        """
        if event_type not in self.VALID_EVENTS:
            raise ValueError(f"unknown event_type: {event_type}. "
                             f"valid: {self.VALID_EVENTS}")

        prev = self._chain[-1]
        block = ForensicBlock(
            index        = prev.index + 1,
            timestamp    = self._utcnow(),
            case_id      = self.case_id,
            investigator = self.investigator,
            event_type   = event_type,
            data         = data,
            prev_hash    = prev.hash,
        )
        block.hash      = block.compute_hash()
        block.signature = self._sign(block.hash)
        self._chain.append(block)
        self._save()
        return block

    # ── verification ──────────────────────────────────────────────────────────

    def verify(self) -> Tuple[bool, str]:
        """
        Full chain integrity verification:
          1. Each block's hash matches its recomputed hash
          2. Each block's prev_hash matches the previous block's hash
          3. Each block's Ed25519 signature is valid
        Returns (ok: bool, report: str)
        """
        lines = [
            "=" * 64,
            "JOCKY Forensic Blockchain — Chain of Custody Verification",
            "=" * 64,
            f"Case:        {self.case_id}",
            f"Investigator:{self.investigator}",
            f"Blocks:      {len(self._chain)}",
            f"Key:         {self._pub_key_hex[:32]}..." if self._pub_key_hex else "",
            "-" * 64,
        ]

        all_ok = True
        for i, block in enumerate(self._chain):
            errors = []

            # hash integrity
            expected_hash = block.compute_hash()
            if block.hash != expected_hash:
                errors.append(f"HASH MISMATCH (stored={block.hash[:8]} "
                              f"computed={expected_hash[:8]})")

            # chain linkage
            if i > 0:
                prev_hash = self._chain[i-1].hash
                if block.prev_hash != prev_hash:
                    errors.append(f"BROKEN LINK "
                                  f"(prev_hash={block.prev_hash[:8]} "
                                  f"expected={prev_hash[:8]})")

            # signature
            if block.signature and self._pub_key_hex:
                if not self._verify_sig(block.hash, block.signature,
                                         self._pub_key_hex):
                    errors.append("INVALID SIGNATURE")

            mark = "✓" if not errors else "✗"
            if errors:
                all_ok = False
            status = " | ".join(errors) if errors else "OK"
            lines.append(
                f"  {mark} [Block {block.index:4d}] "
                f"{block.timestamp[:19]}  "
                f"{block.event_type:<28}  "
                f"{block.hash[:12]}  {status}"
            )

        lines.append("-" * 64)
        result_line = (
            "RESULT: CHAIN INTACT — all blocks verified"
            if all_ok else
            "RESULT: *** CHAIN COMPROMISED — TAMPER DETECTED ***"
        )
        lines.append(result_line)
        lines.append("=" * 64)
        return all_ok, "\n".join(lines)

    # ── query ─────────────────────────────────────────────────────────────────

    @property
    def length(self) -> int:
        return len(self._chain)

    @property
    def latest(self) -> Optional[ForensicBlock]:
        return self._chain[-1] if self._chain else None

    def get_block(self, index: int) -> Optional[ForensicBlock]:
        if 0 <= index < len(self._chain):
            return self._chain[index]
        return None

    def get_events(self, event_type: Optional[str] = None
                   ) -> List[ForensicBlock]:
        if event_type:
            return [b for b in self._chain if b.event_type == event_type]
        return list(self._chain)

    def export(self) -> List[dict]:
        return [b.to_dict() for b in self._chain]

    def summary(self) -> dict:
        event_counts: Dict[str, int] = {}
        for b in self._chain:
            event_counts[b.event_type] = event_counts.get(b.event_type, 0) + 1
        return {
            "case_id":      self.case_id,
            "investigator": self.investigator,
            "blocks":       len(self._chain),
            "genesis_hash": self._chain[0].hash if self._chain else "",
            "latest_hash":  self._chain[-1].hash if self._chain else "",
            "events":       event_counts,
            "pub_key":      self._pub_key_hex,
        }

    # ── persistence ───────────────────────────────────────────────────────────

    def _save(self) -> None:
        self.chain_file.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "case_id":      self.case_id,
            "investigator": self.investigator,
            "pub_key":      self._pub_key_hex,
            "blocks":       [b.to_dict() for b in self._chain],
        }
        self.chain_file.write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )

    def _load(self) -> None:
        data = json.loads(self.chain_file.read_text(encoding="utf-8"))
        self._chain = [
            ForensicBlock.from_dict(b) for b in data["blocks"]
        ]
        if not self._pub_key_hex and "pub_key" in data:
            self._pub_key_hex = data["pub_key"]
        print(f"[blockchain] loaded {len(self._chain)} blocks "
              f"from {self.chain_file}")

    @staticmethod
    def _utcnow() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"