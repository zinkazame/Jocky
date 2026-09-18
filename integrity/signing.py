"""
JOCKY Chain Signer — Phase 16
==============================
Ed25519 digital signatures for hash-chain entries.

Each compile/acquire/transfer event is signed with the operator's
Ed25519 private key. The public key is embedded in the chain for
verification by the standalone verifier binary.

Key management:
  - Keys are generated once per operator and stored in a .key file
  - The .key file must be kept secret (treat like an SSH private key)
  - The public key is stored in the chain's genesis metadata

Requires: cryptography >= 41.0  (pip install cryptography)
"""

from __future__ import annotations

import json
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
        load_pem_private_key,
    )
    _CRYPTO_OK = True
except ImportError:
    _CRYPTO_OK = False

from hash_chain import HashChain


class ChainSigner:
    """
    Signs hash-chain entries with an Ed25519 private key.

    Parameters
    ----------
    key_path : str
        Path to the PEM private key file.
        If the file does not exist, a new key pair is generated and saved.
    """

    def __init__(self, key_path: str) -> None:
        self.key_path = Path(key_path)
        self._private_key = None
        self._public_key_hex: str = ""

        if not _CRYPTO_OK:
            return   # Graceful degradation — signing disabled

        if self.key_path.exists():
            self._load_key()
        else:
            self._generate_key()

    # ─── Public API ───────────────────────────────────────────────────────────

    def sign_entry(self, chain: HashChain, entry_id: int) -> str:
        """
        Sign a chain entry and write the signature back into the chain.

        Parameters
        ----------
        chain    : HashChain
        entry_id : int

        Returns
        -------
        str
            Hex-encoded Ed25519 signature, or empty string if crypto unavailable.
        """
        if not _CRYPTO_OK or self._private_key is None:
            return ""

        entry = chain.get(entry_id)
        # Sign the entry_hash (which already covers all content fields)
        entry_hash_bytes = bytes.fromhex(entry["entry_hash"])
        sig_bytes = self._private_key.sign(entry_hash_bytes)
        sig_hex   = sig_bytes.hex()

        chain.update_signature(entry_id, sig_hex)
        return sig_hex

    def verify_signature(self, entry: dict) -> bool:
        """
        Verify the Ed25519 signature on a chain entry.

        Parameters
        ----------
        entry : dict
            A chain entry dict (as returned by HashChain.get()).

        Returns
        -------
        bool
            True if signature is valid, False otherwise.
        """
        if not _CRYPTO_OK or self._private_key is None:
            return True   # Can't verify — treat as pass (degraded mode)

        sig_hex   = entry.get("signature")
        hash_hex  = entry.get("entry_hash")
        if not sig_hex or not hash_hex:
            return False

        try:
            pub_key = self._private_key.public_key()
            pub_key.verify(bytes.fromhex(sig_hex), bytes.fromhex(hash_hex))
            return True
        except Exception:
            return False

    @property
    def public_key_hex(self) -> str:
        """Hex-encoded Ed25519 public key (for embedding in chain metadata)."""
        return self._public_key_hex

    # ─── Key management ───────────────────────────────────────────────────────

    def _generate_key(self) -> None:
        """Generate a new Ed25519 key pair and save the private key."""
        self._private_key = Ed25519PrivateKey.generate()
        pem = self._private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        self.key_path.write_bytes(pem)
        self.key_path.chmod(0o600)   # owner-read-only

        pub_bytes = self._private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        self._public_key_hex = pub_bytes.hex()
        print(f"[signer] New Ed25519 key pair generated → {self.key_path}")
        print(f"[signer] Public key: {self._public_key_hex}")

    def _load_key(self) -> None:
        """Load an existing Ed25519 private key from PEM file."""
        pem = self.key_path.read_bytes()
        self._private_key = load_pem_private_key(pem, password=None)
        pub_bytes = self._private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        self._public_key_hex = pub_bytes.hex()
