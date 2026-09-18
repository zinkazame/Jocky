"""
JOCKY Agent Controller — Phase 15
===================================
Async multi-machine agent coordination.

Manages simultaneous connections to multiple target machines running
the JOCKY agent binary. Each agent connection is an independent asyncio
task with its own TLS session, command queue, and result buffer.

Architecture:
  AgentController
    └── AgentSession × N  (one per connected target)
          ├── TLS transport (via transport/ layer)
          ├── Command queue (asyncio.Queue)
          └── Result buffer (asyncio.Queue)

Transport:
  All traffic is routed through the transport layer (Phase 14):
  - TLS 1.3 encrypted
  - Domain fronting or cloud API wrapping
  - CDN routing

Protocol:
  JSON-framed messages over TLS:
    → {"cmd": "acquire", "primitive": "process_list", "args": {}}
    ← {"status": "ok", "data": {...}, "timestamp": "..."}

Usage:
    controller = AgentController()
    await controller.connect("192.168.1.10", port=4444, agent_id="WIN-01")
    result = await controller.send_command("WIN-01", "acquire", "process_list")
    await controller.disconnect_all()
"""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("jocky.controller")


# ─── Agent session state ──────────────────────────────────────────────────────

@dataclass
class AgentSession:
    """Represents one connected JOCKY agent."""
    agent_id:    str
    host:        str
    port:        int
    connected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen:   float = field(default_factory=time.monotonic)
    status:      str = "connected"   # connected | idle | busy | disconnected

    # asyncio transport handles (set after connect)
    reader:  asyncio.StreamReader  | None = field(default=None, repr=False)
    writer:  asyncio.StreamWriter  | None = field(default=None, repr=False)

    # Per-session queues
    cmd_queue:    asyncio.Queue = field(default_factory=asyncio.Queue, repr=False)
    result_queue: asyncio.Queue = field(default_factory=asyncio.Queue, repr=False)

    # Accumulated results for this session
    results: list[dict] = field(default_factory=list, repr=False)


# ─── Controller ───────────────────────────────────────────────────────────────

class AgentController:
    """
    Manages multiple simultaneous JOCKY agent connections.

    Parameters
    ----------
    tls_cert : str | None
        Path to TLS certificate for mutual authentication.
        If None, TLS verification is disabled (development mode only).
    heartbeat_interval : float
        Seconds between heartbeat pings to each agent.
    """

    def __init__(
        self,
        tls_cert:           str | None = None,
        heartbeat_interval: float      = 30.0,
    ) -> None:
        self._sessions:   dict[str, AgentSession] = {}
        self._tasks:      dict[str, asyncio.Task] = {}
        self._tls_cert    = tls_cert
        self._hb_interval = heartbeat_interval
        self._running     = False

    # ─── Connection management ────────────────────────────────────────────────

    async def connect(
        self,
        host:     str,
        port:     int,
        agent_id: str,
    ) -> AgentSession:
        """
        Connect to a JOCKY agent and start its session task.

        Parameters
        ----------
        host     : str   Target IP or hostname
        port     : int   Agent listener port
        agent_id : str   Unique identifier for this agent (e.g. "WIN-SUSPECT-01")

        Returns
        -------
        AgentSession
        """
        if agent_id in self._sessions:
            raise ValueError(f"Agent '{agent_id}' is already connected.")

        ssl_ctx = self._build_ssl_context()

        logger.info(f"Connecting to agent {agent_id} at {host}:{port} ...")
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx),
                timeout=10.0,
            )
        except (asyncio.TimeoutError, OSError) as exc:
            raise ConnectionError(
                f"Failed to connect to {agent_id} ({host}:{port}): {exc}"
            ) from exc

        session = AgentSession(
            agent_id = agent_id,
            host     = host,
            port     = port,
            reader   = reader,
            writer   = writer,
        )
        self._sessions[agent_id] = session

        # Start the session handler task
        task = asyncio.create_task(
            self._session_loop(session),
            name=f"agent-{agent_id}",
        )
        self._tasks[agent_id] = task

        logger.info(f"Agent {agent_id} connected.")
        return session

    async def disconnect(self, agent_id: str) -> None:
        """Gracefully disconnect an agent."""
        session = self._sessions.get(agent_id)
        if not session:
            return

        session.status = "disconnected"
        if session.writer:
            try:
                session.writer.close()
                await session.writer.wait_closed()
            except Exception:
                pass

        task = self._tasks.pop(agent_id, None)
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        del self._sessions[agent_id]
        logger.info(f"Agent {agent_id} disconnected.")

    async def disconnect_all(self) -> None:
        """Disconnect all agents."""
        for agent_id in list(self._sessions.keys()):
            await self.disconnect(agent_id)

    # ─── Command dispatch ─────────────────────────────────────────────────────

    async def send_command(
        self,
        agent_id:  str,
        command:   str,
        primitive: str,
        args:      dict[str, Any] | None = None,
        timeout:   float = 60.0,
    ) -> dict:
        """
        Send a forensic command to an agent and wait for the result.

        Parameters
        ----------
        agent_id  : str   Target agent
        command   : str   JOCKY command (acquire, inspect, capture, hash)
        primitive : str   JOCKY primitive (process_list, memory_region, etc.)
        args      : dict  Command arguments
        timeout   : float Seconds to wait for result

        Returns
        -------
        dict
            Agent response: {"status": "ok"|"error", "data": ..., "timestamp": ...}
        """
        session = self._sessions.get(agent_id)
        if not session:
            raise KeyError(f"Agent '{agent_id}' not connected.")
        if session.status == "disconnected":
            raise ConnectionError(f"Agent '{agent_id}' is disconnected.")

        msg = {
            "cmd":       command,
            "primitive": primitive,
            "args":      args or {},
            "ts":        datetime.now(timezone.utc).isoformat(),
        }

        await session.cmd_queue.put(msg)

        try:
            result = await asyncio.wait_for(session.result_queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            raise TimeoutError(
                f"Agent '{agent_id}' did not respond to "
                f"{command}/{primitive} within {timeout}s"
            )

        session.results.append(result)
        return result

    async def broadcast_command(
        self,
        command:   str,
        primitive: str,
        args:      dict[str, Any] | None = None,
        timeout:   float = 60.0,
    ) -> dict[str, dict]:
        """
        Send the same command to all connected agents simultaneously.

        Returns
        -------
        dict[agent_id, result]
        """
        tasks = {
            agent_id: asyncio.create_task(
                self.send_command(agent_id, command, primitive, args, timeout)
            )
            for agent_id in self._sessions
        }
        results: dict[str, dict] = {}
        for agent_id, task in tasks.items():
            try:
                results[agent_id] = await task
            except Exception as exc:
                results[agent_id] = {"status": "error", "error": str(exc)}
        return results

    # ─── Status ───────────────────────────────────────────────────────────────

    def list_agents(self) -> list[dict]:
        """Return status summary for all connected agents."""
        return [
            {
                "agent_id":    s.agent_id,
                "host":        s.host,
                "port":        s.port,
                "status":      s.status,
                "connected_at": s.connected_at,
                "results_count": len(s.results),
            }
            for s in self._sessions.values()
        ]

    def get_results(self, agent_id: str) -> list[dict]:
        """Return all accumulated results for an agent."""
        session = self._sessions.get(agent_id)
        if not session:
            raise KeyError(f"Agent '{agent_id}' not connected.")
        return list(session.results)

    # ─── Session loop ─────────────────────────────────────────────────────────

    async def _session_loop(self, session: AgentSession) -> None:
        """
        Per-agent asyncio task.
        Reads from cmd_queue, sends to agent, reads response, puts in result_queue.
        Also handles heartbeats and disconnection detection.
        """
        hb_task = asyncio.create_task(self._heartbeat_loop(session))
        try:
            while session.status != "disconnected":
                try:
                    # Wait for a command (with heartbeat timeout)
                    msg = await asyncio.wait_for(
                        session.cmd_queue.get(),
                        timeout=self._hb_interval,
                    )
                except asyncio.TimeoutError:
                    continue   # heartbeat loop handles pings

                session.status = "busy"
                try:
                    await self._send_json(session, msg)
                    response = await asyncio.wait_for(
                        self._recv_json(session),
                        timeout=120.0,
                    )
                    session.last_seen = time.monotonic()
                    await session.result_queue.put(response)
                except Exception as exc:
                    logger.error(f"Agent {session.agent_id} error: {exc}")
                    await session.result_queue.put(
                        {"status": "error", "error": str(exc)}
                    )
                finally:
                    session.status = "idle"

        except asyncio.CancelledError:
            pass
        finally:
            hb_task.cancel()
            try:
                await hb_task
            except asyncio.CancelledError:
                pass

    async def _heartbeat_loop(self, session: AgentSession) -> None:
        """Send periodic heartbeat pings to detect dead connections."""
        while session.status != "disconnected":
            await asyncio.sleep(self._hb_interval)
            if session.status == "idle":
                try:
                    await self._send_json(session, {"cmd": "ping"})
                    resp = await asyncio.wait_for(
                        self._recv_json(session), timeout=10.0
                    )
                    session.last_seen = time.monotonic()
                except Exception:
                    logger.warning(f"Agent {session.agent_id} heartbeat failed.")
                    session.status = "disconnected"

    # ─── Wire protocol ────────────────────────────────────────────────────────

    @staticmethod
    async def _send_json(session: AgentSession, msg: dict) -> None:
        """Send a length-prefixed JSON message."""
        data = json.dumps(msg, separators=(",", ":")).encode("utf-8")
        # 4-byte big-endian length prefix
        header = len(data).to_bytes(4, "big")
        session.writer.write(header + data)
        await session.writer.drain()

    @staticmethod
    async def _recv_json(session: AgentSession) -> dict:
        """Receive a length-prefixed JSON message."""
        header = await session.reader.readexactly(4)
        length = int.from_bytes(header, "big")
        if length > 64 * 1024 * 1024:   # 64 MB sanity cap
            raise ValueError(f"Message too large: {length} bytes")
        data = await session.reader.readexactly(length)
        return json.loads(data.decode("utf-8"))

    # ─── TLS ──────────────────────────────────────────────────────────────────

    def _build_ssl_context(self) -> ssl.SSLContext | None:
        """Build TLS 1.3 SSL context."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        if self._tls_cert:
            ctx.load_verify_locations(self._tls_cert)
        else:
            # Development mode — no cert verification
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        return ctx


# ─── CLI (quick test) ─────────────────────────────────────────────────────────

async def _demo() -> None:
    """Demo: connect to a local test agent and run process_list."""
    controller = AgentController()
    print("[controller] JOCKY Agent Controller — demo mode")
    print("[controller] No agents connected. Use the management dashboard.")
    print("[controller] Connected agents:", controller.list_agents())


if __name__ == "__main__":
    asyncio.run(_demo())
