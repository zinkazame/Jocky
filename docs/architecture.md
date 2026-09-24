# Architecture

## High-level architecture

```mermaid
flowchart LR
  S[.jky script] --> P[Parser and validator\nIMPLEMENTED]
  P --> IR[LLVM IR generator\nIMPLEMENTED]
  IR --> B[Native build\nPARTIALLY IMPLEMENTED]
  B --> C[Reviewed collection adapters\nPARTIALLY IMPLEMENTED]
  C --> K[Controller\nPARTIALLY IMPLEMENTED]
  K --> A[FastAPI API\nPARTIALLY IMPLEMENTED]
  A --> U[Dashboard UI\nNOT FOUND]
  C --> E[Evidence records\nPARTIALLY IMPLEMENTED]
  E --> I[Hash chain and signatures\nPARTIALLY IMPLEMENTED]
  classDef implemented fill:#d8f3dc,stroke:#2d6a4f
  classDef partial fill:#fff3bf,stroke:#a07800
  classDef missing fill:#f8d7da,stroke:#9b2226
  class P,IR implemented
  class B,C,K,A,E,I partial
  class U missing
```

## Layers

| Layer | Purpose | Inputs / outputs | Status |
|---|---|---|---|
| Language | Define case and operations | `.jky` -> tokens/tree | IMPLEMENTED |
| Compiler | Validate and emit IR | parse tree -> `.ll` | IMPLEMENTED |
| Runtime/agent | Execute authorized collection | task -> result | PARTIALLY IMPLEMENTED |
| Controller | Track agents and tasks | registrations/tasks -> state/results | PARTIALLY IMPLEMENTED |
| Communication | Deliver check-ins/results | encrypted message -> response | PROTOTYPE |
| Evidence | Collect system artifacts | adapter -> result metadata | PARTIALLY IMPLEMENTED |
| Integrity | Chain and sign events | event -> JSONL entry | PARTIALLY IMPLEMENTED |
| Backend | Serve management operations | HTTP -> controller | PARTIALLY IMPLEMENTED |
| Dashboard | Present status and evidence | API -> UI | NOT FOUND |

## Compiler pipeline

```mermaid
flowchart LR
  A[Grammar JOCKY.lark\nIMPLEMENTED] --> B[Lark parser\nIMPLEMENTED]
  B --> C[Lark Tree\nPARTIAL AST]
  C --> D[Validator\nIMPLEMENTED]
  D --> E[Interpreter stubs\nPROTOTYPE]
  D --> F[LLVM IR\nIMPLEMENTED]
  F --> G[CFG/variable transforms\nPARTIAL]
  G --> H[Clang/native output\nPARTIAL]
```

## Agent and controller

The controller has `AgentState`, `AgentTask`, `AgentSession`, queues, polling, callbacks, and result retention. The transport has retry and circuit-breaker code. The command-to-collection dispatch hook remains unfinished, so the runtime is not an end-to-end agent.

## Deployment concept

```mermaid
flowchart TB
  I[Investigator workstation] --> API[Local API\nPARTIAL]
  API --> CTL[Controller\nPARTIAL]
  CTL --> AG[Authorized test agent\nPROPOSED integration]
  AG --> EV[Evidence store\nPARTIAL]
  EV --> V[Offline verifier\nIMPLEMENTED]
  DB[(Database\nPLANNED)] -.-> API
  UI[Web UI\nNOT FOUND] -.-> API
```

The deployment diagram is a target architecture, not an operational deployment instruction.