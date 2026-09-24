# JOCKY

JOCKY is an under-development Smart India Hackathon project for expressing forensic collection workflows in a small declarative language and compiling them into a traceable execution pipeline. The repository currently contains a working language/compiler prototype, native Windows collection experiments, a multi-agent controller, a FastAPI management API, and an integrity layer.

This is not a finished product. Several components are prototypes, stubs, or planned integrations. The status labels in the documentation are deliberate.

## Overview

The proposed system lets an investigator describe a case and ordered forensic operations in a `.jky` script. The current compiler parses and validates that script, emits LLVM IR, optionally applies IR transformations, invokes Clang, and records a signed hash-chain event. The runtime, remote-agent, dashboard UI, and production deployment model remain incomplete.

## Problem Statement

Forensic work often combines repeatable collection steps, native tools, and case documentation. The project explores whether a constrained language and a verifiable evidence trail can make those workflows easier to review and repeat. The repository does not yet provide evidence that it is production-ready or court-admissible in a particular jurisdiction.

## Motivation

JOCKY is intended for authorized incident-response and forensic research in controlled environments. Its design separates workflow description, validation, execution backends, orchestration, and integrity records.

## Proposed Solution

```text
.jky script -> grammar/parser -> validation -> LLVM IR -> native build
									  |
									  +-> integrity record
native collectors / proposed agents -> controller -> API -> proposed UI
```

The diagram describes the target direction, not a claim that every arrow is integrated today.

## Key Features

- Implemented grammar, LALR parser, indentation handling, and parse errors.
- Implemented section-order, duplicate-section, and command compatibility validation.
- Implemented LLVM IR generation and a compiler CLI.
- Implemented SHA-256 hash chaining, Ed25519 signing, and chain verification.
- Partially implemented controller, FastAPI API, SSE stream, and Windows-native collectors.
- Prototype transport and build-transformation components that require security review.

## System Architecture

See [docs/architecture.md](docs/architecture.md), [docs/data-flow.md](docs/data-flow.md), and [docs/current-status.md](docs/current-status.md).

## End-to-End Workflow

See [docs/end-to-end-workflow.md](docs/end-to-end-workflow.md). The verified local path is the compiler path; remote task execution is not end to end.

## Core Components

| Component | Status | Evidence |
|---|---|---|
| Grammar and parser | IMPLEMENTED | `language/grammar/JOCKY.lark`, `language/lexer_parser/parser.py` |
| Validation | IMPLEMENTED | `language/lexer_parser/validator.py` |
| Dedicated AST | NOT FOUND | `ast_nodes.py` is a placeholder; Lark trees are used |
| Interpreter | PROTOTYPE | `interpreter.py` dispatches to print-only stubs |
| LLVM IR | IMPLEMENTED | `language/llvm_frontend/ir_generator.py` |
| Controller | PARTIALLY IMPLEMENTED | `management_interface/agent_controller.py` |
| API | PARTIALLY IMPLEMENTED | `management_interface/dashboard/api.py` |
| Integrity | PARTIALLY IMPLEMENTED | `integrity/` |
| Database and dashboard UI | NOT FOUND | No database schema or frontend source found |

## Technology Stack

Python, Lark, llvmlite, FastAPI, Uvicorn, Pydantic, cryptography, optional pefile, Clang, and Windows C APIs are present or referenced. See [docs/technology-stack.md](docs/technology-stack.md) for status and caveats.

## Current Development Status

The compiler smoke check passed on the supplied example: parse, validation, LLVM IR generation, Clang compilation, and chain signing completed. The repository has no dependency manifest, CI configuration, general Python test suite, or completed frontend. `pytest` was unavailable in the audit environment, so the transport test file was not executed.

## Project Structure

```text
language/                 grammar, parser, validator, interpreter, LLVM IR
execution_engine/         native Windows experiments and forensic collectors
forensic_primitives/      Python placeholders
management_interface/     controller and FastAPI API
transport/                experimental encrypted transport components
integrity/                hash chain, signing, verification, Log B collector
build_pipeline/           IR and PE transformation experiments
evidence/                 sample chains and key material; review before sharing
docs/                     architecture and implementation documentation
```

## Installation

No supported installer or dependency lockfile exists yet. The observed Python imports include `lark`, `llvmlite`, `cryptography`, `fastapi`, `uvicorn`, `pydantic`, and optionally `pefile`. Native compilation requires a suitable Clang toolchain and Windows libraries. Use an isolated environment and only authorized test systems.

## Running the Current Prototype

```powershell
python main.py compile language/grammar/example_scripts/ransomware_triage.jky --output build
python main.py verify build/chain.json
python language/lexer_parser/parser.py language/grammar/example_scripts/ransomware_triage.jky
python management_interface/dashboard/api.py
```

The `run` command reaches the stub interpreter path, not a production forensic agent. The API is a prototype and should not be exposed beyond localhost.

## Testing

Native harnesses and an offline transport test file exist, but there is no repository-wide test runner configuration. See [docs/testing-strategy.md](docs/testing-strategy.md).

## Development Roadmap

See [docs/development-roadmap.md](docs/development-roadmap.md).

## Limitations

The dedicated AST, Python primitive layer, database, dashboard frontend, real agent command dispatch, and production authentication are incomplete. The transport and obfuscation code is experimental and requires independent review. See [docs/limitations.md](docs/limitations.md).

## Future Scope

Complete the safe compiler/runtime contract, replace stubs with reviewed authorized collection adapters, define a versioned API and storage model, add tests and CI, and perform threat modeling and legal/safety review.

## Documentation

Start with [docs/project-overview.md](docs/project-overview.md), then read [docs/current-status.md](docs/current-status.md) and [docs/architecture.md](docs/architecture.md). The SIH-oriented narrative is in [docs/SIH-PRESENTATION-GUIDE.md](docs/SIH-PRESENTATION-GUIDE.md), and the evidence audit is in [docs/documentation-audit.md](docs/documentation-audit.md).

## Contributing

Contributions should include evidence for claims, focused tests where possible, and an explicit status update when a component changes from prototype to implemented. Do not add credentials, private keys, captured evidence, or unauthorized deployment instructions.

## License

No license file was found in the supplied repository. Add a license before accepting external contributions.
