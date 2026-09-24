# Testing Strategy

## Current evidence

- Compiler smoke path: the supplied example parsed, validated, emitted IR, compiled with Clang, and produced a signed chain entry in the audit environment.
- `transport/test_phase14.py` exists, but `pytest` was unavailable during the audit, so no pass result is claimed.
- Native harnesses exist under `execution_engine/` and require platform, compiler, and privilege-specific validation.
- `tests/` contains only `.gitkeep`; no general Python suite was found.

## Required coverage

Parser tests should cover valid and invalid indentation and syntax. Validator tests should cover all three constraints. AST tests are needed after a real AST exists. Interpreter tests must prove adapter selection, bounded errors, and no unintended side effects. IR tests should assert ABI names, argument types, and deterministic output.

Controller tests should use mock agents for registration, state transitions, timeouts, concurrent tasks, and result callbacks. API tests should cover request validation, authentication, authorization, SSE behavior, and error responses. Integrity tests should cover tampering, gaps, broken links, signatures, key rotation, and JSONL/API compatibility. End-to-end tests should run only in an isolated, explicitly authorized lab.