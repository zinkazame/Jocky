# Documentation Audit

This audit reflects the supplied repository at the time of documentation
generation. It distinguishes source evidence from architectural intent.

## IMPLEMENTED

- Lark grammar and example `.jky` scripts.
- LALR parser with indentation handling and parser CLI.
- Three validator constraints and validation CLI.
- LLVM IR generation and compiler CLI path.
- SHA-256 hash-chain append/verify logic.
- Ed25519 signing and standalone verification logic when dependencies exist.

## PARTIALLY IMPLEMENTED

- Dedicated lexical and AST layers.
- Native forensic bridge and collectors.
- IR/build transformation integration.
- Agent runtime and controller integration.
- FastAPI management API and SSE support.
- Evidence/API integration and operational configuration.

## PROTOTYPE

- Stub interpreter.
- Transport and cloud-shaped message wrapper.
- Domain-fronting and retry/circuit-breaker experiments.
- Native execution-engine experiments and harnesses.

## PLANNED

- Typed AST and policy-aware semantic model.
- Complete authorized adapter/runtime contract.
- Versioned authenticated controller protocol.
- Durable database and production service layer.
- Read-only dashboard frontend.
- CI, dependency locking, integration testing, and formal evaluation.

## NOT FOUND

- Repository-level dependency manifest.
- CI workflow and general Python test suite.
- Database schema/adapter.
- Dashboard frontend source.
- Complete end-to-end agent dispatch implementation.
- License file.

## Architectural questions

- What is the supported, authorized deployment boundary for native collectors?
- Is remote orchestration required for the SIH prototype, or is local compilation enough?
- Which evidence schema and storage format is authoritative: JSONL, JSON API objects, or a database model?
- How will private keys, agent identity, rotation, and operator authorization be governed?
- Which transformation features are necessary for the research goal and which should be removed?
- What Windows versions, privileges, compilers, and Python versions are supported?
- What measurable criteria define success for repeatability, integrity, and usability?

## Recommended next steps

1. Remove credentials, private keys, captured evidence, drivers, and generated binaries from any public release unless their provenance and licensing are clear.
2. Add a dependency manifest and a minimal CI job for parser, validator, IR, and integrity tests.
3. Define a typed AST and a versioned task/result schema.
4. Resolve JSONL versus JSON API handling and add tamper/format regression tests.
5. Build a mock-agent integration before connecting any real collection adapter.
6. Add authentication, authorization, least privilege, and threat modeling before exposing the API.
7. Decide whether to implement or remove the dashboard and database from the SIH scope.