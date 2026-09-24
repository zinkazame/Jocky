# SIH Presentation Guide

## One-line explanation

JOCKY is an under-development declarative forensic workflow and integrity prototype that turns reviewed case scripts into traceable native build artifacts.

## Problem

Forensic workflows combine ordered collection steps, case metadata, platform adapters, and evidence provenance. A constrained, reviewable workflow model may reduce ambiguity, but this benefit is still a project hypothesis.

## Proposed solution and innovation

JOCKY combines a domain-specific language, validation, LLVM-based generation, orchestration concepts, and tamper-evident event chaining. The innovation claim is architectural; the repository does not contain comparative evaluation.

## Architecture and stack

Explain the path: grammar -> parser -> validator -> IR -> native build -> collection adapters -> controller -> API -> future UI, with integrity records along the evidence path. Mention Python, Lark, llvmlite, Clang, FastAPI, and cryptography, separating present code from proposed integrations.

## Feasibility

The local compiler and integrity path has runnable evidence. Feasibility risks are native ABI stability, Windows privilege boundaries, secure orchestration, test coverage, storage, and legal/safety review.

## Current progress

Implemented: grammar, parser, validation, IR generation, hash chain, signing, verification. Partial/prototype: native collectors, controller, API, transport, build transformations. Missing: dedicated AST, database, frontend, and complete agent dispatch.

## Roadmap and expected outcome

Prioritize a safe typed AST and adapter contract, then mock-agent controller integration, authenticated storage/API, a read-only UI, and isolated evaluation. The expected outcome is a demonstrable, reviewable prototype, not a claim of production deployment.

## Common judge questions

**What works today?** The compiler smoke path and integrity primitives; several other components are partial.

**Is it a finished SOC platform?** No. The project is under development.

**Does the interpreter collect live data?** No. It records stub results; native collectors are separate experiments.

**Is there a dashboard?** There is a FastAPI prototype, but no frontend was found.

**How is evidence checked?** Hash-chain links and optional Ed25519 signatures are implemented, subject to integration and key-management work.

**What is the largest gap?** End-to-end, authorized integration with tests, authentication, persistence, and a clear safety model.

**Why should the proposal be funded?** To validate whether the compiler and integrity design can support repeatable forensic workflows under measured, controlled conditions.