# Problem Statement

## Problem

Forensic collection can involve heterogeneous commands, platform-specific backends, case metadata, and evidence handling. Without a constrained workflow, ordering and provenance decisions may be difficult to review consistently.

## Proposed response

JOCKY proposes a small language, compiler pipeline, orchestration layer, and integrity record. The language makes required metadata and operation order explicit; the compiler creates a repeatable intermediate artifact; the integrity layer links events for later verification.

## Facts versus expected benefits

Implemented facts are documented in [current-status.md](current-status.md). Expected benefits such as repeatability, easier review, and centralized status visibility are design goals, not measured outcomes. No comparative study or production validation is present in the repository.