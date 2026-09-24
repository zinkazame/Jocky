# Project Overview

## One paragraph

JOCKY is a proposed forensic workflow framework. Its language describes a case, target, mode, sections, and operations. The current repository can parse and validate those scripts, generate LLVM IR, compile a native output when Clang is available, and record a signed integrity event. Controller, transport, native collection, and API components exist at different maturity levels; a complete agent-to-dashboard product does not.

## Two-minute explanation

An investigator writes a constrained `.jky` workflow. The grammar requires a case header and ordered sections. Validation rejects duplicate or incorrectly ordered sections and incompatible command/primitive pairs. The compiler turns valid operations into calls to a declared native ABI, then optionally applies IR transformations and invokes Clang. A hash chain records compilation or evidence events, with optional Ed25519 signatures.

The repository also contains a controller with agent state and task models, a FastAPI API, transport experiments, and Windows forensic C code. These pieces are not yet a verified end-to-end deployment: the interpreter prints stubs, transport command dispatch is a hook, and no dashboard frontend or database was found.

## Intended users

The proposal is aimed at authorized incident responders, digital-forensics researchers, educators, and SIH reviewers evaluating a repeatable workflow concept. It is not documented as a general-purpose remote administration tool.

## Boundaries

Current evidence supports a compiler and integrity prototype. Claims about remote collection, operational agent deployment, stealth, court admissibility, or production scalability remain out of scope until independently validated.