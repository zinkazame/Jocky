# Development Roadmap

| Phase | Goal | Current status | Definition of done |
|---|---|---|---|
| 1. Language definition | Freeze syntax and safety constraints | PARTIALLY IMPLEMENTED | Versioned grammar and negative tests |
| 2. Parser and AST | Replace direct tree coupling with semantic nodes | PARTIALLY IMPLEMENTED | AST API and parser tests |
| 3. Validation | Validate types, arguments, authorization policy | PARTIALLY IMPLEMENTED | Deterministic diagnostics and tests |
| 4. Interpreter | Safe local adapter execution | PROTOTYPE | No stubs; bounded, auditable adapters |
| 5. IR generation | Stable ABI and reproducible output | IMPLEMENTED | ABI tests and reproducible fixtures |
| 6. Transformations | Review optional transformation passes | PARTIALLY IMPLEMENTED | Validity tests and security review |
| 7. Native collectors | Complete supported evidence adapters | PARTIALLY IMPLEMENTED | Privilege/error tests on isolated hosts |
| 8. Controller | Integrate task lifecycle and results | PARTIALLY IMPLEMENTED | Contract tests with a mock agent |
| 9. Backend/storage | Add authenticated API and database | PLANNED | Migration, API, and recovery tests |
| 10. Dashboard | Build a read-only first UI | NOT FOUND | UI tests and evidence traceability |
| 11. Integration | Connect only approved components | PLANNED | Reproducible local integration run |
| 12. Evaluation | Threat model, legal review, performance | PLANNED | Signed review and published limitations |

Dependencies flow from language -> compiler -> adapters -> controller -> API/storage -> UI -> integration. Integrity and testing should accompany every phase.