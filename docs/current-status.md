# Current Status

| Component | Status | Evidence in project | Planned purpose |
|---|---|---|---|
| Grammar | IMPLEMENTED | `language/grammar/JOCKY.lark`, examples | Define `.jky` syntax |
| Lexer module | PARTIALLY IMPLEMENTED | `lexer.py` is placeholder; Lark lexes grammar | Dedicated lexical layer |
| Parser | IMPLEMENTED | `parser.py`, LALR, indenter, CLI | Build parse trees |
| AST | PARTIALLY IMPLEMENTED | Lark trees; `ast_nodes.py` placeholder | Stable semantic model |
| Validator | IMPLEMENTED | `validator.py` | Enforce semantic constraints |
| Interpreter | PROTOTYPE | Print-only operation stubs | Local execution |
| IR generation | IMPLEMENTED | `ir_generator.py` | Emit native-call IR |
| IR transformation | PARTIALLY IMPLEMENTED | CFG and variable transforms; placeholders remain | Controlled transformation passes |
| Build pipeline | PARTIALLY IMPLEMENTED | `main.py`, nested polymorphic pipeline | Produce reviewed native artifacts |
| Agent runtime | PARTIALLY IMPLEMENTED | transport check-in loop; dispatch hook | Run authorized tasks |
| Controller | PARTIALLY IMPLEMENTED | `agent_controller.py` | Coordinate agents and results |
| Evidence collection | PARTIALLY IMPLEMENTED | native C collectors; bridge no-ops | Collect forensic artifacts |
| Integrity | PARTIALLY IMPLEMENTED | hash chain, signer, verifier | Detect alteration and verify records |
| Transport | PROTOTYPE | router, wrapper, fronting code, offline test file | Secure communication contract |
| Backend API | PARTIALLY IMPLEMENTED | FastAPI routes in `api.py` | Expose management operations |
| Database | NOT FOUND | No schema or adapter found | Durable storage |
| Dashboard UI | NOT FOUND | No frontend source found | Human-facing view |

## Current versus target

| Component | Current state | Target state | Remaining work |
|---|---|---|---|
| Language | Grammar and parse tree | Versioned language and AST | Dedicated AST, compatibility tests |
| Runtime | Stub interpreter and native experiments | Reviewed adapter interface | Replace stubs; authorization and error contracts |
| Controller | In-memory state and asyncio loop | Durable, authenticated orchestration | Protocol integration, persistence, recovery |
| Integrity | Hash/sign/verify modules | Auditable evidence lifecycle | Fix format consistency and key governance |
| API | Prototype routes and SSE | Authenticated versioned service | Validation, auth, storage, tests |
| UI | No frontend | Scanning-oriented dashboard | Implement UI and accessibility tests |