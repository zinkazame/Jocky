# Technology Stack

| Layer | Technology | Purpose | Status |
|---|---|---|---|
| Language | Lark grammar/LALR | Parse `.jky` | IMPLEMENTED |
| Compiler | Python, llvmlite | Generate LLVM IR | IMPLEMENTED |
| Native build | Clang and Windows libraries | Link collector ABI | PARTIALLY IMPLEMENTED |
| Runtime | Python stubs and C experiments | Execute collection | PROTOTYPE |
| Controller | Python asyncio/threading | Agent/task state | PARTIALLY IMPLEMENTED |
| API | FastAPI, Uvicorn, Pydantic | HTTP and SSE | PARTIALLY IMPLEMENTED |
| Integrity | hashlib, cryptography | SHA-256 and Ed25519 | PARTIALLY IMPLEMENTED |
| Transport | Python TLS/socket/crypto code | Message delivery experiment | PROTOTYPE |
| Transformations | Python, optional pefile | IR/PE transformations | PARTIALLY IMPLEMENTED |
| Storage | JSONL files | Chain persistence | PARTIALLY IMPLEMENTED |
| Database | None found | Durable service storage | PLANNED |
| Frontend | None found | Dashboard UI | NOT FOUND |

No `requirements.txt`, `pyproject.toml`, lockfile, CI workflow, or supported installation script was found.