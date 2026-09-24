# IR Generation

`language/llvm_frontend/ir_generator.py` converts validated Lark trees into
LLVM IR using `llvmlite`. It declares the native primitive ABI, creates
`JOCKY_main()`, emits operation calls in script order, converts arguments, and
supports an optional obfuscated CFG mode. The output is written as `.ll` by
`main.py` and can be passed to Clang.

Status: IMPLEMENTED for the current ABI and output path. ABI compatibility,
deterministic builds, and complete primitive coverage require tests.