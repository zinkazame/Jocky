# Interpreter

`language/lexer_parser/interpreter.py` walks validated trees, extracts context
and arguments, dispatches operations, and returns structured records. Each
dispatch target is currently a print-only stub and records
`STUB - not yet implemented`.

Status: PROTOTYPE. It is useful for validating traversal and result shape, but
it is not a live collection runtime. Replace stubs with reviewed, bounded
adapter interfaces and explicit authorization checks before calling it complete.