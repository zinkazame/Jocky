# Compiler Overview

The compiler path is the most complete part of JOCKY:

```mermaid
flowchart LR
 A[.jky] --> B[Grammar and Lark parser]
 B --> C[Validated Lark Tree]
 C --> D[LLVM IR]
 D --> E[Clang output]
 E --> F[Signed compile event]
```

`main.py` wires parsing, validation, IR generation, optional transformations,
native compilation, and integrity recording. The parser and validator are
implemented; the dedicated AST and interpreter remain incomplete.