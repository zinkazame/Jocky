# AST

The current implementation uses Lark parse trees directly. `language/lexer_parser/ast_nodes.py`
contains only a placeholder, so no dedicated node classes, visitor contract,
source-span model, or serialization format was found.

Status: PARTIALLY IMPLEMENTED. A future AST should decouple validation,
interpretation, and IR generation from grammar-specific tree layouts while
preserving source locations and case metadata.