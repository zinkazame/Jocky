# Parser

`language/lexer_parser/parser.py` builds a Lark LALR parser from the grammar,
uses `JOCKYIndenter` for `_INDENT` and `_DEDENT`, exposes `parse()` and
`parse_file()`, and translates Lark failures into `JOCKYParseError` messages
with line and column information. It also has a standalone CLI.

Status: IMPLEMENTED. The output is a Lark `Tree`, not a stable project-owned
AST. Parser tests should be added to the repository test suite.