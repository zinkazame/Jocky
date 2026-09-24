# Validator

`language/lexer_parser/validator.py` implements three checks:

1. Sections follow memory, network, system, disk order.
2. A section cannot appear twice.
3. Each command is paired with an allowed primitive.

It raises `JOCKYValidationError` with a constraint and source line where
available. Argument types and policy/authorization checks are not implemented.

Status: IMPLEMENTED for the documented three constraints; PARTIALLY IMPLEMENTED
as a complete semantic policy layer.