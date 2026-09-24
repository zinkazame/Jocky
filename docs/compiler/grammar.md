# Grammar

`language/grammar/JOCKY.lark` defines a case header, one or more ordered
sections, and operations such as `acquire process_list()` and
`inspect registry(key="...")`. It uses Lark named terminals, comments, and an
indentation post-lexer. Section order and uniqueness are intentionally deferred
to validation. Example scripts are under `language/grammar/example_scripts/`.

Status: IMPLEMENTED grammar; language versioning and a dedicated lexer module
remain incomplete.