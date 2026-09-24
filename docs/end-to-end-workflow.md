# End-to-End Workflow

## Verified local compiler path

1. A `.jky` file is read by `parse_file()`.
2. Lark creates an indentation-aware parse tree.
3. `validate()` checks section order, duplicates, and compatibility.
4. `context_from_tree()` extracts case metadata.
5. `generate_ir()` emits LLVM IR and external primitive declarations.
6. `main.py` invokes Clang when available.
7. `HashChain.append()` records a compile event and `ChainSigner` signs it.

This path was smoke-tested with the supplied ransomware triage example. The observed run generated IR, a Windows executable, and a signed chain entry.

## Not yet end to end

The `run` interpreter records stub results. The transport router receives a command but `_dispatch_command()` is a hook. The controller/API path therefore does not prove remote collection. There is no repository frontend or database.