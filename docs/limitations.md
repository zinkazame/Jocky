# Limitations

- The project is under development and lacks a supported release process.
- `ast_nodes.py`, `lexer.py`, and Python forensic primitive modules are placeholders.
- The interpreter returns stub records rather than performing collection.
- Several native bridge functions are no-ops or incomplete.
- Transport command dispatch is an explicit hook; live communication is unvalidated.
- The dashboard API has permissive CORS, hardcoded demo values, and no authentication.
- The API reads chain files with `json.load()` while the integrity engine writes JSONL.
- No database, frontend, CI, dependency manifest, or repository-wide test suite was found.
- The CLI expects a top-level `build_pipeline/pipeline.py`, while the available pipeline is nested under `build_pipeline/polymorphic_engine/`.
- Sample keys, evidence, drivers, and compiled binaries require careful handling before publication or sharing.
- Platform privileges, Windows versions, compilers, and cryptographic libraries affect reproducibility.
- Safety-sensitive execution-engine and transport experiments need threat modeling, authorization controls, and independent review.