# IR Transformation

The current repository includes CFG generation in `ir_generator.py`, LLVM
identifier renaming in `build_pipeline/obfuscator/var_renamer.py`, and string
transformation experiments in `string_encryptor.py`. `cf_obfuscator.py` and
`binary_mutator.py` are placeholders or incomplete passes. The nested PE
pipeline under `build_pipeline/polymorphic_engine/` is not wired to the CLI's
expected top-level import path.

Status: PARTIALLY IMPLEMENTED. Transformations require output-validity tests,
reproducibility expectations, review of generated artifacts, and a documented
authorization boundary.