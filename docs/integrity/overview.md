# Integrity Overview

`integrity/hash_chain.py` appends entries containing IDs, UTC timestamps,
events, data, previous hashes, and entry hashes. `integrity/signing.py` adds
Ed25519 signatures when `cryptography` is available. `integrity/verifier.py`
checks JSONL parsing, sequential IDs, hashes, links, and optional signatures.

Status: PARTIALLY IMPLEMENTED. Key governance, API integration, and evidence
format consistency remain unfinished.