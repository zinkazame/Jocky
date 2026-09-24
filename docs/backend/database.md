# Database

No database schema, migration, ORM, or database adapter was found. Current
controller state is in memory and integrity chains are file-backed JSONL.

## Proposed model

An eventual store should separate cases, agents, tasks, result metadata, chain
locations, verification reports, and audit events. It should store hashes and
references rather than silently replacing evidence. The schema, retention,
access control, and migration policy are PLANNED.