# DORM — Post-Parse Validation Rules
# Version: 0.1.0
#
# These three constraints cannot be expressed in Lark's grammar rules.
# They are enforced in Python code in Phase 3 (tree-walking interpreter),
# after the grammar has already accepted the script as syntactically valid.
# Each constraint has: what it checks, valid example, invalid example.

---

## Constraint 1 — Section Order

### What it checks
Sections must appear in this exact volatility order when present:

    memory → network → system → disk

A section may be omitted entirely, but no section may appear before one
that should precede it. A `disk` section before a `memory` section is an error.

### Why it is not in the grammar
Lark's `section_block+` rule accepts any sequence of valid section names.
Encoding a specific ordering requires stateful tracking that belongs in
a post-parse visitor, not a context-free grammar.

### Valid
```
section memory
    acquire process_list()

section disk
    hash file(path="C:\suspect.exe")
```
memory comes before disk — valid even with network and system omitted.

### Invalid
```
section disk
    hash file(path="C:\suspect.exe")

section memory          # ERROR: memory must precede disk
    acquire process_list()
```

### Enforcement (Phase 3 pseudocode)
```python
VALID_ORDER = ["memory", "network", "system", "disk"]

def validate_section_order(section_names: list[str]):
    positions = [VALID_ORDER.index(name) for name in section_names]
    if positions != sorted(positions):
        raise DormValidationError("Sections are out of volatility order.")
```

---

## Constraint 2 — No Duplicate Sections

### What it checks
Each section name (memory, network, system, disk) may appear at most once
in a script. Two `section memory` blocks in the same script is an error.

### Why it is not in the grammar
`section_block+` allows any number of section blocks. The grammar has no
mechanism to assert uniqueness of a child's string value across siblings.

### Valid
```
section memory
    acquire process_list()

section network
    acquire connections()
```

### Invalid
```
section memory
    acquire process_list()

section memory          # ERROR: memory already declared
    acquire cpu_registers()
```

### Enforcement (Phase 3 pseudocode)
```python
def validate_no_duplicate_sections(section_names: list[str]):
    seen = set()
    for name in section_names:
        if name in seen:
            raise DormValidationError(f"Duplicate section: '{name}'")
        seen.add(name)
```

---

## Constraint 3 — Command–Primitive Compatibility

### What it checks
Not every command is valid with every primitive. The grammar allows any
NAME as a primitive after any command. The validator enforces a strict
compatibility table.

### Compatibility table

| Command  | Valid primitives                                          |
|----------|-----------------------------------------------------------|
| acquire  | process_list, memory_region, cpu_registers, connections, dns_cache |
| capture  | traffic                                                   |
| inspect  | registry, services, startup_items, file_metadata, recent_files |
| hash     | file                                                      |

### Valid
```
hash file(path="C:\suspect\invoice.pdf")
acquire process_list()
capture traffic(duration=30, interface="eth0")
inspect registry(key="HKLM\Software\Run")
```

### Invalid
```
hash process_list()     # ERROR: hash only applies to file
capture registry()      # ERROR: capture only applies to traffic
acquire traffic()       # ERROR: traffic is a capture primitive, not acquire
```

### Enforcement (Phase 3 pseudocode)
```python
COMPAT = {
    "acquire": {"process_list", "memory_region", "cpu_registers",
                "connections", "dns_cache"},
    "capture": {"traffic"},
    "inspect": {"registry", "services", "startup_items",
                "file_metadata", "recent_files"},
    "hash":    {"file"},
}

def validate_command_primitive(command: str, primitive: str, line: int):
    if primitive not in COMPAT[command]:
        raise DormValidationError(
            f"Line {line}: '{command}' is not compatible with '{primitive}'."
        )
```

---

## Summary table

| # | What fails | Grammar catches it? | Validator catches it? |
|---|------------|--------------------|-----------------------|
| 1 | Wrong section order | No | Yes — Phase 3 |
| 2 | Duplicate section   | No | Yes — Phase 3 |
| 3 | Bad command-primitive pair | No | Yes — Phase 3 |

All three validators run together in a single `validate(tree)` function
called immediately after `parser.parse(script_text)` returns.
