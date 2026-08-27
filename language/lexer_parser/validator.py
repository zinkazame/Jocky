"""
JOCKY Forensic Language — Validator  (Phase 3)
===============================================
Single responsibility: enforce the three post-parse constraints from
validation_rules.md against a parse tree returned by Phase 2.

Accepts: lark.Tree from parser.parse()
Returns: None on success, raises JockyValidationError on violation.

Nothing else. No execution. No output writing.
"""

from __future__ import annotations

import sys
from pathlib import Path

from lark import Tree

# ─── Exception ───────────────────────────────────────────────────────────────

class JockyValidationError(Exception):
    """
    Raised when a syntactically valid .jky tree violates a semantic constraint.
    Always contains a human-readable message identifying which constraint
    failed and exactly where.
    """
    pass


# ─── Constants ───────────────────────────────────────────────────────────────

# Volatility order — the only valid ordering of sections when present.
_SECTION_ORDER: list[str] = ["memory", "network", "system", "disk"]

# Command → valid primitives (Constraint 3 compatibility table).
_COMPAT: dict[str, set[str]] = {
    "acquire": {"process_list", "memory_region", "cpu_registers",
                "connections", "dns_cache"},
    "capture": {"traffic"},
    "inspect": {"registry", "services", "startup_items",
                "file_metadata", "recent_files"},
    "hash":    {"file"},
}


# ─── Public API ──────────────────────────────────────────────────────────────

def validate(tree: Tree) -> None:
    """
    Run all three validation constraints against a JOCKY parse tree.

    Constraints are run in this order:
      1. Section order      (memory → network → system → disk)
      2. No duplicate sections
      3. Command-primitive compatibility

    Parameters
    ----------
    tree : lark.Tree
        Tree returned by parser.parse() / parser.parse_file().
        Must have been produced with keep_all_tokens=True (set in parser.py).

    Raises
    ------
    JockyValidationError
        On the first constraint violation found.
    """
    section_names = _extract_section_names(tree)
    _validate_section_order(section_names)
    _validate_no_duplicates(section_names)
    _validate_command_primitive(tree)


# ─── Tree traversal helper ───────────────────────────────────────────────────

def _extract_section_names(tree: Tree) -> list[str]:
    """
    Walk the tree and return section names in the order they appear.

    Uses tree.find_data("section_block") — Lark's built-in generator that
    yields every node whose .data == "section_block", depth-first.

    Example return value: ["memory", "network", "disk"]
    """
    names: list[str] = []
    for section_block in tree.find_data("section_block"):
        # section_block.children layout:
        #   [0]  section_name node  (Tree)
        #   [1+] operation nodes
        sn_node = _first_tree_child(section_block, "section_name")
        # sn_node.children[0] is the string-literal Token, e.g. Token('MEMORY','memory')
        # str() normalises it to the raw string value.
        names.append(str(sn_node.children[0]))
    return names


# ─── Constraint 1: section order ─────────────────────────────────────────────

def _validate_section_order(section_names: list[str]) -> None:
    """
    Sections present in the script must appear in volatility order.
    Absent sections are allowed. A section appearing after one that
    should follow it is a hard error.
    """
    positions = [_SECTION_ORDER.index(name) for name in section_names]
    for i in range(1, len(positions)):
        if positions[i] < positions[i - 1]:
            raise JockyValidationError(
                f"Constraint 1 — Section order violation: "
                f"'{section_names[i]}' appears after '{section_names[i - 1]}' "
                f"but must precede it in volatility order.\n"
                f"  Required order: {' → '.join(_SECTION_ORDER)}"
            )


# ─── Constraint 2: no duplicate sections ─────────────────────────────────────

def _validate_no_duplicates(section_names: list[str]) -> None:
    """Each section name may appear at most once in a script."""
    seen: set[str] = set()
    for name in section_names:
        if name in seen:
            raise JockyValidationError(
                f"Constraint 2 — Duplicate section: "
                f"'{name}' is declared more than once."
            )
        seen.add(name)


# ─── Constraint 3: command-primitive compatibility ────────────────────────────

def _validate_command_primitive(tree: Tree) -> None:
    """
    Every operation node must use a command-primitive pair in _COMPAT.

    Walks all operation nodes across all sections via find_data().
    Reports line number when propagate_positions=True was set on the parser.
    """
    for operation in tree.find_data("operation"):
        command_node   = _first_tree_child(operation, "command")
        primitive_node = _first_tree_child(operation, "primitive")

        command_str   = str(command_node.children[0])
        primitive_str = str(primitive_node.children[0])

        allowed = _COMPAT.get(command_str, set())
        if primitive_str not in allowed:
            line = getattr(operation.meta, "line", "?")
            raise JockyValidationError(
                f"Constraint 3 — Command-primitive mismatch at line {line}: "
                f"'{command_str}' cannot be used with '{primitive_str}'.\n"
                f"  Valid primitives for '{command_str}': "
                f"{', '.join(sorted(allowed))}"
            )


# ─── Internal helpers ─────────────────────────────────────────────────────────

def _first_tree_child(node: Tree, rule_name: str) -> Tree:
    """
    Return the first direct child of *node* that is a Tree with .data == rule_name.
    Raises AssertionError (internal bug) if not found — keeps constraint code clean.
    """
    for child in node.children:
        if isinstance(child, Tree) and child.data == rule_name:
            return child
    raise AssertionError(
        f"Expected child '{rule_name}' in node '{node.data}' — "
        "this is a parser/grammar bug, not a user error."
    )


# ─── CLI ──────────────────────────────────────────────────────────────────────

def _main() -> None:
    """
    Usage: python validator.py <script.jky>

    Runs parse then validate.
    Exit 0 — both passed.
    Exit 1 — parse error or validation error (details on stderr).
    """
    # Make the sibling parser.py importable when running this file directly.
    _pkg = Path(__file__).resolve().parent
    if str(_pkg) not in sys.path:
        sys.path.insert(0, str(_pkg))

    from parser import JockyParseError, parse_file  # language/lexer_parser/parser.py

    if len(sys.argv) != 2:
        print("Usage: python validator.py <script.jky>", file=sys.stderr)
        sys.exit(1)

    script_path = Path(sys.argv[1])
    if not script_path.exists():
        print(f"Error: file not found — {script_path}", file=sys.stderr)
        sys.exit(1)

    # Step 1 — parse
    try:
        tree = parse_file(script_path)
    except JockyParseError as exc:
        print(f"Parse error:\n  {exc}", file=sys.stderr)
        sys.exit(1)
    print(f"Parse successful — {script_path.name}")

    # Step 2 — validate
    try:
        validate(tree)
    except JockyValidationError as exc:
        print(f"Validation error:\n  {exc}", file=sys.stderr)
        sys.exit(1)
    print("Validation passed.")


if __name__ == "__main__":
    _main()
