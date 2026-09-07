"""
DORM Forensic Language — Interpreter  (Phase 4)
=================================================
Single responsibility: walk a validated parse tree and execute each
operation by dispatching to a stub function.

Stubs print what the real primitive would do — no OS calls happen here.
Phase 12 replaces each stub body with a real implementation.
The dispatch table, context, and result structure never change.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from lark import Tree


# ─── Execution context ────────────────────────────────────────────────────────

@dataclass
class ExecutionContext:
    """
    Immutable per-run context built from the case block header.
    Passed to every operation so Phase 12 backends know which machine
    to target and whether to use local or remote acquisition paths.
    """
    case_id:  str
    operator: str
    target:   str
    mode:     str


# ─── Public API ───────────────────────────────────────────────────────────────

def interpret(tree: Tree) -> list[dict]:
    """
    Walk a validated DORM parse tree and execute each operation.

    Parameters
    ----------
    tree : lark.Tree
        Must have already passed validate(). Calling interpret() on an
        unvalidated tree is undefined behavior — the validator is the
        contract; the interpreter trusts it.

    Returns
    -------
    list[dict]
        One record per executed operation, in script order.
        Keys: case_id, operator, section, command, primitive, args,
              result, timestamp.
        This list is the raw input for the Phase 16 integrity engine —
        do not change the key names without updating Phase 16.
    """
    case_block = _first_tree_child(tree, "case_block")
    ctx = _extract_context(case_block)

    print(f"Case:     {ctx.case_id}")
    print(f"Operator: {ctx.operator}")
    print(f"Target:   {ctx.target}")
    print(f"Mode:     {ctx.mode}")

    results: list[dict] = []

    for section_block in tree.find_data("section_block"):
        _execute_section(section_block, ctx, results)

    print(f"\nExecution complete. {len(results)} operations recorded.")
    return results


# ─── Context extraction ───────────────────────────────────────────────────────

def _extract_context(case_block: Tree) -> ExecutionContext:
    return ExecutionContext(
        case_id  = _get_string_value(_first_tree_child(case_block, "id_field")),
        operator = _get_string_value(_first_tree_child(case_block, "operator_field")),
        target   = _get_string_value(_first_tree_child(case_block, "target_field")),
        mode     = _get_string_value(_first_tree_child(case_block, "mode_field")),
    )


# ─── Section / operation execution ───────────────────────────────────────────

def _execute_section(
    section_block: Tree,
    ctx: ExecutionContext,
    results: list[dict],
) -> None:
    sn_node      = _first_tree_child(section_block, "section_name")
    section_name = str(sn_node.children[0])

    print(f"\n--- section: {section_name} ---")

    for child in section_block.children:
        if isinstance(child, Tree) and child.data == "operation":
            _execute_operation(child, section_name, ctx, results)


def _execute_operation(
    operation: Tree,
    section_name: str,
    ctx: ExecutionContext,
    results: list[dict],
) -> None:
    command_node   = _first_tree_child(operation, "command")
    primitive_node = _first_tree_child(operation, "primitive")

    command_str   = str(command_node.children[0])
    primitive_str = str(primitive_node.children[0])

    # arglist is optional — search children rather than assume index
    arglist_node: Tree | None = None
    for child in operation.children:
        if isinstance(child, Tree) and child.data == "arglist":
            arglist_node = child
            break

    args = _extract_args(arglist_node)

    stub_fn = _DISPATCH.get((command_str, primitive_str))
    if stub_fn is None:
        raise RuntimeError(
            f"No stub registered for ({command_str!r}, {primitive_str!r}). "
            "This pair should have been rejected by the validator."
        )

    stub_fn(args)

    results.append({
        "case_id":   ctx.case_id,
        "operator":  ctx.operator,
        "section":   section_name,
        "command":   command_str,
        "primitive": primitive_str,
        "args":      args,
        "result":    "STUB — not yet implemented",
        "timestamp": datetime.now(tz=timezone.utc).isoformat(timespec="seconds"),
    })


# ─── Argument extraction ──────────────────────────────────────────────────────

def _extract_args(arglist_node: Tree | None) -> dict:
    """
    Convert an arglist tree node into a plain Python dict.

    Token type determines value handling:
      STRING  → strip surrounding double-quotes, keep as str
      INTEGER → convert to int
      NAME    → keep as str (no quotes to strip)
    """
    if arglist_node is None:
        return {}

    args: dict = {}
    for argument in arglist_node.children:
        if not (isinstance(argument, Tree) and argument.data == "argument"):
            continue
        name_node  = _first_tree_child(argument, "arg_name")
        value_node = _first_tree_child(argument, "arg_value")

        name        = str(name_node.children[0])
        value_token = value_node.children[0]
        tok_type    = getattr(value_token, "type", "")

        if tok_type == "STRING":
            value: str | int = str(value_token)[1:-1]   # strip surrounding quotes
        elif tok_type == "INTEGER":
            value = int(str(value_token))
        else:                                             # NAME or unrecognised
            value = str(value_token)

        args[name] = value

    return args


# ─── Stub functions ───────────────────────────────────────────────────────────
# Convention:
#   - receives the parsed args dict for that operation
#   - prints exactly one [STUB] line
#   - Phase 12 replaces the print() with a real OS call
#   - _DISPATCH and all callers remain untouched

def _fmt_call(command: str, primitive: str, args: dict) -> str:
    """Format `command primitive(k=v, ...)` for [STUB] output lines."""
    if not args:
        return f"{command} {primitive}()"
    parts = [
        f'{k}="{v}"' if isinstance(v, str) else f"{k}={v}"
        for k, v in args.items()
    ]
    return f"{command} {primitive}({', '.join(parts)})"


def _stub_process_list(args: dict) -> None:
    print(f"[STUB] {_fmt_call('acquire','process_list', args)}"
          " → would enumerate all running processes")

def _stub_memory_region(args: dict) -> None:
    pid  = args.get("pid",  "?")
    size = args.get("size", "?")
    print(f"[STUB] {_fmt_call('acquire','memory_region', args)}"
          f" → would read {size} bytes from PID {pid}")

def _stub_cpu_registers(args: dict) -> None:
    print(f"[STUB] {_fmt_call('acquire','cpu_registers', args)}"
          " → would capture CPU register state")

def _stub_connections(args: dict) -> None:
    print(f"[STUB] {_fmt_call('acquire','connections', args)}"
          " → would enumerate active network connections")

def _stub_dns_cache(args: dict) -> None:
    print(f"[STUB] {_fmt_call('acquire','dns_cache', args)}"
          " → would dump the DNS resolver cache")

def _stub_traffic(args: dict) -> None:
    duration  = args.get("duration",  "?")
    interface = args.get("interface", "?")
    print(f"[STUB] {_fmt_call('capture','traffic', args)}"
          f" → would capture {duration}s of traffic on {interface}")

def _stub_registry(args: dict) -> None:
    key = args.get("key", "?")
    print(f"[STUB] {_fmt_call('inspect','registry', args)}"
          f" → would read registry key {key}")

def _stub_services(args: dict) -> None:
    state = args.get("state", "all")
    print(f"[STUB] {_fmt_call('inspect','services', args)}"
          f" → would list {state} services")

def _stub_startup_items(args: dict) -> None:
    print(f"[STUB] {_fmt_call('inspect','startup_items', args)}"
          " → would enumerate startup items")

def _stub_file_metadata(args: dict) -> None:
    path = args.get("path", "?")
    print(f"[STUB] {_fmt_call('inspect','file_metadata', args)}"
          f" → would read metadata for {path}")

def _stub_recent_files(args: dict) -> None:
    count = args.get("count", "?")
    print(f"[STUB] {_fmt_call('inspect','recent_files', args)}"
          f" → would list {count} most recently accessed files")

def _stub_hash_file(args: dict) -> None:
    path = args.get("path", "?")
    print(f"[STUB] {_fmt_call('hash','file', args)}"
          f" → would compute SHA-256 of {path}")


# ─── Dispatch table ───────────────────────────────────────────────────────────
# Maps (command, primitive) → stub function.
# Phase 12: swap stub body for real implementation. Table never changes.

_DISPATCH: dict[tuple[str, str], Callable[[dict], None]] = {
    ("acquire", "process_list"):  _stub_process_list,
    ("acquire", "memory_region"): _stub_memory_region,
    ("acquire", "cpu_registers"): _stub_cpu_registers,
    ("acquire", "connections"):   _stub_connections,
    ("acquire", "dns_cache"):     _stub_dns_cache,
    ("capture", "traffic"):       _stub_traffic,
    ("inspect", "registry"):      _stub_registry,
    ("inspect", "services"):      _stub_services,
    ("inspect", "startup_items"): _stub_startup_items,
    ("inspect", "file_metadata"): _stub_file_metadata,
    ("inspect", "recent_files"):  _stub_recent_files,
    ("hash",    "file"):          _stub_hash_file,
}


# ─── Tree helpers ─────────────────────────────────────────────────────────────

def _first_tree_child(node: Tree, rule_name: str) -> Tree:
    """First direct child of *node* that is a Tree with .data == rule_name."""
    for child in node.children:
        if isinstance(child, Tree) and child.data == rule_name:
            return child
    raise AssertionError(
        f"Expected child '{rule_name}' in '{node.data}' — grammar/parser bug."
    )


def _get_string_value(node: Tree) -> str:
    """
    Extract the STRING token from a header field node and strip its quotes.
    Works regardless of how many anonymous tokens keep_all_tokens adds.
    """
    for child in node.children:
        if hasattr(child, "type") and child.type == "STRING":
            return str(child)[1:-1]
    raise AssertionError(f"No STRING token in '{node.data}' — grammar/parser bug.")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def _main() -> None:
    """
    Usage: python interpreter.py <script.drm>
    Full pipeline: parse → validate → interpret.
    """
    _pkg = Path(__file__).resolve().parent
    if str(_pkg) not in sys.path:
        sys.path.insert(0, str(_pkg))

    from parser    import DormParseError, parse_file       # noqa: PLC0415
    from validator import DormValidationError, validate    # noqa: PLC0415

    if len(sys.argv) != 2:
        print("Usage: python interpreter.py <script.drm>", file=sys.stderr)
        sys.exit(1)

    script_path = Path(sys.argv[1])
    if not script_path.exists():
        print(f"Error: file not found — {script_path}", file=sys.stderr)
        sys.exit(1)

    try:
        tree = parse_file(script_path)
    except DormParseError as exc:
        print(f"Parse error:\n  {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        validate(tree)
    except DormValidationError as exc:
        print(f"Validation error:\n  {exc}", file=sys.stderr)
        sys.exit(1)

    interpret(tree)


if __name__ == "__main__":
    _main()