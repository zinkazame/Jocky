"""
JOCKY Forensic Language — Interpreter  (Phase 4, v0.3)
========================================================
Walks a validated parse tree and executes each operation by dispatching
to real forensic primitives.

All OS-level calls live in _primitives.py (same package).
The interpreter only handles: tree traversal, context management,
argument extraction, result accumulation, and conditional evaluation.

Result record keys (never change — Phase 16 integrity engine depends on them):
  case_id, operator, section, command, primitive, args,
  result, timestamp, suspicious, error
"""

from __future__ import annotations

import sys
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from lark import Tree


# ─── Execution context ────────────────────────────────────────────────────────

@dataclass
class ExecutionContext:
    """
    Immutable per-run context built from the case block header.
    Passed to every primitive so it knows which investigation it is
    operating under.
    """
    case_id:  str
    operator: str
    target:   str
    mode:     str


# ─── Result accumulator ───────────────────────────────────────────────────────

@dataclass
class ResultAccumulator:
    """
    Mutable runtime state that grows as operations complete.
    Used by conditional (when) blocks to decide whether to execute.
    """
    records: list[dict] = field(default_factory=list)

    # Summary counters updated after each operation
    suspicious_count: int = 0
    error_count:      int = 0
    proc_count:       int = 0
    net_count:        int = 0

    # Namespace for when-block condition evaluation
    # keys: "suspicious", "proc_count", "net_count", "error_count",
    #       "<primitive>.suspicious", "<primitive>.count", etc.
    _ns: dict[str, Any] = field(default_factory=dict)

    def push(self, record: dict) -> None:
        self.records.append(record)
        suspicious = record.get("suspicious", 0)
        self.suspicious_count += suspicious
        if record.get("error"):
            self.error_count += 1
        result = record.get("result") or {}
        if isinstance(result, dict):
            count = result.get("count", 0)
            prim  = record["primitive"]
            # per-primitive namespace
            self._ns[f"{prim}.count"]      = count
            self._ns[f"{prim}.suspicious"] = suspicious
            # top-level namespace
            self._ns["suspicious"] = self.suspicious_count
            self._ns["errors"]     = self.error_count

    def eval_cond(self, cond_str: str) -> bool:
        """
        Evaluate a when-block condition string against the accumulated namespace.
        Returns True (execute the block) on evaluation error as a safe default.
        Safe eval — only numeric comparisons and logical and/or, no code exec.
        """
        try:
            ns = {k: v for k, v in self._ns.items() if isinstance(v, (int, float, str))}
            return bool(eval(cond_str, {"__builtins__": {}}, ns))  # noqa: S307
        except Exception:
            return True  # unknown condition → execute the block (conservative)


# ─── Public API ───────────────────────────────────────────────────────────────

def interpret(tree: Tree) -> list[dict]:
    """
    Walk a validated JOCKY parse tree and execute each operation.

    Returns a list of result records (one per operation), in script order.
    Each record is suitable for blockchain / integrity signing by Phase 16.
    """
    # lazy-import primitives so the module loads even without pywin32
    from . import _primitives as P  # type: ignore[import]

    case_block = _first_tree_child(tree, "case_block")
    ctx        = _extract_context(case_block)
    acc        = ResultAccumulator()

    # Build function namespace from func_def nodes
    func_ns: dict[str, Tree] = {}
    for func_def in tree.find_data("func_def"):
        fn_name = str(_first_tree_child(func_def, "func_name").children[0])
        func_ns[fn_name] = func_def

    print(f"Case:     {ctx.case_id}")
    print(f"Operator: {ctx.operator}")
    print(f"Target:   {ctx.target}")
    print(f"Mode:     {ctx.mode}")
    print()

    for section_block in tree.find_data("section_block"):
        _execute_section(section_block, ctx, acc, func_ns, P)

    print(f"\nExecution complete. {len(acc.records)} operations, "
          f"{acc.suspicious_count} suspicious indicators, "
          f"{acc.error_count} errors.")
    return acc.records


# ─── Context extraction ───────────────────────────────────────────────────────

def _extract_context(case_block: Tree) -> ExecutionContext:
    return ExecutionContext(
        case_id  = _get_string_value(_first_tree_child(case_block, "id_field")),
        operator = _get_string_value(_first_tree_child(case_block, "operator_field")),
        target   = _get_string_value(_first_tree_child(case_block, "target_field")),
        mode     = _get_string_value(_first_tree_child(case_block, "mode_field")),
    )


# ─── Section / statement dispatch ────────────────────────────────────────────

def _execute_section(
    section_block: Tree,
    ctx:    ExecutionContext,
    acc:    ResultAccumulator,
    func_ns: dict[str, Tree],
    P:      Any,
) -> None:
    sn_node      = _first_tree_child(section_block, "section_name")
    section_name = str(sn_node.children[0])
    print(f"--- section: {section_name} ---")

    for child in section_block.children:
        if not isinstance(child, Tree):
            continue
        if child.data == "section_stmt":
            _execute_section_stmt(child, section_name, ctx, acc, func_ns, P)
        elif child.data == "operation":
            _execute_operation(child, section_name, ctx, acc, P)
        elif child.data == "cond_block":
            _execute_cond_block(child, section_name, ctx, acc, func_ns, P)
        elif child.data == "call_stmt":
            _execute_call(child, section_name, ctx, acc, func_ns, P)


def _execute_section_stmt(
    stmt:    Tree,
    section: str,
    ctx:    ExecutionContext,
    acc:    ResultAccumulator,
    func_ns: dict[str, Tree],
    P:      Any,
) -> None:
    child = stmt.children[0] if stmt.children else None
    if child is None:
        return
    if child.data == "operation":
        _execute_operation(child, section, ctx, acc, P)
    elif child.data == "cond_block":
        _execute_cond_block(child, section, ctx, acc, func_ns, P)
    elif child.data == "call_stmt":
        _execute_call(child, section, ctx, acc, func_ns, P)


def _execute_cond_block(
    cond_block: Tree,
    section:   str,
    ctx:       ExecutionContext,
    acc:       ResultAccumulator,
    func_ns:   dict[str, Tree],
    P:         Any,
) -> None:
    cond_expr_node = _first_tree_child(cond_block, "cond_expr")
    cond_str       = _flatten_cond(cond_expr_node)

    if not acc.eval_cond(cond_str):
        print(f"  [when] condition '{cond_str}' is false — skipping block")
        return

    print(f"  [when] condition '{cond_str}' is true — executing block")
    cond_body = _first_tree_child(cond_block, "cond_body")
    for child in cond_body.children:
        if isinstance(child, Tree):
            if child.data == "section_stmt":
                _execute_section_stmt(child, section, ctx, acc, func_ns, P)
            elif child.data == "operation":
                _execute_operation(child, section, ctx, acc, P)
            elif child.data == "call_stmt":
                _execute_call(child, section, ctx, acc, func_ns, P)


def _execute_call(
    call_stmt: Tree,
    section:   str,
    ctx:       ExecutionContext,
    acc:       ResultAccumulator,
    func_ns:   dict[str, Tree],
    P:         Any,
) -> None:
    fn_name = str(_first_tree_child(call_stmt, "func_name").children[0])
    fn_def  = func_ns.get(fn_name)
    if fn_def is None:
        print(f"  [call] {fn_name}() — function not found (validator missed this?)",
              file=sys.stderr)
        return

    # Extract call args as a flat dict (param_name → value)
    call_args: dict[str, Any] = {}
    for ca_node in call_stmt.find_data("call_arg"):
        name_tok  = ca_node.children[0]
        value_node = _first_tree_child(ca_node, "arg_value")
        call_args[str(name_tok)] = _decode_arg_value(value_node)

    print(f"  [call] {fn_name}({', '.join(f'{k}={v}' for k,v in call_args.items())})")

    # Execute the function body with call_args available as a local param namespace
    fn_body = _first_tree_child(fn_def, "func_body")
    for child in fn_body.children:
        if not isinstance(child, Tree):
            continue
        if child.data == "func_stmt":
            inner = child.children[0] if child.children else None
            if inner is None:
                continue
            if inner.data == "operation":
                _execute_operation(inner, section, ctx, acc, P,
                                   param_ns=call_args)
            elif inner.data == "cond_block":
                _execute_cond_block(inner, section, ctx, acc, func_ns, P)
        elif child.data == "operation":
            _execute_operation(child, section, ctx, acc, P,
                               param_ns=call_args)
        elif child.data == "cond_block":
            _execute_cond_block(child, section, ctx, acc, func_ns, P)


# ─── Operation execution ─────────────────────────────────────────────────────

def _execute_operation(
    operation:   Tree,
    section_name: str,
    ctx:         ExecutionContext,
    acc:         ResultAccumulator,
    P:           Any,
    param_ns:    dict[str, Any] | None = None,
) -> None:
    command_node   = _first_tree_child(operation, "command")
    primitive_node = _first_tree_child(operation, "primitive")

    command_str   = str(command_node.children[0])
    primitive_str = str(primitive_node.children[0])

    arglist_node: Tree | None = None
    for child in operation.children:
        if isinstance(child, Tree) and child.data == "arglist":
            arglist_node = child
            break

    args = _extract_args(arglist_node)

    # Substitute function parameters into args
    if param_ns:
        for k, v in args.items():
            if isinstance(v, str) and v in param_ns:
                args[k] = param_ns[v]

    # Dispatch to real primitive
    fn_key   = (command_str, primitive_str)
    prim_fn  = _DISPATCH.get(fn_key)
    result   = {}
    error    = None
    suspicious = 0

    if prim_fn is None:
        error  = f"No implementation for ({command_str}, {primitive_str})"
        result = {}
        print(f"  [{command_str}] {primitive_str} — {error}", file=sys.stderr)
    else:
        try:
            result = prim_fn(P, args, ctx)
            suspicious = result.pop("_suspicious", 0)
            print(f"  [{command_str}] {primitive_str}() → "
                  f"{result.get('count', len(result))} items, "
                  f"{suspicious} suspicious")
        except Exception as exc:
            error  = f"{type(exc).__name__}: {exc}"
            result = {}
            print(f"  [{command_str}] {primitive_str}() — ERROR: {error}",
                  file=sys.stderr)
            if "--debug" in sys.argv:
                traceback.print_exc()

    record = {
        "case_id":   ctx.case_id,
        "operator":  ctx.operator,
        "section":   section_name,
        "command":   command_str,
        "primitive": primitive_str,
        "args":      args,
        "result":    result,
        "suspicious": suspicious,
        "error":     error,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(timespec="seconds"),
    }
    acc.push(record)


# ─── Dispatch table ───────────────────────────────────────────────────────────
# Maps (command, primitive) → fn(P, args, ctx) → dict
#
# P  = the _primitives module (lazy-imported)
# args = dict from arglist
# ctx  = ExecutionContext
#
# Return value must be a dict. A "_suspicious" key (int) is extracted and
# removed before storing — it increments the accumulator's suspicious count.
# ─────────────────────────────────────────────────────────────────────────────

def _d(fn_name: str):
    """Return a lambda that calls P.<fn_name>(args, ctx)."""
    def _call(P, args, ctx):
        return getattr(P, fn_name)(args, ctx)
    _call.__name__ = fn_name
    return _call


_DISPATCH: dict[tuple[str, str], Callable] = {

    # ── acquire ────────────────────────────────────────────────────────────────
    ("acquire", "process_list"):    _d("acquire_process_list"),
    ("acquire", "memory_region"):   _d("acquire_memory_region"),
    ("acquire", "cpu_registers"):   _d("acquire_cpu_registers"),
    ("acquire", "loaded_modules"):  _d("acquire_loaded_modules"),
    ("acquire", "handles"):         _d("acquire_handles"),
    ("acquire", "tokens"):          _d("acquire_tokens"),
    ("acquire", "heap_strings"):    _d("acquire_heap_strings"),
    ("acquire", "connections"):     _d("acquire_connections"),
    ("acquire", "dns_cache"):       _d("acquire_dns_cache"),
    ("acquire", "arp_cache"):       _d("acquire_arp_cache"),
    ("acquire", "route_table"):     _d("acquire_route_table"),
    ("acquire", "sockets"):         _d("acquire_sockets"),
    ("acquire", "proc_memory"):     _d("acquire_proc_memory"),
    ("acquire", "drivers"):         _d("acquire_drivers"),

    # ── inspect ────────────────────────────────────────────────────────────────
    ("inspect", "registry"):        _d("inspect_registry"),
    ("inspect", "services"):        _d("inspect_services"),
    ("inspect", "startup_items"):   _d("inspect_startup_items"),
    ("inspect", "scheduled_tasks"): _d("inspect_scheduled_tasks"),
    ("inspect", "event_log"):       _d("inspect_event_log"),
    ("inspect", "usb_history"):     _d("inspect_usb_history"),
    ("inspect", "prefetch_history"):_d("inspect_prefetch_history"),
    ("inspect", "wifi_profiles"):   _d("inspect_wifi_profiles"),
    ("inspect", "named_pipes"):     _d("inspect_named_pipes"),
    ("inspect", "shares"):          _d("inspect_shares"),
    ("inspect", "file_metadata"):   _d("inspect_file_metadata"),
    ("inspect", "recent_files"):    _d("inspect_recent_files"),
    ("inspect", "file_tree"):       _d("inspect_file_tree"),
    ("inspect", "ads"):             _d("inspect_ads"),
    ("inspect", "installed_apps"):  _d("inspect_installed_apps"),
    ("inspect", "sms"):             _d("inspect_sms"),
    ("inspect", "call_log"):        _d("inspect_call_log"),
    ("inspect", "location"):        _d("inspect_location"),
    ("inspect", "whatsapp_db"):     _d("inspect_whatsapp_db"),
    ("inspect", "telegram_db"):     _d("inspect_telegram_db"),
    ("inspect", "contacts"):        _d("inspect_contacts"),

    # ── hash ───────────────────────────────────────────────────────────────────
    ("hash", "file"):               _d("hash_file"),
    ("hash", "directory"):          _d("hash_directory"),
    ("hash", "memory_region"):      _d("hash_memory_region"),

    # ── capture ────────────────────────────────────────────────────────────────
    ("capture", "traffic"):         _d("capture_traffic"),
    ("capture", "keystrokes"):      _d("capture_keystrokes"),
    ("capture", "clipboard"):       _d("capture_clipboard"),
    ("capture", "screen"):          _d("capture_screen"),

    # ── extract ────────────────────────────────────────────────────────────────
    ("extract", "browser_history"): _d("extract_browser_history"),
    ("extract", "browser_cookies"): _d("extract_browser_cookies"),
    ("extract", "browser_passwords"):_d("extract_browser_passwords"),
    ("extract", "mft"):             _d("extract_mft"),
    ("extract", "evtx"):            _d("extract_evtx"),
    ("extract", "prefetch"):        _d("extract_prefetch"),
    ("extract", "lnk"):             _d("extract_lnk"),
    ("extract", "registry_hive"):   _d("extract_registry_hive"),
    ("extract", "memory_strings"):  _d("extract_memory_strings"),

    # ── dump ───────────────────────────────────────────────────────────────────
    ("dump", "process"):            _d("dump_process"),
    ("dump", "registry_hive"):      _d("dump_registry_hive"),
    ("dump", "mft_raw"):            _d("dump_mft_raw"),
    ("dump", "pagefile"):           _d("dump_pagefile"),
    ("dump", "hiberfil"):           _d("dump_hiberfil"),

    # ── list ───────────────────────────────────────────────────────────────────
    ("list", "processes"):          _d("list_processes"),
    ("list", "connections"):        _d("list_connections"),
    ("list", "users"):              _d("list_users"),
    ("list", "groups"):             _d("list_groups"),
    ("list", "sessions"):           _d("list_sessions"),
    ("list", "patches"):            _d("list_patches"),
    ("list", "software"):           _d("list_software"),
    ("list", "environment"):        _d("list_environment"),
    ("list", "timezone"):           _d("list_timezone"),
}


# ─── Argument extraction ──────────────────────────────────────────────────────

def _extract_args(arglist_node: Tree | None) -> dict:
    if arglist_node is None:
        return {}
    args: dict = {}
    for argument in arglist_node.children:
        if not (isinstance(argument, Tree) and argument.data == "argument"):
            continue
        name_node  = _first_tree_child(argument, "arg_name")
        value_node = _first_tree_child(argument, "arg_value")
        name       = str(name_node.children[0])
        args[name] = _decode_arg_value(value_node)
    return args


def _decode_arg_value(value_node: Tree) -> str | int:
    value_token = value_node.children[0]
    tok_type    = getattr(value_token, "type", "")
    if tok_type == "STRING":
        return str(value_token)[1:-1]
    elif tok_type == "INTEGER":
        return int(str(value_token))
    else:
        return str(value_token)


def _flatten_cond(cond_expr: Tree) -> str:
    """Flatten a cond_expr tree back into a Python-evaluable expression string."""
    parts = []
    for child in cond_expr.children:
        if isinstance(child, Tree):
            if child.data == "cond_term":
                # cond_term: NAME ("." NAME)* | INTEGER | STRING
                parts.append("".join(str(c) for c in child.children))
            else:
                parts.append(_flatten_cond(child))
        else:
            # Token (operator)
            parts.append(str(child))
    return " ".join(parts)


# ─── Tree helpers ─────────────────────────────────────────────────────────────

def _first_tree_child(node: Tree, rule_name: str) -> Tree:
    for child in node.children:
        if isinstance(child, Tree) and child.data == rule_name:
            return child
    raise AssertionError(
        f"Expected child '{rule_name}' in '{node.data}' — grammar/parser bug."
    )


def _get_string_value(node: Tree) -> str:
    for child in node.children:
        if hasattr(child, "type") and child.type == "STRING":
            return str(child)[1:-1]
    raise AssertionError(f"No STRING token in '{node.data}' — grammar/parser bug.")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def _main() -> None:
    """
    Usage: python interpreter.py <script.jky> [--debug]
    Full pipeline: parse → validate → interpret.
    """
    _pkg = Path(__file__).resolve().parent
    if str(_pkg) not in sys.path:
        sys.path.insert(0, str(_pkg))

    from parser    import JOCKYParseError, parse_file
    from validator import JOCKYValidationError, validate

    script_args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not script_args:
        print("Usage: python interpreter.py <script.jky> [--debug]",
              file=sys.stderr)
        sys.exit(1)

    script_path = Path(script_args[0])
    if not script_path.exists():
        print(f"Error: file not found — {script_path}", file=sys.stderr)
        sys.exit(1)

    try:
        tree = parse_file(script_path)
    except JOCKYParseError as exc:
        print(f"Parse error:\n  {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        validate(tree)
    except JOCKYValidationError as exc:
        print(f"Validation error:\n  {exc}", file=sys.stderr)
        sys.exit(1)

    interpret(tree)


if __name__ == "__main__":
    _main()
