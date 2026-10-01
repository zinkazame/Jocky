"""
JOCKY Forensic Language — Validator  (Phase 3)
===============================================
Enforces post-parse semantic constraints:

  1. Section order (volatility order: memory → network → system → disk → files → android)
  2. No duplicate sections
  3. Command-primitive compatibility (expanded table for v0.3 primitives)
  4. Function declarations: no duplicate names, no reserved names
  5. Call statements: function must be declared before the call site

Nothing else. No execution. No output writing.
"""

from __future__ import annotations

import sys
from pathlib import Path

from lark import Tree


# ─── Exception ───────────────────────────────────────────────────────────────

class JOCKYValidationError(Exception):
    """
    Raised when a syntactically valid .jky tree violates a semantic constraint.
    Always contains a human-readable message identifying which constraint
    failed and exactly where.
    """
    pass


# ─── Constants ───────────────────────────────────────────────────────────────

# Volatility order — the only valid ordering of sections when present.
# android is always last (off-device ADB collection, least volatile).
_SECTION_ORDER: list[str] = ["memory", "network", "system", "disk", "files", "android"]

# ──────────────────────────────────────────────────────────────────────────────
# Command → valid primitives  (Constraint 3 compatibility table)
#
# Organised by forensic category for readability.
# Every primitive must have exactly one command — no aliasing.
# ──────────────────────────────────────────────────────────────────────────────
_COMPAT: dict[str, set[str]] = {

    # acquire: live data acquisition (volatile, in-memory state)
    "acquire": {
        # Memory section
        "process_list",       # all running processes + metadata
        "memory_region",      # read bytes from a process VA range
        "cpu_registers",      # thread register state (for suspended threads)
        "loaded_modules",     # DLLs / .so files loaded into a process
        "handles",            # open handles (files, registry, sockets) per process
        "tokens",             # process/thread security tokens + privilege list
        "heap_strings",       # printable strings extracted from process heap
        # Network section
        "connections",        # TCP/UDP connection table + owning PIDs
        "dns_cache",          # OS resolver cache entries
        "arp_cache",          # ARP table (IP → MAC)
        "route_table",        # IP routing table
        "sockets",            # raw socket list (including RAW, ICMP)
        # System section
        "proc_memory",        # full memory map of a process (VAD walk)
        "drivers",            # loaded kernel drivers + paths + signatures
    },

    # inspect: read OS metadata / configuration (less volatile, but still live)
    "inspect": {
        # System section
        "registry",           # enumerate a registry key + values
        "services",           # SCM service list + state
        "startup_items",      # all autorun locations (registry + folders + tasks)
        "scheduled_tasks",    # task XML + flags (SYSTEM-run, shell interpreters)
        "event_log",          # Windows event log (Security, System, Application)
        "usb_history",        # USBSTOR registry — ever-connected USB devices
        "prefetch_history",   # Prefetch .pf binary parse → execution timeline
        "wifi_profiles",      # Saved Wi-Fi profiles + cleartext PSKs (if any)
        "named_pipes",        # named pipe list (common C2 channel)
        "shares",             # SMB share list
        # Disk section
        "file_metadata",      # stat-level metadata: timestamps, size, owner
        "recent_files",       # shell MRU / jump list / Recent Items
        "file_tree",          # recursive directory listing + hashes
        "ads",                # NTFS Alternate Data Streams scan
        # Android section
        "installed_apps",     # package list + third-party flag + permissions
        "sms",                # SMS message database
        "call_log",           # call history (number, duration, direction)
        "location",           # GPS history from provider databases
        "whatsapp_db",        # WhatsApp msgstore.db pull via ADB
        "telegram_db",        # Telegram local cache pull via ADB
        "contacts",           # device contact list
    },

    # hash: content hashing (disk section almost exclusively)
    "hash": {
        "file",               # SHA-256 of a single file
        "directory",          # recursive SHA-256 of all files in a directory
        "memory_region",      # SHA-256 of a live memory region
    },

    # capture: real-time capture (active / blocking)
    "capture": {
        "traffic",            # packet capture (pcap) for N seconds
        "keystrokes",         # keyboard input monitor
        "clipboard",          # clipboard content snapshot
        "screen",             # screenshot
    },

    # extract: parse/decode from a data source into structured records
    "extract": {
        "browser_history",    # Chrome/Edge/Firefox SQLite history + downloads
        "browser_cookies",    # browser cookie databases
        "browser_passwords",  # browser saved credentials (login data)
        "mft",                # NTFS Master File Table records
        "evtx",               # parse a raw .evtx file
        "prefetch",           # parse a single .pf file
        "lnk",                # parse a .lnk shortcut file
        "registry_hive",      # parse an offline registry hive file
        "memory_strings",     # printable strings from a raw memory dump
    },

    # dump: raw binary export to evidence store
    "dump": {
        "process",            # full process memory dump (minidump or full)
        "registry_hive",      # export a live registry hive to file
        "mft_raw",            # raw MFT export
        "pagefile",           # pagefile / swapfile content
        "hiberfil",           # hibernate file
    },

    # list: enumerate without deep inspection (fast, low footprint)
    "list": {
        "processes",          # quick process name+PID list (no hashes)
        "connections",        # quick socket list (no PID resolution)
        "users",              # local user accounts
        "groups",             # local group memberships
        "sessions",           # active logon sessions
        "patches",            # installed Windows patches / hotfixes
        "software",           # installed programs (registry uninstall keys)
        "environment",        # environment variables
        "timezone",           # system timezone + current UTC offset
    },
}

# Reserved function names — cannot be used as user-defined function names
_RESERVED_NAMES: set[str] = {
    "case", "section", "define", "call", "when",
    "memory", "network", "system", "disk", "files", "android",
    "acquire", "inspect", "hash", "capture", "extract", "dump", "list",
}


# ─── Public API ──────────────────────────────────────────────────────────────

def validate(tree: Tree) -> None:
    """
    Run all validation constraints against a JOCKY parse tree.

    Constraints:
      1. Section order  (memory → network → system → disk → files → android)
      2. No duplicate sections
      3. Command-primitive compatibility (all operations in all contexts)
      4. Function names: no duplicates, no reserved names
      5. Call statements: function must be declared before use

    Raises
    ------
    JOCKYValidationError  on the first constraint violation found.
    """
    declared_functions = _validate_functions(tree)          # C4 + collect names
    section_names      = _extract_section_names(tree)
    _validate_no_duplicates(section_names)                  # C2 before C1
    _validate_section_order(section_names)                  # C1
    _validate_command_primitive_all(tree)                   # C3 (all contexts)
    _validate_call_statements(tree, declared_functions)     # C5


# ─── Constraint helpers ───────────────────────────────────────────────────────

def _extract_section_names(tree: Tree) -> list[str]:
    names: list[str] = []
    for sb in tree.find_data("section_block"):
        sn = _first_tree_child(sb, "section_name")
        names.append(str(sn.children[0]))
    return names


def _validate_section_order(section_names: list[str]) -> None:
    positions = [_SECTION_ORDER.index(name) for name in section_names]
    for i in range(1, len(positions)):
        if positions[i] < positions[i - 1]:
            raise JOCKYValidationError(
                f"Constraint 1 — Section order violation: "
                f"'{section_names[i]}' appears after '{section_names[i - 1]}' "
                f"but must precede it in volatility order.\n"
                f"  Required order: {' → '.join(_SECTION_ORDER)}"
            )


def _validate_no_duplicates(section_names: list[str]) -> None:
    seen: set[str] = set()
    for name in section_names:
        if name in seen:
            raise JOCKYValidationError(
                f"Constraint 2 — Duplicate section: "
                f"'{name}' is declared more than once."
            )
        seen.add(name)


def _validate_command_primitive_all(tree: Tree) -> None:
    """
    Validate every operation node across sections AND function bodies.
    """
    for operation in tree.find_data("operation"):
        _check_operation(operation)


def _check_operation(operation: Tree) -> None:
    command_node   = _first_tree_child(operation, "command")
    primitive_node = _first_tree_child(operation, "primitive")

    command_str   = str(command_node.children[0])
    primitive_str = str(primitive_node.children[0])

    allowed = _COMPAT.get(command_str, set())
    if primitive_str not in allowed:
        line = getattr(operation.meta, "line", "?")
        raise JOCKYValidationError(
            f"Constraint 3 — Command-primitive mismatch at line {line}: "
            f"'{command_str}' cannot be used with '{primitive_str}'.\n"
            f"  Valid primitives for '{command_str}': "
            f"{', '.join(sorted(allowed))}"
        )


def _validate_functions(tree: Tree) -> set[str]:
    """
    Constraint 4: validate function definitions.
    Returns the set of declared function names (used by C5).
    """
    declared: set[str] = set()
    for func_def in tree.find_data("func_def"):
        fn_name_node = _first_tree_child(func_def, "func_name")
        fn_name      = str(fn_name_node.children[0])
        line         = getattr(func_def.meta, "line", "?")

        if fn_name in _RESERVED_NAMES:
            raise JOCKYValidationError(
                f"Constraint 4 — Reserved function name at line {line}: "
                f"'{fn_name}' is a keyword and cannot be used as a function name.\n"
                f"  Reserved names: {', '.join(sorted(_RESERVED_NAMES))}"
            )

        if fn_name in declared:
            raise JOCKYValidationError(
                f"Constraint 4 — Duplicate function name at line {line}: "
                f"'{fn_name}' is defined more than once."
            )

        declared.add(fn_name)

    return declared


def _validate_call_statements(tree: Tree, declared: set[str]) -> None:
    """
    Constraint 5: every call_stmt must reference a declared function.
    """
    for call_stmt in tree.find_data("call_stmt"):
        fn_name_node = _first_tree_child(call_stmt, "func_name")
        fn_name      = str(fn_name_node.children[0])
        line         = getattr(call_stmt.meta, "line", "?")

        if fn_name not in declared:
            raise JOCKYValidationError(
                f"Constraint 5 — Undefined function at line {line}: "
                f"call '{fn_name}' — function is not declared in this script.\n"
                f"  Declared functions: {', '.join(sorted(declared)) or '(none)'}"
            )


# ─── Internal helpers ─────────────────────────────────────────────────────────

def _first_tree_child(node: Tree, rule_name: str) -> Tree:
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
    _pkg = Path(__file__).resolve().parent
    if str(_pkg) not in sys.path:
        sys.path.insert(0, str(_pkg))

    from parser import JOCKYParseError, parse_file

    if len(sys.argv) != 2:
        print("Usage: python validator.py <script.jky>", file=sys.stderr)
        sys.exit(1)

    script_path = Path(sys.argv[1])
    if not script_path.exists():
        print(f"Error: file not found — {script_path}", file=sys.stderr)
        sys.exit(1)

    try:
        tree = parse_file(script_path)
    except JOCKYParseError as exc:
        print(f"Parse error:\n  {exc}", file=sys.stderr)
        sys.exit(1)
    print(f"Parse successful — {script_path.name}")

    try:
        validate(tree)
    except JOCKYValidationError as exc:
        print(f"Validation error:\n  {exc}", file=sys.stderr)
        sys.exit(1)
    print("Validation passed.")


if __name__ == "__main__":
    _main()
