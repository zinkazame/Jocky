"""
JOCKY Forensic Language — Parser  (Phase 2)
============================================
Single responsibility: take a .jky script string, run it through the grammar,
and return a clean parse tree OR raise a precise, human-readable error.

No validation logic here — that is Phase 3.
No primitive execution — that is Phase 4+.
"""

from __future__ import annotations

import sys
from pathlib import Path

from lark import Lark, Tree
from lark.exceptions import UnexpectedCharacters, UnexpectedInput, UnexpectedToken
from lark.indenter import Indenter

# ─── Grammar path ─────────────────────────────────────────────────────────────
# parser.py lives at  language/lexer_parser/parser.py
# grammar lives at    language/grammar/jocky.lark
# Resolve relative to this file so the module works regardless of cwd.

_GRAMMAR_PATH = Path(__file__).resolve().parent.parent / "grammar" / "jocky.lark"


# ─── Indenter ─────────────────────────────────────────────────────────────────

class JockyIndenter(Indenter):
    """
    Post-lexer that turns leading-whitespace changes into virtual
    _INDENT / _DEDENT tokens before the LALR parser sees the stream.

    Why OPEN/CLOSE_PAREN_types are empty:
        JOCKY parentheses are string literals ("(" / ")") not named terminals,
        so Lark gives them no usable token-type name.  Argument lists also
        always fit on one line, so paren-context suppression is not needed.

    tab_len = 8:
        POSIX standard.  Scripts using 4-space indentation still work because
        the Indenter tracks indent *levels*, not raw column counts.
    """
    NL_type          = "_NL"
    OPEN_PAREN_types : list[str] = []
    CLOSE_PAREN_types: list[str] = []
    INDENT_type      = "_INDENT"
    DEDENT_type      = "_DEDENT"
    tab_len          = 8


# ─── Parser singleton ─────────────────────────────────────────────────────────
# Built once at import time — LALR table construction is expensive; reuse it.

def _build_parser() -> Lark:
    if not _GRAMMAR_PATH.exists():
        raise FileNotFoundError(
            f"Grammar file not found: {_GRAMMAR_PATH}\n"
            "Run from the project root or check your directory layout."
        )
    grammar_text = _GRAMMAR_PATH.read_text(encoding="utf-8")
    return Lark(
        grammar_text,
        parser="lalr",
        postlex=JockyIndenter(),
        propagate_positions=True,   # attach line/col to every tree node
    )


_PARSER: Lark = _build_parser()


# ─── Public exception ─────────────────────────────────────────────────────────

class JockyParseError(Exception):
    """
    Raised when a .jky script is syntactically invalid.
    Always contains a human-readable message with line and column numbers.
    """
    pass


# ─── Public API ───────────────────────────────────────────────────────────────

def parse(text: str) -> Tree:
    """
    Parse a JOCKY script string.

    Parameters
    ----------
    text : str
        Raw content of a .jky file (UTF-8).

    Returns
    -------
    lark.Tree
        Root of the parse tree.  Caller owns validation (Phase 3)
        and execution (Phase 4+).

    Raises
    ------
    JockyParseError
        On any syntax error.  Message includes line, column, and what
        the parser expected at the point of failure.
    """
    try:
        return _PARSER.parse(text)

    except UnexpectedCharacters as exc:
        raise JockyParseError(
            f"Unexpected character at line {exc.line}, col {exc.column}: "
            f"'{exc.char}'\n"
            f"  Expected: {_fmt_expected(exc.allowed)}"
        ) from exc

    except UnexpectedToken as exc:
        raise JockyParseError(
            f"Unexpected token at line {exc.line}, col {exc.column}: "
            f"'{exc.token}' ({exc.token.type})\n"
            f"  Expected: {_fmt_expected(exc.expected)}"
        ) from exc

    except UnexpectedInput as exc:
        # Catch-all for any other Lark parse failure
        raise JockyParseError(
            f"Parse error near line {exc.line}, col {exc.column}."
        ) from exc


def parse_file(path: str | Path) -> Tree:
    """
    Parse a .jky script from disk.

    Parameters
    ----------
    path : str or Path

    Returns
    -------
    lark.Tree

    Raises
    ------
    FileNotFoundError
    JockyParseError
    """
    path = Path(path)
    return parse(path.read_text(encoding="utf-8"))


# ─── Internal helpers ─────────────────────────────────────────────────────────

def _fmt_expected(allowed: set[str] | frozenset[str] | None) -> str:
    """
    Format the set of expected token types into a readable string.
    Strips Lark-internal names (prefixed __) that mean nothing to the user.
    """
    if not allowed:
        return "(unknown)"
    readable = sorted(t for t in allowed if not t.startswith("__"))
    return ", ".join(readable) if readable else "(unknown)"


# ─── CLI ──────────────────────────────────────────────────────────────────────

def _main() -> None:
    """
    Usage:  python parser.py <script.jky>

    Prints the parse tree on success, a precise error message on failure.
    Exit code 0 = success, 1 = error.
    """
    if len(sys.argv) != 2:
        print("Usage: python parser.py <script.jky>", file=sys.stderr)
        sys.exit(1)

    script_path = Path(sys.argv[1])

    if not script_path.exists():
        print(f"Error: file not found — {script_path}", file=sys.stderr)
        sys.exit(1)

    try:
        tree = parse_file(script_path)
    except JockyParseError as exc:
        print(f"Parse error:\n  {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"Parse successful — {script_path.name}")
    print()
    print(tree.pretty())


if __name__ == "__main__":
    _main()