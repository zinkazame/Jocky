"""
JOCKY Variable Renamer — Phase 6 Obfuscator
=============================================
Renames LLVM IR global variables, local values, and basic block labels
to randomised names, breaking pattern-based static analysis.

Standard Clang output uses predictable names:
  @.str.0, @.str.1, %call, %retval, entry, cleanup, etc.

After renaming:
  @.xk7q2, @.mf9p1, %v_a3b, %v_c8d, bb_0, bb_1, etc.

This neutralises:
  - YARA rules that match on IR-level symbol names
  - Compiler fingerprinting (MSVC vs GCC vs Clang output patterns)
  - Import/export name correlation across builds

Usage:
    renamer = VariableRenamer(seed=None)   # None = random per build
    mutated_ir = renamer.rename(ir_text)
"""

from __future__ import annotations

import random
import re
import secrets
import string
from typing import Callable


class VariableRenamer:
    """
    Renames LLVM IR identifiers to randomised names.

    Parameters
    ----------
    seed : int | None
        RNG seed. None = cryptographically random (production default).
    prefix_len : int
        Length of the random suffix appended to each renamed identifier.
    """

    # LLVM IR identifier patterns
    # Global: @name or @"name"
    # Local:  %name or %"name"
    # Labels: name: (at start of line, followed by colon)

    _GLOBAL_RE = re.compile(r'@([\w.]+)')
    _LOCAL_RE  = re.compile(r'%([\w.]+)')
    _LABEL_RE  = re.compile(r'^([\w.]+):', re.MULTILINE)

    # Names to preserve (LLVM IR keywords and external function names)
    _PRESERVE_GLOBALS = {
        "llvm.memcpy.p0i8.p0i8.i64",
        "llvm.memset.p0i8.i64",
        "llvm.lifetime.start.p0",
        "llvm.lifetime.end.p0",
        "JOCKY_main",   # entry point — must keep
    }
    _PRESERVE_LOCALS = {
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
    }
    _PRESERVE_LABELS = {
        "entry", "exit",   # keep entry/exit for readability in debug builds
    }

    def __init__(self, seed: int | None = None, prefix_len: int = 6) -> None:
        self._rng        = random.Random(seed)
        self._prefix_len = prefix_len
        self._global_map: dict[str, str] = {}
        self._local_map:  dict[str, str] = {}
        self._label_map:  dict[str, str] = {}

    # ─── Public API ───────────────────────────────────────────────────────────

    def rename(self, ir_text: str) -> str:
        """
        Apply all renaming passes to LLVM IR text.

        Parameters
        ----------
        ir_text : str
            Raw LLVM IR text.

        Returns
        -------
        str
            IR text with randomised identifiers.
        """
        self._global_map.clear()
        self._local_map.clear()
        self._label_map.clear()

        # Pass 1: Collect all identifiers and build rename maps
        self._collect_globals(ir_text)
        self._collect_locals(ir_text)
        self._collect_labels(ir_text)

        # Pass 2: Apply substitutions (globals first, then locals, then labels)
        result = self._apply_globals(ir_text)
        result = self._apply_locals(result)
        result = self._apply_labels(result)

        return result

    def get_rename_map(self) -> dict[str, dict[str, str]]:
        """Return the rename maps for debugging/logging."""
        return {
            "globals": dict(self._global_map),
            "locals":  dict(self._local_map),
            "labels":  dict(self._label_map),
        }

    # ─── Collection passes ────────────────────────────────────────────────────

    def _collect_globals(self, ir_text: str) -> None:
        for match in self._GLOBAL_RE.finditer(ir_text):
            name = match.group(1)
            if name not in self._PRESERVE_GLOBALS and name not in self._global_map:
                # Preserve JOCKY_ prefixed functions (external C primitives)
                if name.startswith("JOCKY_"):
                    self._global_map[name] = name   # identity mapping
                else:
                    self._global_map[name] = self._random_name("g")

    def _collect_locals(self, ir_text: str) -> None:
        for match in self._LOCAL_RE.finditer(ir_text):
            name = match.group(1)
            if name not in self._PRESERVE_LOCALS and name not in self._local_map:
                self._local_map[name] = self._random_name("v")

    def _collect_labels(self, ir_text: str) -> None:
        for match in self._LABEL_RE.finditer(ir_text):
            name = match.group(1)
            if name not in self._PRESERVE_LABELS and name not in self._label_map:
                # Skip LLVM IR keywords that look like labels
                if name in {"define", "declare", "target", "source_filename",
                            "attributes", "metadata", "module", "type"}:
                    continue
                self._label_map[name] = self._random_name("bb")

    # ─── Application passes ───────────────────────────────────────────────────

    def _apply_globals(self, ir_text: str) -> str:
        def replace(m: re.Match) -> str:
            name = m.group(1)
            new  = self._global_map.get(name, name)
            return f"@{new}"
        return self._GLOBAL_RE.sub(replace, ir_text)

    def _apply_locals(self, ir_text: str) -> str:
        def replace(m: re.Match) -> str:
            name = m.group(1)
            new  = self._local_map.get(name, name)
            return f"%{new}"
        return self._LOCAL_RE.sub(replace, ir_text)

    def _apply_labels(self, ir_text: str) -> str:
        def replace(m: re.Match) -> str:
            name = m.group(1)
            new  = self._label_map.get(name, name)
            return f"{new}:"
        return self._LABEL_RE.sub(replace, ir_text)

    # ─── Name generation ──────────────────────────────────────────────────────

    def _random_name(self, prefix: str) -> str:
        """Generate a random identifier: prefix + random alphanumeric suffix."""
        chars  = string.ascii_lowercase + string.digits
        suffix = "".join(self._rng.choices(chars, k=self._prefix_len))
        return f"{prefix}_{suffix}"
