"""
JOCKY Forensic Framework — Main Entry Point
============================================
Full compiler + agent pipeline CLI.

Usage:
    python main.py compile <script.jky> [--obfuscate] [--output <dir>]
    python main.py run     <script.jky> [--obfuscate] [--target local|remote]
    python main.py verify  <log.json>
    python main.py dashboard

Phases wired here:
    Phase 2  — parse (.jky → AST)
    Phase 3  — validate (semantic constraints)
    Phase 4  — IR generation (AST → LLVM IR)
    Phase 5  — CFG obfuscation (opaque predicates, junk blocks)
    Phase 6  — Polymorphic build (per-build binary mutation)
    Phase 16 — Hash-chain integrity (log signing + verification)
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# ─── Path bootstrap ───────────────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent
_LANG = _ROOT / "language"
_LEX  = _LANG / "lexer_parser"
_LLVM = _LANG / "llvm_frontend"
_PIPE = _ROOT / "build_pipeline"
_POLY = _PIPE / "polymorphic_engine"
_INTG = _ROOT / "integrity"

for _p in [str(_LEX), str(_LLVM), str(_POLY), str(_INTG)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from parser    import DormParseError, parse_file          # Phase 2
from validator import DormValidationError, validate        # Phase 3
from ir_generator import context_from_tree, generate_ir   # Phase 4+5
from pipeline  import PolymorphicPipeline                  # Phase 6
from hash_chain import HashChain                           # Phase 16
from signing   import ChainSigner                          # Phase 16
from verifier  import verify_chain                         # Phase 16


# ─── Clang detection ──────────────────────────────────────────────────────────

def _find_clang() -> str | None:
    for candidate in ["clang", "clang-17", "clang-16", "clang-15"]:
        if shutil.which(candidate):
            return candidate
    return None


# ─── Compile command ──────────────────────────────────────────────────────────

def cmd_compile(args: argparse.Namespace) -> int:
    script = Path(args.script)
    if not script.exists():
        print(f"[jocky] Error: script not found — {script}", file=sys.stderr)
        return 1

    out_dir = Path(args.output) if args.output else script.parent / "build"
    out_dir.mkdir(parents=True, exist_ok=True)

    stem = script.stem

    # ── Phase 2: Parse ────────────────────────────────────────────────────────
    print(f"[jocky] Parsing {script.name} ...")
    try:
        tree = parse_file(script)
    except DormParseError as exc:
        print(f"[jocky] Parse error:\n  {exc}", file=sys.stderr)
        return 1
    print("[jocky] Parse OK")

    # ── Phase 3: Validate ─────────────────────────────────────────────────────
    print("[jocky] Validating ...")
    try:
        validate(tree)
    except DormValidationError as exc:
        print(f"[jocky] Validation error:\n  {exc}", file=sys.stderr)
        return 1
    print("[jocky] Validation OK")

    # ── Phase 4+5: IR generation (+ optional CFG obfuscation) ─────────────────
    obfuscate = getattr(args, "obfuscate", False)
    print(f"[jocky] Generating LLVM IR (obfuscate={obfuscate}) ...")
    ctx    = context_from_tree(tree)
    ir_txt = generate_ir(tree, ctx, obfuscate=obfuscate)

    ll_path = out_dir / f"{stem}.ll"
    ll_path.write_text(ir_txt, encoding="utf-8")
    print(f"[jocky] IR written → {ll_path}  ({len(ir_txt):,} bytes)")

    # ── Phase 6: Compile IR → native binary via Clang ─────────────────────────
    clang = _find_clang()
    if not clang:
        print("[jocky] Warning: clang not found — skipping native compilation.")
        print(f"[jocky] IR is ready at {ll_path}. Compile manually:")
        print(f"        clang -O2 -o {out_dir / stem} {ll_path} "
              f"execution_engine/forensics/*.c -lkernel32 -lpsapi")
        return 0

    # Gather forensic primitive C sources
    forensic_c = list((_ROOT / "execution_engine" / "forensics").glob("*.c"))
    forensic_c = [str(f) for f in forensic_c if "test_" not in f.name]

    bin_path = out_dir / (stem + (".exe" if sys.platform == "win32" else ""))
    clang_cmd = [
        clang, "-O2", "-o", str(bin_path),
        str(ll_path),
        *forensic_c,
        "-lkernel32", "-lpsapi",
    ]
    print(f"[jocky] Compiling → {bin_path}")
    print(f"        {' '.join(clang_cmd)}")
    result = subprocess.run(clang_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[jocky] Clang error:\n{result.stderr}", file=sys.stderr)
        return 1
    print(f"[jocky] Binary ready → {bin_path}")

    # ── Phase 6b: Polymorphic mutation ────────────────────────────────────────
    if sys.platform == "win32":
        print("[jocky] Running polymorphic mutation pass ...")
        try:
            poly = PolymorphicPipeline(str(bin_path))
            mutated_path = poly.run()
            print(f"[jocky] Mutated binary → {mutated_path}")
        except Exception as exc:
            print(f"[jocky] Warning: polymorphic pass failed — {exc}")

    # ── Phase 16: Hash-chain entry ────────────────────────────────────────────
    chain_path = out_dir / "chain.json"
    try:
        chain = HashChain(str(chain_path))
        entry_id = chain.append(
            event="compile",
            data={
                "script":    str(script),
                "case_id":   ctx.case_id,
                "operator":  ctx.operator,
                "target":    ctx.target,
                "mode":      ctx.mode,
                "obfuscate": obfuscate,
                "ir_bytes":  len(ir_txt),
                "binary":    str(bin_path),
            }
        )
        signer = ChainSigner(str(out_dir / "signing.key"))
        signer.sign_entry(chain, entry_id)
        print(f"[jocky] Chain entry #{entry_id} signed → {chain_path}")
    except Exception as exc:
        print(f"[jocky] Warning: integrity chain failed — {exc}")

    print(f"\n[jocky] Build complete. Output directory: {out_dir}")
    return 0


# ── Verify command ─────────────────────────────────────────────────────────────

def cmd_verify(args: argparse.Namespace) -> int:
    chain_path = Path(args.chain)
    if not chain_path.exists():
        print(f"[jocky] Error: chain file not found — {chain_path}", file=sys.stderr)
        return 1
    print(f"[jocky] Verifying chain: {chain_path}")
    ok, report = verify_chain(str(chain_path))
    print(report)
    return 0 if ok else 1


# ── Dashboard command ──────────────────────────────────────────────────────────

def cmd_dashboard(args: argparse.Namespace) -> int:
    dash_dir = _ROOT / "management_interface" / "dashboard"
    api_path  = dash_dir / "api.py"
    if not api_path.exists():
        print("[jocky] Dashboard not yet built. Run Phase 17 setup.", file=sys.stderr)
        return 1
    print("[jocky] Starting management dashboard ...")
    subprocess.run([sys.executable, str(api_path)], check=False)
    return 0


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(
        prog="jocky",
        description="JOCKY Forensic Framework — compiler + agent pipeline",
    )
    sub = ap.add_subparsers(dest="command", required=True)

    # compile
    p_compile = sub.add_parser("compile", help="Compile a .jky script to native binary")
    p_compile.add_argument("script",              help="Input .jky script path")
    p_compile.add_argument("--obfuscate",         action="store_true",
                           help="Apply CFG obfuscation (opaque predicates + junk blocks)")
    p_compile.add_argument("--output", "-o",      metavar="DIR",
                           help="Output directory (default: <script_dir>/build)")

    # verify
    p_verify = sub.add_parser("verify", help="Verify a hash-chain integrity log")
    p_verify.add_argument("chain", help="Path to chain.json")

    # dashboard
    sub.add_parser("dashboard", help="Launch management dashboard (Phase 17)")

    args = ap.parse_args()

    dispatch = {
        "compile":   cmd_compile,
        "verify":    cmd_verify,
        "dashboard": cmd_dashboard,
    }
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
