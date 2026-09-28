"""
coc_report.py -- Generate a human-readable Chain of Custody PDF report
from a JOCKY blockchain JSON file.

Usage:
  python coc_report.py --chain evidence/coc_NTRO-2026-001.json
  python coc_report.py --chain evidence/coc_NTRO-2026-001.json --pdf

Outputs:
  evidence/coc_report_NTRO-2026-001.txt   (always)
  evidence/coc_report_NTRO-2026-001.pdf   (if --pdf and fpdf2 installed)
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib  import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
for _p in [str(_ROOT), str(_ROOT/"integrity")]:
    if _p not in sys.path: sys.path.insert(0, _p)

from blockchain import ForensicBlockchain

EVENT_LABELS = {
    "INVESTIGATION_START": "Investigation Opened",
    "AGENT_DEPLOYED":      "Agent / USB Action",
    "TASK_DISPATCHED":     "Task / USB Event",
    "EVIDENCE_COLLECTED":  "Evidence Collected",
    "ANOMALY_DETECTED":    "Anomaly Detected",
    "CHAIN_VERIFIED":      "Chain Verified",
    "INVESTIGATION_CLOSED":"Investigation Closed",
}

def generate_text_report(chain_file: Path) -> str:
    data = json.loads(chain_file.read_text(encoding="utf-8"))
    blocks = data.get("blocks", [])
    case_id = data.get("case_id", "UNKNOWN")
    investigator = data.get("investigator", "UNKNOWN")
    pub_key = data.get("pub_key", "")

    lines = []
    lines.append("=" * 72)
    lines.append("JOCKY FORENSIC FRAMEWORK")
    lines.append("CHAIN OF CUSTODY REPORT")
    lines.append("=" * 72)
    lines.append(f"Case ID:         {case_id}")
    lines.append(f"Investigator:    {investigator}")
    lines.append(f"Total Blocks:    {len(blocks)}")
    lines.append(f"Public Key:      {pub_key[:32]}..." if pub_key else "Public Key: N/A")
    lines.append(f"Generated:       {datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}")
    lines.append("=" * 72)
    lines.append("")

    # verify chain integrity first
    bc = ForensicBlockchain.__new__(ForensicBlockchain)
    bc.case_id      = case_id
    bc.investigator = investigator
    bc.chain_file   = chain_file
    bc.key_file     = None
    bc._chain       = []
    bc._priv_key    = None
    bc._pub_key_hex = pub_key

    from blockchain import ForensicBlock
    for b in blocks:
        bc._chain.append(ForensicBlock.from_dict(b))

    ok, verify_report = bc.verify()
    lines.append("INTEGRITY VERIFICATION")
    lines.append("-" * 72)
    lines.append(verify_report)
    lines.append("")
    lines.append("CUSTODY TIMELINE")
    lines.append("-" * 72)

    for block in blocks:
        idx       = block["index"]
        ts        = block["timestamp"]
        ev        = block["event_type"]
        data      = block.get("data", {})
        hash_val  = block.get("hash","")
        sig_val   = block.get("signature","")
        label     = EVENT_LABELS.get(ev, ev)

        lines.append(f"\n[Block #{idx:04d}]  {ts}")
        lines.append(f"  Event:      {label} ({ev})")
        lines.append(f"  Hash:       {hash_val[:32]}...")
        lines.append(f"  Signature:  {sig_val[:32]}..." if sig_val else "  Signature:  (none)")

        # format data nicely
        if data:
            lines.append("  Details:")
            for k, v in data.items():
                v_str = str(v)
                if len(v_str) > 80:
                    v_str = v_str[:77] + "..."
                lines.append(f"    {k:<20s} {v_str}")

    lines.append("")
    lines.append("=" * 72)
    lines.append(f"END OF CHAIN OF CUSTODY REPORT — {case_id}")
    lines.append("=" * 72)
    return "\n".join(lines)

def generate_pdf_report(text: str, out_path: Path):
    try:
        from fpdf import FPDF
    except ImportError:
        print("[-] fpdf2 not installed -- text report only")
        print("    pip install fpdf2 --break-system-packages")
        return False

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Courier", size=8)

    for line in text.split("\n"):
        # handle unicode box-drawing chars
        try:
            pdf.cell(0, 4, line, ln=True)
        except Exception:
            pdf.cell(0, 4, line.encode("ascii","replace").decode(), ln=True)

    pdf.output(str(out_path))
    return True

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chain", required=True, help="Path to blockchain JSON file")
    ap.add_argument("--pdf",   action="store_true", help="Also generate PDF")
    ap.add_argument("--out",   default=None, help="Output dir (default: same as chain)")
    args = ap.parse_args()

    chain_file = Path(args.chain)
    if not chain_file.exists():
        print(f"[-] Chain file not found: {chain_file}")
        sys.exit(1)

    out_dir = Path(args.out) if args.out else chain_file.parent
    out_dir.mkdir(exist_ok=True)

    case_stem = chain_file.stem.replace("coc_","")
    txt_out   = out_dir / f"coc_report_{case_stem}.txt"

    print(f"[*] Generating COC report for {chain_file.name}...")
    report_text = generate_text_report(chain_file)

    txt_out.write_text(report_text, encoding="utf-8")
    print(f"[+] Text report: {txt_out}")

    if args.pdf:
        pdf_out = out_dir / f"coc_report_{case_stem}.pdf"
        ok = generate_pdf_report(report_text, pdf_out)
        if ok:
            print(f"[+] PDF report:  {pdf_out}")

    print()
    print(report_text)

if __name__ == "__main__":
    main()