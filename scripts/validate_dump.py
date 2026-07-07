#!/usr/bin/env python3
"""Real-dump validation harness.

Runs the full pipeline (run → parse → detect → timeline → report) against a
real memory image and prints a summary. Use it to shake out column-name drift
between the tolerant parser and actual Volatility3 output — the one thing the
synthetic unit tests cannot cover.

Requires Volatility3 (`pip install -e '.[vol]'`) and a dump.

    python scripts/validate_dump.py /path/to/memory.raw [--os windows] [-o case/]

Public images to test against:
  - Volatility3 sample images:  https://downloads.volatilityfoundation.org/
  - MemLabs / Malware-Traffic-Analysis / Digital Corpora dumps
  - CTF memory challenges (e.g. HackTheBox, MemLabs)
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate Mneme against a real dump")
    ap.add_argument("dump", type=Path)
    ap.add_argument("--os", dest="os_type", choices=["windows", "linux", "mac"])
    ap.add_argument("-o", "--output", type=Path, default=Path("validation_case"))
    ap.add_argument("--vol-bin", default="vol")
    args = ap.parse_args()

    if not args.dump.exists():
        print(f"dump not found: {args.dump}", file=sys.stderr)
        return 2
    if shutil.which(args.vol_bin) is None:
        print(f"{args.vol_bin!r} not on PATH — pip install -e '.[vol]'", file=sys.stderr)
        return 2

    from mneme.core import detector, ioc, report, timeline
    from mneme.core.exporter import export as export_events
    from mneme.core.orchestrator import Orchestrator
    from mneme.core.parser import list_datasets, parse_rows

    case = args.output
    orch = Orchestrator(str(args.dump), vol_bin=args.vol_bin, raw_dir=case / "raw")
    os_type = args.os_type or orch.detect_os()
    print(f"[*] dump={args.dump.name} os={os_type} sha={orch.dump_sha[:16]}…")

    # 1. run plugins
    results = orch.full_analysis(os_type=os_type,
                                 progress=lambda p, s: print(f"    {s:5} {p}"))
    ok = [p for p, v in results.items() if not isinstance(v, dict)]
    failed = {p: v["error"] for p, v in results.items() if isinstance(v, dict)}
    print(f"[*] plugins: {len(ok)} ok, {len(failed)} failed")
    for p, err in failed.items():
        print(f"      FAIL {p}: {err[:100]}")

    # 2. parse → ECS, flag any collected dataset we cannot normalize
    import json
    ecs_dir = case / "ecs"
    ecs_dir.mkdir(parents=True, exist_ok=True)
    known = set(list_datasets())
    total, unparsed = 0, []
    for f in sorted((case / "raw").glob("*.json")):
        dataset = ".".join(p for p in f.stem.split(".")
                           if not (len(p) == 12 and all(c in "0123456789abcdef" for c in p)))
        rows = json.loads(f.read_text())
        rows = rows if isinstance(rows, list) else rows.get("rows", [rows])
        events = list(parse_rows(dataset, rows))
        if rows and not events:
            unparsed.append((dataset, len(rows), dataset in known))
        total += export_events(events, ecs_dir / f"{dataset}.ecs.jsonl", fmt="jsonl")
    print(f"[*] normalized {total} ECS events")
    if unparsed:
        print("[!] datasets with rows but ZERO parsed events (column drift?):")
        for ds, n, registered in unparsed:
            tag = "registered-but-empty" if registered else "no-parser"
            print(f"      {ds}: {n} raw rows → 0 events  [{tag}]")

    # 3. detect / timeline / report
    all_ecs = [rec for f in sorted(ecs_dir.glob("*.ecs.jsonl"))
               for rec in (json.loads(line) for line in f.read_text().splitlines() if line)]
    findings = detector.detect(all_ecs)
    tl = timeline.build(all_ecs)
    iocs = ioc.extract(all_ecs)
    html = report.render(dump=args.dump.name, os_type=os_type,
                         counts={"events": len(all_ecs), "detections": len(findings)},
                         findings=findings, timeline=tl, iocs=iocs)
    (case / "report.html").write_text(html, encoding="utf-8")
    print(f"[*] findings={len(findings)} timeline={len(tl)} "
          f"iocs={sum(len(v) for v in iocs.values())}")
    print(f"[*] report → {case / 'report.html'}")

    # non-zero exit if nothing parsed — a real dump must yield events
    return 0 if total > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
