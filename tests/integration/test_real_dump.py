"""Opt-in end-to-end test against a real memory dump.

Skipped unless BOTH hold:
  - Volatility3's `vol` is on PATH
  - MNEME_TEST_DUMP points at a real memory image

Run it with:  MNEME_TEST_DUMP=/path/to/mem.raw pytest -m integration
"""

import os
import shutil

import pytest

DUMP = os.environ.get("MNEME_TEST_DUMP")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("vol") is None, reason="Volatility3 not installed"),
    pytest.mark.skipif(not DUMP, reason="set MNEME_TEST_DUMP to a real memory image"),
]


def test_full_pipeline_on_real_dump(tmp_path):
    import json

    from mneme.core import detector, timeline
    from mneme.core.exporter import export as export_events
    from mneme.core.orchestrator import Orchestrator
    from mneme.core.parser import parse_rows

    case = tmp_path / "case"
    orch = Orchestrator(DUMP, raw_dir=case / "raw")
    os_type = orch.detect_os()
    results = orch.full_analysis(os_type=os_type)

    # at least one plugin must succeed
    ok = [p for p, v in results.items() if not isinstance(v, dict)]
    assert ok, f"no plugin succeeded: {results}"

    # parse to ECS
    ecs = case / "ecs"
    ecs.mkdir(parents=True)
    total = 0
    for f in sorted((case / "raw").glob("*.json")):
        dataset = ".".join(p for p in f.stem.split(".")
                           if not (len(p) == 12 and all(c in "0123456789abcdef" for c in p)))
        rows = json.loads(f.read_text())
        rows = rows if isinstance(rows, list) else [rows]
        total += export_events(parse_rows(dataset, rows), ecs / f"{dataset}.ecs.jsonl")
    assert total > 0, "no events normalized from a real dump — parser column drift?"

    all_ecs = [json.loads(line) for f in ecs.glob("*.ecs.jsonl")
               for line in f.read_text().splitlines() if line]
    # process listing must yield processes
    assert any("process" in e for e in all_ecs)
    # detection + timeline must not raise
    detector.detect(all_ecs)
    assert timeline.build(all_ecs) is not None
