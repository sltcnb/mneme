import json
from pathlib import Path

from mneme.core import detector
from mneme.core.parser import parse_rows

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _ecs(name, dataset):
    rows = json.loads((FIXTURES / name).read_text())
    return [e.to_ecs() for e in parse_rows(dataset, rows)]


def _all_events():
    ev = []
    ev += _ecs("windows.pslist.json", "windows.pslist")
    ev += _ecs("windows.malfind.json", "windows.malfind")
    ev += _ecs("windows.netscan.json", "windows.netscan")
    ev += _ecs("windows.svcscan.json", "windows.svcscan")
    return ev


def test_injection_detects_rwx():
    ev = _ecs("windows.malfind.json", "windows.malfind")
    hits = detector.check_process_injection(ev)
    assert hits and all(h["technique"] == "RWX_MEMORY" for h in hits)
    assert all(h["severity"] == "high" for h in hits)  # both are RWX


def test_hollowing_detects_bad_parent():
    ev = _ecs("windows.pslist.json", "windows.pslist")
    hits = detector.check_process_hollowing(ev)
    # svchost.exe (2847) parent is explorer.exe, not services.exe
    assert any(h["pid"] == 2847 for h in hits)


def test_cred_theft_lsass_injection():
    ev = _ecs("windows.malfind.json", "windows.malfind")
    hits = detector.check_cred_theft(ev)
    assert any(h["technique"] == "LSASS_INJECTION" and h["severity"] == "critical"
               for h in hits)


def test_persistence_lolbin_service():
    ev = _ecs("windows.svcscan.json", "windows.svcscan")
    hits = detector.check_persistence(ev)
    # UpdaterSvc runs from Temp → flagged; Dnscache is clean
    assert len(hits) == 1 and hits[0]["type"] == "persistence"


def test_detect_ranks_and_correlates():
    findings = detector.detect(_all_events())
    assert findings
    # critical/high sort first
    assert findings[0]["severity"] in ("critical", "high")
    # pid 2847 appears in injection + hollowing → correlation bump
    p2847 = [f for f in findings if f.get("pid") == 2847]
    assert any(f.get("correlated", 0) >= 2 for f in p2847)


def test_dkom_end_to_end_via_parser():
    # pid 6666 is in psscan fixture but not in pslist → hidden
    ev = (_ecs("windows.pslist.json", "windows.pslist")
          + _ecs("windows.psscan.json", "windows.psscan"))
    hits = detector.check_dkom(ev)
    assert [h["pid"] for h in hits] == [6666]
    assert hits[0]["severity"] == "critical"


def test_dkom_scan_minus_list():
    events = [
        {"process": {"pid": 66}, "event": {"dataset": "windows.psscan"}},
        {"process": {"pid": 4}, "event": {"dataset": "windows.pslist"}},
        {"process": {"pid": 4}, "event": {"dataset": "windows.psscan"}},
    ]
    hits = detector.check_dkom(events)
    assert len(hits) == 1 and hits[0]["pid"] == 66
    assert hits[0]["severity"] == "critical"
