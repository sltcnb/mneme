import json
from pathlib import Path

from mneme.core.parser import get_mapper, list_datasets, parse_rows

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _rows(name):
    return json.loads((FIXTURES / name).read_text())


def test_registry_has_core_datasets():
    ds = list_datasets()
    assert "windows.pslist" in ds
    assert "windows.netscan" in ds


def test_suffix_fallback():
    # linux.pslist not explicitly special-cased vs windows.pslist — suffix match works
    assert get_mapper("something.pslist") is not None


def test_pslist_maps_process():
    events = list(parse_rows("windows.pslist", _rows("windows.pslist.json")))
    assert len(events) == 7
    svc = next(e for e in events if e.process.pid == 2847)
    assert svc.process.name == "svchost.exe"
    assert svc.process.parent_pid == 1284
    assert svc.event.action == "process_create"
    assert svc.to_ecs()["@timestamp"] == "2024-01-15T10:32:14+00:00"


def test_netscan_maps_endpoints():
    events = list(parse_rows("windows.netscan", _rows("windows.netscan.json")))
    c2 = next(e for e in events if e.destination.ip == "185.234.72.19")
    assert c2.destination.port == 443
    assert c2.source.ip == "10.0.1.5"
    assert c2.process.pid == 2847


def test_malfind_flags_protection():
    events = list(parse_rows("windows.malfind", _rows("windows.malfind.json")))
    assert all(e.memory["kind"] == "malfind" for e in events)
    assert any("EXECUTE_READWRITE" in e.memory["protection"] for e in events)


def test_pstree_nested_children_flattened():
    events = list(parse_rows("windows.pstree", _rows("windows.pstree.json")))
    pids = {e.process.pid for e in events}
    assert pids == {4, 324, 488}  # root + nested descendants all surfaced
    wininit = next(e for e in events if e.process.pid == 488)
    assert wininit.process.parent_pid == 324
    assert "__children" not in wininit.memory["raw"]


def test_bad_row_skipped_not_fatal():
    rows = [{"garbage": 1}, {"PID": 5, "ImageFileName": "x"}]
    events = list(parse_rows("windows.pslist", rows))
    assert len(events) == 1 and events[0].process.pid == 5
