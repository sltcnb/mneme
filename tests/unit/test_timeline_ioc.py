import json
from pathlib import Path

from mneme.core import ioc, timeline
from mneme.core.parser import parse_rows

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _ecs(name, dataset):
    rows = json.loads((FIXTURES / name).read_text())
    return [e.to_ecs() for e in parse_rows(dataset, rows)]


def _events():
    return (_ecs("windows.pslist.json", "windows.pslist")
            + _ecs("windows.netscan.json", "windows.netscan"))


def test_timeline_sorted_and_dated_only():
    tl = timeline.build(_events())
    ts = [e["@timestamp"] for e in tl]
    assert ts == sorted(ts)
    assert all(e["@timestamp"] for e in tl)


def test_timeline_severity_for_network():
    tl = timeline.build(_ecs("windows.netscan.json", "windows.netscan"))
    assert all(e["severity"] == "medium" for e in tl)


def test_cluster_groups_by_second():
    tl = timeline.build(_events())
    clusters = timeline.cluster(tl, window_seconds=1)
    assert clusters
    assert sum(len(c["events"]) for c in clusters) == len(tl)


def test_ioc_extract_public_only():
    iocs = ioc.extract(_ecs("windows.netscan.json", "windows.netscan"))
    assert "185.234.72.19" in iocs["ipv4"]
    assert "8.8.8.8" in iocs["ipv4"]
    assert "10.0.1.5" not in iocs["ipv4"]  # private, dropped


def test_ioc_domains_skip_file_extensions():
    events = [{
        "process": {"command_line":
                    "rundll32.exe evil.dll,Start; beacon to bad-c2.example.com"},
        "event": {"action": "process_cmdline"},
    }]
    iocs = ioc.extract(events)
    assert "bad-c2.example.com" in iocs["domain"]
    assert "rundll32.exe" not in iocs["domain"]
    assert "evil.dll" not in iocs["domain"]


def test_stix_bundle_shape():
    iocs = {"ipv4": ["185.234.72.19"], "domain": [], "path": []}
    bundle = ioc.to_stix(iocs)
    assert bundle["type"] == "bundle"
    assert bundle["objects"][0]["type"] == "indicator"
    assert "ipv4-addr:value = '185.234.72.19'" in bundle["objects"][0]["pattern"]
