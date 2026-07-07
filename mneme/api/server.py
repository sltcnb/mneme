"""FastAPI backend + minimal single-page GUI for Mneme.

Web deployment mode (Docker / K8s). Exposes the pipeline over HTTP and serves a
dependency-free dashboard at `/`. Cases live under MNEME_DATA (default
/data). Designed for the multi-user story: JWT/OAuth and RBAC bolt on at the
gateway; per-user workspaces map to per-user case subdirectories.

Requires `mneme-dfir[web]`.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterator

from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse

from mneme.core import detector as detect_mod
from mneme.core import ioc as ioc_mod
from mneme.core import report as report_mod
from mneme.core import timeline as timeline_mod
from mneme.core.parser import parse_rows

DATA = Path(os.environ.get("MNEME_DATA", "/data"))
app = FastAPI(title="Mneme", version="0.1.0")


def _case(name: str) -> Path:
    # prevent path traversal — a single safe path segment only
    safe = Path(name).name
    if not safe or safe != name:
        raise HTTPException(400, "invalid case name")
    return DATA / "cases" / safe


def _read_jsonl(path: Path) -> Iterator[dict]:
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)


def _load_ecs(case: Path) -> list[dict]:
    ecs = case / "ecs"
    if not ecs.exists():
        return []
    return [rec for f in sorted(ecs.glob("*.ecs.jsonl")) for rec in _read_jsonl(f)]


@app.get("/api/cases")
def list_cases():
    root = DATA / "cases"
    if not root.exists():
        return {"cases": []}
    return {"cases": sorted(p.name for p in root.iterdir() if p.is_dir())}


@app.post("/api/cases/{name}/raw")
async def upload_raw(name: str, dataset: str, file: UploadFile):
    """Upload a raw Vol3 JSON file for a dataset, then parse it to ECS."""
    case = _case(name)
    (case / "raw").mkdir(parents=True, exist_ok=True)
    (case / "ecs").mkdir(parents=True, exist_ok=True)
    raw = case / "raw" / f"{dataset}.json"
    raw.write_bytes(await file.read())
    try:
        rows = json.loads(raw.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise HTTPException(400, "uploaded file is not valid JSON") from e
    events = list(parse_rows(dataset, rows if isinstance(rows, list) else [rows]))
    from mneme.core.exporter import export as export_events
    n = export_events(events, case / "ecs" / f"{dataset}.ecs.jsonl", fmt="jsonl")
    return {"dataset": dataset, "events": n}


@app.get("/api/cases/{name}/detections")
def detections(name: str):
    events = _load_ecs(_case(name))
    return {"findings": detect_mod.detect(events)}


@app.get("/api/cases/{name}/timeline")
def timeline(name: str, cluster: bool = False):
    events = _load_ecs(_case(name))
    tl = timeline_mod.build(events)
    return {"timeline": timeline_mod.cluster(tl) if cluster else tl}


@app.get("/api/cases/{name}/iocs")
def iocs(name: str):
    return ioc_mod.extract(_load_ecs(_case(name)))


@app.get("/api/cases/{name}/report", response_class=HTMLResponse)
def report(name: str, os_type: str = "windows"):
    case = _case(name)
    events = _load_ecs(case)
    findings = detect_mod.detect(events)
    tl = timeline_mod.build(events)
    counts = {
        "processes": sum(1 for e in events if e.get("event", {}).get("action") == "process_create"),
        "network": sum(1 for e in events if "network" in e),
        "dlls": sum(1 for e in events if "dll" in e),
        "detections": len(findings),
    }
    return report_mod.render(dump=name, os_type=os_type, counts=counts,
                             findings=findings, timeline=tl,
                             iocs=ioc_mod.extract(events))


@app.get("/healthz")
def healthz():
    return JSONResponse({"status": "ok"})


@app.get("/", response_class=HTMLResponse)
def index():
    return _INDEX_HTML


_INDEX_HTML = """<!doctype html><html><head><meta charset="utf-8">
<title>Mneme</title><style>
 body{font:14px system-ui,sans-serif;margin:0;background:#0f1115;color:#e6e6e6}
 header{padding:20px 28px;background:#161a22;border-bottom:1px solid #262b36}
 main{padding:24px 28px;max-width:900px} select,button{font:inherit;padding:6px 10px}
 pre{background:#161a22;padding:14px;border-radius:8px;overflow:auto;border:1px solid #262b36}
 h1{margin:0;font-size:18px}
</style></head><body>
<header><h1>Mneme — Memory Forensics</h1></header>
<main>
 <p>Case: <select id="case"></select>
    <button onclick="load('detections')">Detections</button>
    <button onclick="load('timeline')">Timeline</button>
    <button onclick="load('iocs')">IOCs</button>
    <button onclick="openReport()">Open report</button></p>
 <pre id="out">select a case…</pre>
</main>
<script>
async function cases(){
  const r = await fetch('/api/cases'); const j = await r.json();
  const s = document.getElementById('case');
  s.innerHTML = j.cases.map(c=>`<option>${c}</option>`).join('') || '<option>(none)</option>';
}
async function load(kind){
  const c = document.getElementById('case').value;
  const r = await fetch(`/api/cases/${c}/${kind}`);
  document.getElementById('out').textContent = JSON.stringify(await r.json(), null, 2);
}
function openReport(){
  const c = document.getElementById('case').value;
  window.open(`/api/cases/${c}/report`, '_blank');
}
cases();
</script></body></html>"""
