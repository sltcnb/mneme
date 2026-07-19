"""Mneme CLI — run | parse | detect | timeline | report | export.

Pipeline mirrors a real IR workflow and keeps raw evidence separate from
derived data:

    run     dump.raw           → case/raw/<plugin>.json   (Volatility3 output)
    parse   case/raw           → case/ecs/<plugin>.ecs.jsonl
    detect  case/ecs           → ranked threat findings
    timeline case/ecs          → ordered / clustered events
    report  case/              → case/report.html
    export  case/ecs           → jsonl | csv

`run` needs Volatility3; every later stage works on any pre-collected Vol3 JSON.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

import click
from rich.console import Console
from rich.table import Table

from mneme.core import detector as detect_mod
from mneme.core import ioc as ioc_mod
from mneme.core import report as report_mod
from mneme.core import timeline as timeline_mod
from mneme.core.exporter import FORMATS
from mneme.core.exporter import export as export_events
from mneme.core.parser import list_datasets, parse_rows
from mneme.core.plugins import recommended
from mneme.ecs.schema import ForensicEvent

console = Console()


def _read_jsonl(path: Path) -> Iterator[dict]:
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)


def _load_ecs(ecs_input: Path) -> list[dict]:
    files = sorted(ecs_input.glob("*.ecs.jsonl")) if ecs_input.is_dir() else [ecs_input]
    return [rec for f in files for rec in _read_jsonl(f)]


@click.group()
@click.version_option(package_name="mneme-dfir", prog_name="mneme")
def cli():
    """Mneme — memory forensics toolkit built on Volatility3."""


# ── run ──────────────────────────────────────────────────────────────────
@cli.command()
@click.argument("dump", type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "-o", type=click.Path(file_okay=False), required=True,
              help="Case directory (raw/ created inside).")
@click.option("--os", "os_type", type=click.Choice(["windows", "linux", "mac"]),
              default=None, help="Force OS (default: infer from dump name).")
@click.option("--plugin", "plugins", multiple=True,
              help="Run only these plugins (repeatable).")
@click.option("--vol-bin", default="vol", show_default=True, help="Volatility3 binary.")
@click.option("--workers", default=4, show_default=True)
def run(dump, output, os_type, plugins, vol_bin, workers):
    """Run Volatility3 plugins against DUMP into <output>/raw/."""
    from mneme.core.orchestrator import Orchestrator

    orch = Orchestrator(dump, vol_bin=vol_bin, raw_dir=Path(output) / "raw",
                        workers=workers)
    if plugins:
        for p in plugins:
            console.print(f"[cyan]running[/] {p}…")
            try:
                path = orch.run_plugin(p)
                console.print(f"  [green]ok[/] → {path}")
            except Exception as e:  # noqa: BLE001
                console.print(f"  [red]failed[/]: {e}")
        return
    os_type = os_type or orch.detect_os()
    console.print(f"[dim]os={os_type}, plugins={len(recommended(os_type))}[/]")

    def _prog(plugin, state):
        color = {"start": "cyan", "done": "green", "error": "red"}[state]
        console.print(f"  [{color}]{state:5}[/] {plugin}")

    results = orch.full_analysis(os_type=os_type, progress=_prog)
    ok = sum(1 for v in results.values() if not isinstance(v, dict))
    console.print(f"[bold]{ok}/{len(results)}[/] plugins succeeded → {output}/raw/")


# ── parse ──────────────────────────────────────────────────────────────────
@cli.command()
@click.argument("raw_dir", type=click.Path(exists=True, file_okay=False))
@click.option("--output", "-o", type=click.Path(file_okay=False), required=True)
def parse(raw_dir, output):
    """Normalize raw Vol3 JSON into ECS events (<output>/ecs/)."""
    raw_dir = Path(raw_dir)
    out_dir = Path(output) / "ecs"
    out_dir.mkdir(parents=True, exist_ok=True)
    total = 0
    for f in sorted(raw_dir.glob("*.json")):
        # filename stem may carry a cache digest: windows.pslist.ab12cd34
        dataset = ".".join(p for p in f.stem.split(".") if not _is_digest(p))
        try:
            rows = json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            console.print(f"[yellow]skip[/] {f.name}: bad JSON")
            continue
        if isinstance(rows, dict):
            rows = rows.get("rows", []) or [rows]
        events = list(parse_rows(dataset, rows))
        if not events:
            console.print(f"[yellow]skip[/] {f.name}: no parser for {dataset!r}")
            continue
        dest = out_dir / f"{dataset}.ecs.jsonl"
        n = export_events(events, dest, fmt="jsonl")
        total += n
        console.print(f"[green]{n}[/] events  {f.name} → {dest.name}")
    console.print(f"[bold]total:[/] {total} ECS events")


def _is_digest(part: str) -> bool:
    return len(part) == 12 and all(c in "0123456789abcdef" for c in part)


# ── detect ───────────────────────────────────────────────────────────────────
@cli.command()
@click.argument("ecs_input", type=click.Path(exists=True))
@click.option("--yara", "yara_rules", type=click.Path(exists=True), default=None,
              help="Compiled/source YARA rules file.")
@click.option("--json", "as_json", is_flag=True)
def detect(ecs_input, yara_rules, as_json):
    """Run malware-detection heuristics over normalized events."""
    events = _load_ecs(Path(ecs_input))
    findings = detect_mod.detect(events, yara_rules=yara_rules)
    if as_json:
        click.echo(json.dumps(findings, indent=2, default=str))
        return
    if not findings:
        console.print("[green]no threats detected[/]")
        return
    t = Table("severity", "conf", "type", "technique", "ATT&CK", "detail",
              title=f"[red]Threat findings ({len(findings)})[/]")
    for f in findings:
        t.add_row(f["severity"], f"{int(f['confidence']*100)}%", f["type"],
                  f.get("technique", ""), f.get("mitre", ""),
                  f"{f.get('process') or ''} {f.get('evidence') or ''}"[:70])
    console.print(t)


# ── timeline ─────────────────────────────────────────────────────────────────
@cli.command()
@click.argument("ecs_input", type=click.Path(exists=True))
@click.option("--cluster", "do_cluster", is_flag=True, help="Cluster by 1s window.")
@click.option("--json", "as_json", is_flag=True)
@click.option("--limit", default=50, show_default=True)
def timeline(ecs_input, do_cluster, as_json, limit):
    """Build a timeline from normalized events."""
    events = _load_ecs(Path(ecs_input))
    tl = timeline_mod.build(events)
    if do_cluster:
        clusters = timeline_mod.cluster(tl)
        if as_json:
            click.echo(json.dumps(clusters, indent=2, default=str))
            return
        for c in clusters[:limit]:
            console.print(f"[bold]{c['window']}[/] [{c['max_severity']}] "
                          f"{len(c['events'])} events")
        return
    if as_json:
        click.echo(json.dumps(tl, indent=2, default=str))
        return
    t = Table("time", "sev", "action", "description", title="Timeline")
    for e in tl[:limit]:
        t.add_row(str(e["@timestamp"]), e["severity"], e["action"],
                  str(e["description"])[:60])
    console.print(t)


# ── report ───────────────────────────────────────────────────────────────────
@cli.command()
@click.argument("case_dir", type=click.Path(exists=True, file_okay=False))
@click.option("--os", "os_type", default="windows", show_default=True)
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Report path (default: <case>/report.html).")
def report(case_dir, os_type, output):
    """Render an HTML report from a case directory's ecs/ output."""
    case = Path(case_dir)
    ecs_dir = case / "ecs" if (case / "ecs").exists() else case
    events = _load_ecs(ecs_dir)
    findings = detect_mod.detect(events)
    tl = timeline_mod.build(events)
    iocs = ioc_mod.extract(events)
    counts = {
        "processes": sum(1 for e in events if e.get("event", {}).get("action") == "process_create"),
        "network": sum(1 for e in events if "network" in e),
        "dlls": sum(1 for e in events if "dll" in e),
        "detections": len(findings),
    }
    out = Path(output) if output else case / "report.html"
    html = report_mod.render(dump=case.name, os_type=os_type, counts=counts,
                             findings=findings, timeline=tl, iocs=iocs)
    out.write_text(html, encoding="utf-8")
    console.print(f"[green]report[/] → {out}  ({len(findings)} findings, {len(tl)} events)")


# ── export ───────────────────────────────────────────────────────────────────
@cli.command()
@click.argument("ecs_input", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(FORMATS), default="jsonl",
              show_default=True)
@click.option("--output", "-o", type=click.Path(), required=True)
@click.option("--gzip", "gz", is_flag=True)
def export(ecs_input, fmt, output, gz):
    """Convert normalized events to jsonl/csv."""
    events = (ForensicEvent(**rec) for rec in _load_ecs(Path(ecs_input)))
    n = export_events(events, Path(output), fmt=fmt, gz=gz)
    console.print(f"[green]{n}[/] events → {output}")


# ── stix ─────────────────────────────────────────────────────────────────────
@cli.command()
@click.argument("ecs_input", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), default=None)
def stix(ecs_input, output):
    """Extract IOCs and emit a STIX 2.1 bundle."""
    events = _load_ecs(Path(ecs_input))
    iocs = ioc_mod.extract(events)
    bundle = ioc_mod.to_stix(iocs)
    text = json.dumps(bundle, indent=2)
    if output:
        Path(output).write_text(text, encoding="utf-8")
        console.print(f"[green]{len(bundle['objects'])}[/] indicators → {output}")
    else:
        click.echo(text)


# ── helpers ──────────────────────────────────────────────────────────────────
@cli.command("plugins")
@click.option("--os", "os_type", type=click.Choice(["windows", "linux", "mac"]),
              default="windows", show_default=True)
def plugins_cmd(os_type):
    """List recommended plugins for an OS."""
    t = Table("plugin", title=f"Recommended — {os_type}")
    for p in recommended(os_type):
        t.add_row(p)
    console.print(t)


@cli.command("parsers")
def parsers_cmd():
    """List datasets with a registered parser."""
    t = Table("dataset")
    for d in list_datasets():
        t.add_row(d)
    console.print(t)


@cli.command("serve")
@click.option("--host", default="127.0.0.1", show_default=True,
              help="Bind address. The API ships no auth — only bind a public "
                   "interface (e.g. 0.0.0.0) behind a trusted gateway.")
@click.option("--port", default=8080, show_default=True)
def serve(host, port):
    """Launch the web GUI (requires mneme-dfir[web])."""
    try:
        import uvicorn
    except ImportError as e:
        raise click.ClickException("web extras missing — `pip install mneme-dfir[web]`") from e
    uvicorn.run("mneme.api.server:app", host=host, port=port)


if __name__ == "__main__":
    cli()
