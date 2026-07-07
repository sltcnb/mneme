"""Parse Volatility3 plugin JSON into normalized ECS ForensicEvents.

Vol3 `-r json` emits a list of row dicts whose columns vary per plugin. Each
mapper here is tolerant of column-name drift (Vol3 renames columns between
releases) via `_pick`, and stows the full raw row under `memory.raw` so nothing
is lost. Register a mapper per dataset (plugin name) so the CLI can dispatch on
the raw filename stem.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Iterator, Optional

from mneme.ecs.schema import Dll, Event, ForensicEvent, Host, Network, Process, Registry

Row = dict[str, Any]
Mapper = Callable[[Row], Optional[ForensicEvent]]
_REGISTRY: dict[str, Mapper] = {}


def register(*names: str):
    def deco(fn: Mapper):
        for n in names:
            _REGISTRY[n] = fn
        return fn
    return deco


def get_mapper(dataset: str) -> Optional[Mapper]:
    if dataset in _REGISTRY:
        return _REGISTRY[dataset]
    # tolerate os-prefix drift: windows.pslist ~ linux.pslist share a suffix
    suffix = dataset.split(".")[-1]
    for name, fn in _REGISTRY.items():
        if name.split(".")[-1] == suffix:
            return fn
    return None


def list_datasets() -> list[str]:
    return sorted(_REGISTRY)


def _pick(row: Row, *keys, default=None):
    """First present, non-empty value among candidate column names."""
    for k in keys:
        if k in row and row[k] not in (None, "", "-"):
            return row[k]
    return default


def _int(v) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _flatten(rows: Iterable[Row]) -> Iterator[Row]:
    """Expand Volatility3 tree output (pstree) into flat rows.

    The json renderer nests descendants under `__children`; walk them
    depth-first, stripping the key so each node maps like a plain row.
    Flat plugins have no `__children`, so this is a no-op for them.
    """
    for row in rows:
        if not isinstance(row, dict):
            continue
        children = row.get("__children") or []
        node = {k: v for k, v in row.items() if k != "__children"}
        yield node
        if children:
            yield from _flatten(children)


def parse_rows(dataset: str, rows: Iterable[Row]) -> Iterator[ForensicEvent]:
    mapper = get_mapper(dataset)
    if mapper is None:
        return
    for row in _flatten(rows):
        try:
            ev = mapper(row)
        except Exception:  # noqa: BLE001 — one bad row must not kill the run
            ev = None
        if ev is not None:
            ev.event.dataset = ev.event.dataset or dataset
            yield ev


# ── process listings ───────────────────────────────────────────────────────
@register("windows.pslist", "windows.pstree", "windows.psscan",
          "linux.pslist", "linux.pstree", "mac.pslist", "mac.pstree")
def _map_pslist(row: Row) -> Optional[ForensicEvent]:
    pid = _int(_pick(row, "PID", "Pid"))
    if pid is None:
        return None
    proc = Process(
        pid=pid,
        parent_pid=_int(_pick(row, "PPID", "Ppid")),
        name=_pick(row, "ImageFileName", "COMM", "Name", "Process"),
        start=_pick(row, "CreateTime", "Start", "StartTime"),
        exit=_pick(row, "ExitTime"),
        threads=_int(_pick(row, "Threads")),
        entity_id=str(_pick(row, "Offset(V)", "Offset", "OFFSET (V)", default=pid)),
    )
    return ForensicEvent(
        timestamp=proc.start, process=proc,
        event=Event(action="process_create", category=["process"], type=["start"]),
        message=f"process {proc.name} (pid {pid})",
        memory={"raw": row})


@register("windows.cmdline", "linux.psaux", "mac.psaux")
def _map_cmdline(row: Row) -> Optional[ForensicEvent]:
    pid = _int(_pick(row, "PID", "Pid"))
    if pid is None:
        return None
    cmd = _pick(row, "Args", "Arguments", "COMMAND", "Cmd")
    proc = Process(pid=pid, name=_pick(row, "Process", "COMM"), command_line=cmd)
    return ForensicEvent(
        process=proc,
        event=Event(action="process_cmdline", category=["process"]),
        message=cmd, memory={"raw": row})


# ── loaded modules / DLLs ────────────────────────────────────────────────────
@register("windows.dlllist")
def _map_dll(row: Row) -> Optional[ForensicEvent]:
    pid = _int(_pick(row, "PID", "Pid"))
    dll = Dll(
        name=_pick(row, "Name"), path=_pick(row, "Path"),
        base=str(_pick(row, "Base", default="")) or None,
        size=_int(_pick(row, "Size")))
    return ForensicEvent(
        timestamp=_pick(row, "LoadTime"),
        process=Process(pid=pid, name=_pick(row, "Process")) if pid else None,
        dll=dll,
        event=Event(action="dll_load", category=["library"], dataset="windows.dlllist"),
        message=f"dll {dll.name}", memory={"raw": row})


@register("windows.modscan", "windows.ssdt", "linux.check_syscall",
          "linux.check_idt", "mac.check_syscall")
def _map_module(row: Row) -> Optional[ForensicEvent]:
    name = _pick(row, "Name", "Module", "Symbol")
    return ForensicEvent(
        event=Event(action="kernel_module", category=["driver"]),
        message=f"module {name}",
        memory={"raw": row, "kind": "kernel_module",
                "base": str(_pick(row, "Base", default="")) or None})


# ── network ──────────────────────────────────────────────────────────────────
@register("windows.netscan", "linux.sockstat", "mac.netstat")
def _map_netscan(row: Row) -> Optional[ForensicEvent]:
    proto = _pick(row, "Proto", "Protocol", "Family")
    net = Network(protocol=proto, state=_pick(row, "State"))
    src = Host(ip=_pick(row, "LocalAddr", "Source", "LocalIP"),
               port=_int(_pick(row, "LocalPort")))
    dst = Host(ip=_pick(row, "ForeignAddr", "Destination", "ForeignIP"),
               port=_int(_pick(row, "ForeignPort")))
    pid = _int(_pick(row, "PID", "Pid"))
    return ForensicEvent(
        timestamp=_pick(row, "Created"),
        network=net, source=src, destination=dst,
        process=Process(pid=pid, name=_pick(row, "Owner", "Process")) if pid else None,
        event=Event(action="network_connection", category=["network"]),
        message=f"{src.ip}:{src.port} -> {dst.ip}:{dst.port}",
        memory={"raw": row})


# ── injected / suspicious memory (malfind) ───────────────────────────────────
@register("windows.malfind", "linux.malfind", "mac.malfind")
def _map_malfind(row: Row) -> Optional[ForensicEvent]:
    pid = _int(_pick(row, "PID", "Pid"))
    prot = _pick(row, "Protection", "Prot", default="")
    return ForensicEvent(
        process=Process(pid=pid, name=_pick(row, "Process", "Task")) if pid else None,
        event=Event(action="suspicious_memory", category=["intrusion_detection"],
                    type=["info"]),
        message=f"malfind region in pid {pid} ({prot})",
        memory={"raw": row, "kind": "malfind", "protection": prot,
                "start": _pick(row, "Start VPA", "Start", "Address")})


# ── services ─────────────────────────────────────────────────────────────────
@register("windows.svcscan")
def _map_svc(row: Row) -> Optional[ForensicEvent]:
    name = _pick(row, "Name")
    binary = _pick(row, "Binary", "Binary Path")
    return ForensicEvent(
        process=Process(command_line=binary, name=name),
        event=Event(action="service", category=["configuration"], dataset="windows.svcscan"),
        message=f"service {name} -> {binary}",
        memory={"raw": row, "kind": "service", "start_type": _pick(row, "Start"),
                "state": _pick(row, "State")})


# ── registry hives ───────────────────────────────────────────────────────────
@register("windows.registry.hivelist")
def _map_hive(row: Row) -> Optional[ForensicEvent]:
    path = _pick(row, "FileFullPath", "Name", "Path")
    return ForensicEvent(
        registry=Registry(hive=path),
        event=Event(action="registry_hive", category=["registry"]),
        message=f"hive {path}", memory={"raw": row})


# ── files ────────────────────────────────────────────────────────────────────
@register("windows.filescan", "linux.lsof", "mac.lsof")
def _map_file(row: Row) -> Optional[ForensicEvent]:
    path = _pick(row, "Name", "Path", "File Path")
    return ForensicEvent(
        event=Event(action="file_object", category=["file"]),
        message=f"file {path}", memory={"raw": row, "kind": "file", "path": path})
