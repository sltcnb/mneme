"""Malware detection engine.

Heuristics over normalized ECS events (as produced by parse). Each check returns
ThreatFinding dicts with a technique, MITRE ATT&CK id, evidence, and a base
confidence; `detect()` aggregates, scores, and ranks them. Pure functions over
in-memory event lists — no dump access needed, so it runs on any Vol3 output.

Optional YARA scanning is wired via `yara_scan` if `yara-python` and rules are
present; absent that, heuristics still run.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable, Optional

Event = dict[str, Any]

SEVERITY = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Windows processes whose parent is well-known; anomalous parents are suspicious.
_EXPECTED_PARENT = {
    "svchost.exe": "services.exe",
    "services.exe": "wininit.exe",
    "lsass.exe": "wininit.exe",
    "smss.exe": "System",
    "csrss.exe": "smss.exe",
    "wininit.exe": "smss.exe",
    "winlogon.exe": "smss.exe",
}
_RWX = ("PAGE_EXECUTE_READWRITE", "RWX", "EXECUTE_READWRITE")
_LOLBINS = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
            "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"}


def _get(ev: Event, dotted: str, default=None):
    cur: Any = ev
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return default
        cur = cur.get(part)
        if cur is None:
            return default
    return cur


def _finding(**kw) -> dict[str, Any]:
    kw.setdefault("severity", "medium")
    kw.setdefault("confidence", 0.5)
    return kw


# ── individual heuristics ────────────────────────────────────────────────────
def check_process_injection(events: Iterable[Event]) -> list[dict]:
    """malfind RWX regions → classic code injection (T1055)."""
    out = []
    for ev in events:
        if _get(ev, "memory.kind") != "malfind":
            continue
        prot = str(_get(ev, "memory.protection", "")).upper()
        rwx = any(m in prot for m in _RWX)
        out.append(_finding(
            type="process_injection", technique="RWX_MEMORY",
            mitre="T1055", pid=_get(ev, "process.pid"),
            process=_get(ev, "process.name"),
            severity="high" if rwx else "medium",
            confidence=0.75 if rwx else 0.45,
            evidence=f"executable private memory ({prot})"))
    return out


def check_process_hollowing(events: Iterable[Event]) -> list[dict]:
    """Process whose parent is not its canonical parent → hollowing/masquerade."""
    procs = {}
    for ev in events:
        # Only trust process listings for the parent relationship; other
        # plugins (malfind, netscan) carry a pid with no/blank parent and
        # would otherwise clobber the real ppid.
        ds = _get(ev, "event.dataset", "")
        if "pslist" not in ds and "pstree" not in ds:
            continue
        pid = _get(ev, "process.pid")
        name = _get(ev, "process.name")
        ppid = _get(ev, "process.parent_pid")
        if pid is not None and name:
            procs[pid] = {"name": name.lower(), "ppid": ppid}
    by_pid_name = {pid: p["name"] for pid, p in procs.items()}
    out = []
    for pid, p in procs.items():
        expected = _EXPECTED_PARENT.get(p["name"])
        if not expected:
            continue
        parent_name = by_pid_name.get(p["ppid"])
        if parent_name and parent_name != expected.lower():
            out.append(_finding(
                type="process_hollowing", technique="ANOMALOUS_PARENT",
                mitre="T1055.012", pid=pid, process=p["name"],
                severity="high", confidence=0.65,
                evidence=f"{p['name']} parent is {parent_name}, expected {expected}"))
    return out


def check_dkom(events: Iterable[Event]) -> list[dict]:
    """Processes visible via scan but absent from the active list → DKOM hiding."""
    listed, scanned = set(), set()
    for ev in events:
        pid = _get(ev, "process.pid")
        ds = _get(ev, "event.dataset", "")
        if pid is None:
            continue
        if "pslist" in ds or "pstree" in ds:
            listed.add(pid)
        if "psscan" in ds:
            scanned.add(pid)
    out = []
    for pid in scanned - listed:
        out.append(_finding(
            type="dkom", technique="HIDDEN_PROCESS", mitre="T1014",
            pid=pid, severity="critical", confidence=0.8,
            evidence="process found by scan but missing from active list"))
    return out


def check_rootkit(events: Iterable[Event]) -> list[dict]:
    """Hooked syscall / SSDT / IDT entries pointing outside known modules."""
    out = []
    for ev in events:
        if _get(ev, "memory.kind") != "kernel_module":
            continue
        raw = _get(ev, "memory.raw", {}) or {}
        hooked = any(str(v).lower() in ("hooked", "true", "unknown")
                     for k, v in raw.items() if "hook" in k.lower())
        if hooked:
            out.append(_finding(
                type="rootkit", technique="SYSCALL_HOOK", mitre="T1014",
                severity="high", confidence=0.6,
                evidence=f"hooked kernel entry: {_get(ev, 'message')}"))
    return out


def check_persistence(events: Iterable[Event]) -> list[dict]:
    """Services or run-keys launching LOLBins / suspicious binaries."""
    out = []
    for ev in events:
        if _get(ev, "memory.kind") != "service":
            continue
        binary = str(_get(ev, "process.command_line", "")).lower()
        if any(lol in binary for lol in _LOLBINS) or "\\temp\\" in binary \
                or "appdata" in binary:
            out.append(_finding(
                type="persistence", technique="SERVICE_LOLBIN", mitre="T1543.003",
                process=_get(ev, "process.name"), severity="medium", confidence=0.55,
                evidence=f"service binary: {binary[:120]}"))
    return out


def check_cred_theft(events: Iterable[Event]) -> list[dict]:
    """Non-system processes touching lsass, or malfind inside lsass."""
    out = []
    for ev in events:
        name = str(_get(ev, "process.name", "")).lower()
        msg = str(_get(ev, "message", "")).lower()
        touches_lsass = "lsass" in name or "lsass" in msg
        if "lsass" in name and _get(ev, "memory.kind") == "malfind":
            out.append(_finding(
                type="credential_theft", technique="LSASS_INJECTION",
                mitre="T1003.001", pid=_get(ev, "process.pid"),
                severity="critical", confidence=0.7,
                evidence="injected memory in lsass"))
        elif name and name not in ("lsass.exe", "system") and touches_lsass:
            out.append(_finding(
                type="credential_theft", technique="LSASS_ACCESS",
                mitre="T1003.001", process=name, severity="high", confidence=0.5,
                evidence=f"{name} references lsass"))
    return out


HEURISTICS = [
    check_process_injection, check_process_hollowing, check_dkom,
    check_rootkit, check_persistence, check_cred_theft,
]


def _score(finding: dict) -> float:
    """Bump confidence when multiple signals hit the same pid."""
    return min(1.0, finding.get("confidence", 0.5))


def detect(events: Iterable[Event], yara_rules: Optional[str] = None) -> list[dict]:
    """Run all heuristics; return findings ranked by severity then confidence."""
    events = list(events)
    findings: list[dict] = []
    for check in HEURISTICS:
        findings.extend(check(events))
    if yara_rules:
        findings.extend(yara_scan(events, yara_rules))

    # correlate: findings sharing a pid reinforce each other's confidence
    by_pid: dict[Any, list[dict]] = defaultdict(list)
    for f in findings:
        if f.get("pid") is not None:
            by_pid[f["pid"]].append(f)
    for group in by_pid.values():
        if len(group) > 1:
            for f in group:
                f["confidence"] = min(1.0, f["confidence"] + 0.1 * (len(group) - 1))
                f["correlated"] = len(group)

    for f in findings:
        f["confidence"] = round(_score(f), 2)
    return sorted(findings, key=lambda f: (SEVERITY.get(f["severity"], 0),
                                           f["confidence"]), reverse=True)


def yara_scan(events: Iterable[Event], rules_path: str) -> list[dict]:
    """Scan malfind hexdumps with YARA rules, if yara-python is available."""
    try:
        import yara  # type: ignore
    except ImportError:
        return []
    try:
        rules = yara.compile(filepath=rules_path)
    except Exception:  # noqa: BLE001
        return []
    out = []
    for ev in events:
        if _get(ev, "memory.kind") != "malfind":
            continue
        raw = _get(ev, "memory.raw", {}) or {}
        blob = str(raw.get("Hexdump") or raw.get("Disasm") or "").encode()
        if not blob:
            continue
        for m in rules.match(data=blob):
            out.append(_finding(
                type="yara_match", technique=str(m.rule), mitre="",
                pid=_get(ev, "process.pid"), severity="high", confidence=0.85,
                evidence=f"YARA rule {m.rule}"))
    return out
