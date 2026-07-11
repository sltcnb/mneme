"""IOC extraction + STIX 2.1 bundle export.

Pulls indicators (IPs, domains, file paths, service binaries) out of normalized
events and emits either a flat list or a minimal STIX 2.1 bundle for threat-intel
sharing.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Iterable

Event = dict[str, Any]

_DOMAIN = re.compile(r"\b([a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

# File extensions that the domain regex would otherwise mistake for a TLD
# (e.g. "explorer.exe", "kernel32.dll"). Drop any match ending in one.
_FILE_EXT = {
    "exe", "dll", "sys", "dat", "tmp", "log", "ini", "bin", "cfg", "cpl",
    "scr", "bat", "cmd", "ps1", "vbs", "jar", "msi", "lnk",
    "db", "sqlite", "xml", "txt", "png", "jpg", "gif", "ico",
}
# NB: ".com" is intentionally NOT here — it collides with the .com TLD, which
# is far more common in evidence than legacy COM executables.


def _get(ev: Event, dotted: str, default=None):
    cur: Any = ev
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return default
        cur = cur.get(part)
        if cur is None:
            return default
    return cur


def _routable(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def extract(events: Iterable[Event]) -> dict[str, list[str]]:
    """Return {ipv4, domain, path} sorted unique indicator lists."""
    ips, domains, paths = set(), set(), set()
    for ev in events:
        for host in ("source.ip", "destination.ip"):
            ip = _get(ev, host)
            if ip and _routable(str(ip)):
                ips.add(str(ip))
        path = _get(ev, "memory.path") or _get(ev, "dll.path")
        if path:
            paths.add(str(path))
        cmd = _get(ev, "process.command_line") or ""
        for m in _IPV4.findall(cmd):
            if _routable(m):
                ips.add(m)
        for full in _DOMAIN.finditer(cmd):
            d = full.group(0).lower()
            if d.rsplit(".", 1)[-1] not in _FILE_EXT:
                domains.add(d)
    return {"ipv4": sorted(ips), "domain": sorted(domains), "path": sorted(paths)}


def _stix_quote(value: str) -> str:
    """Escape a value for a STIX 2.1 pattern string literal.

    Per the STIX 2.1 spec, backslash and single-quote are the only characters
    that must be escaped inside a single-quoted literal. Backslash must be
    escaped first so the quote-escape's own backslash is not doubled again.
    Windows paths (e.g. ``C:\\Windows\\...``) otherwise emit invalid patterns.
    """
    return value.replace("\\", "\\\\").replace("'", "\\'")


def to_stix(iocs: dict[str, list[str]], created: str = "1970-01-01T00:00:00Z") -> dict:
    """Minimal STIX 2.1 bundle of Indicator SDOs (id derived from value)."""
    import hashlib

    patterns = {
        "ipv4": lambda v: f"[ipv4-addr:value = '{_stix_quote(v)}']",
        "domain": lambda v: f"[domain-name:value = '{_stix_quote(v)}']",
        "path": lambda v: f"[file:name = '{_stix_quote(v)}']",
    }
    objects = []
    for kind, values in iocs.items():
        for v in values:
            oid = hashlib.sha256(f"{kind}:{v}".encode()).hexdigest()[:32]
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{_uuidish(oid)}",
                "created": created,
                "modified": created,
                "name": f"{kind} {v}",
                "pattern": patterns[kind](v),
                "pattern_type": "stix",
                "valid_from": created,
            })
    return {"type": "bundle", "id": f"bundle--{_uuidish('mneme')}", "objects": objects}


def _uuidish(seed: str) -> str:
    import hashlib
    h = hashlib.sha256(seed.encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
