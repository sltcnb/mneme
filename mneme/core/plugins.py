"""Recommended Volatility3 plugin sets + OS detection heuristics.

Smart plugin selection: given a detected OS, return the ordered set of plugins
Mneme runs for a full triage. Plugins are grouped so the orchestrator can
run independent ones in parallel.
"""

from __future__ import annotations

RECOMMENDED_PLUGINS: dict[str, list[str]] = {
    "windows": [
        "windows.info",
        "windows.pslist",
        "windows.pstree",
        "windows.psscan",
        "windows.cmdline",
        "windows.dlllist",
        "windows.handles",
        "windows.malfind",
        "windows.netscan",
        "windows.filescan",
        "windows.registry.hivelist",
        "windows.svcscan",
        "windows.modscan",
        "windows.ssdt",
    ],
    "linux": [
        "linux.pslist",
        "linux.pstree",
        "linux.psaux",
        "linux.sockstat",
        "linux.lsof",
        "linux.check_syscall",
        "linux.check_idt",
        "linux.malfind",
        "linux.mounts",
    ],
    "mac": [
        "mac.pslist",
        "mac.pstree",
        "mac.psaux",
        "mac.netstat",
        "mac.check_syscall",
        "mac.lsof",
        "mac.malfind",
    ],
}

# Plugins that never depend on another's output → safe to run concurrently.
PARALLEL_SAFE = {
    "windows.pslist", "windows.pstree", "windows.psscan", "windows.cmdline",
    "windows.dlllist",
    "windows.netscan", "windows.filescan", "windows.malfind", "windows.svcscan",
    "windows.modscan", "windows.ssdt", "windows.handles",
    "linux.pslist", "linux.pstree", "linux.psaux", "linux.sockstat", "linux.lsof",
    "linux.malfind", "linux.check_syscall", "linux.check_idt",
    "mac.pslist", "mac.pstree", "mac.psaux", "mac.netstat", "mac.malfind",
}

_OS_MARKERS = (
    ("windows", ("windows.", "ntoskrnl", "\\systemroot", "kdbg", "pdb")),
    ("linux", ("linux.", "vmlinux", "swapper", "/proc/", "init_task")),
    ("mac", ("mac.", "kernel_task", "com.apple", "mach_kernel")),
)


def recommended(os_type: str) -> list[str]:
    """Ordered plugin list for an OS ('windows'|'linux'|'mac')."""
    if os_type not in RECOMMENDED_PLUGINS:
        raise ValueError(f"unknown os {os_type!r}; choose from {list(RECOMMENDED_PLUGINS)}")
    return list(RECOMMENDED_PLUGINS[os_type])


def detect_os(hint: str) -> str:
    """Best-effort OS guess from a free-text hint (banner, filename, path)."""
    low = (hint or "").lower()
    for os_type, markers in _OS_MARKERS:
        if any(m in low for m in markers):
            return os_type
    return "windows"  # most memory dumps in the wild
