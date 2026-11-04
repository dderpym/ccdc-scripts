"""Process and service attribution from /proc and pidfiles, shared by listener discovery and the update workflow.

Standard library only; runs on the target (python3.9+).
"""
import os
from pathlib import Path
import pwd
import re


def read(path):
    try:
        return Path(path).read_text(errors="replace")
    except OSError:
        return ""


def process_info(pid):
    base = Path("/proc") / str(pid)
    stat = read(base / "stat")
    try:
        parent = int(stat.rsplit(")", 1)[1].split()[1])
    except (ValueError, IndexError):
        parent = 0
    status = read(base / "status")
    uid = re.search(r"^Uid:\s+(\d+)", status, re.M)
    try:
        exe = os.readlink(base / "exe")
    except OSError:
        exe = None
    units = [part for line in read(base / "cgroup").splitlines()
             for part in line.split(":", 2)[-1].split("/") if part.endswith(".service")]
    return dict(parent=parent, process=read(base / "comm").strip() or None,
                executable=exe, uid=uid[1] if uid else None,
                service=units[-1] if units else None)


def username(uid):
    if uid is None:
        return None
    try:
        return pwd.getpwuid(int(uid)).pw_name
    except (KeyError, ValueError):
        return str(uid)


def service_hints():
    """Only associate live pidfiles; OpenRC names and runit cwd add evidence."""
    hints, runit = {}, {}
    started = {p.name for p in Path("/run/openrc/started").glob("*")}
    for path in sorted(Path("/run").glob("*.pid")):
        value = read(path).strip()
        if value.isdigit() and int(value) > 1 and Path("/proc", value).exists():
            name = path.stem
            # pidfiles can be stale/reused: never claim high confidence.
            hints.setdefault(int(value), []).append((name, name in started))
    for root in ("/var/service", "/etc/service", "/run/runit/service"):
        for path in sorted(Path(root).glob("*")):
            if path.is_dir():
                runit.setdefault(os.path.realpath(path), path.name)
    return hints, runit
