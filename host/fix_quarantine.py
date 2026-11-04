#!/usr/bin/env python3
"""fix_quarantine PATH...: freeze, kill and delete unowned binaries/units, keeping evidence.

PATH may be a binary or a systemd unit. Every call re-reads the real state (running
pids, units that reference the binary, which files still exist) so a repeat run
after a respawn does the right thing. Evidence: /root/ir/<host>-<ts>/ (0700) + SHA256SUMS.
Order matters because the red team uses mutual respawn: copy, SIGSTOP all, stop+disable
units, SIGKILL, delete, daemon-reload, reset-failed.
"""
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time

from host import scan_unowned

EVIDENCE_ROOT = "/root/ir"
UNIT_DIRS = scan_unowned.UNIT_DIRS
QUIET = {"check": False, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}


def units_for(paths, unit_dirs=UNIT_DIRS, read=None):
    """Unit files that are in `paths` or whose ExecStart is one of them."""
    read = read or (lambda p: open(p, errors="replace").read())
    wanted = set(paths) | {os.path.realpath(p) for p in paths}
    found = set()
    for path in scan_unowned.list_files(unit_dirs):
        if not path.endswith(".service"):
            continue
        if path in wanted:
            found.add(path)
            continue
        try:
            if any(t in wanted or os.path.realpath(t) in wanted for t in scan_unowned.exec_target(read(path))):
                found.add(path)
        except OSError:
            pass
    return sorted(found)


def pids_for(paths, running=None):
    running = scan_unowned.running_executables() if running is None else running
    wanted = set(paths) | {os.path.realpath(p) for p in paths}
    return sorted({pid for exe, pids in running.items() if exe in wanted for pid in pids})


def preserve(paths, destination):
    os.makedirs(destination, mode=0o700, exist_ok=True)
    os.chmod(destination, 0o700)
    sums = []
    for path in paths:
        if not os.path.isfile(path) or os.path.islink(path):
            continue
        name = path.strip("/").replace("/", "__")
        copy = os.path.join(destination, name)
        shutil.copy2(path, copy)
        with open(copy, "rb") as handle:
            sums.append(f"{hashlib.sha256(handle.read()).hexdigest()}  {name}  # {path}\n")
    with open(os.path.join(destination, "SHA256SUMS"), "a") as handle:
        handle.writelines(sums)
    return destination


def wants_links(unit_name, base="/etc/systemd/system"):
    for directory in scan_unowned.expand([os.path.join(base, "*.wants"), os.path.join(base, "*.requires")]):
        link = os.path.join(directory, unit_name)
        if os.path.lexists(link):
            yield link


def _signal(kill, pid, sig):
    try:
        kill(pid, sig)
    except ProcessLookupError:
        pass


def quarantine(paths, evidence_root=EVIDENCE_ROOT, run=subprocess.run, kill=os.kill, remove=os.unlink,
               now=time.time, hostname=socket.gethostname, units=None, pids=None):
    paths = [p for p in paths if os.path.isabs(p)]
    units = units_for(paths) if units is None else units
    pids = pids_for(paths) if pids is None else pids
    targets = [p for p in dict.fromkeys([*units, *paths]) if os.path.lexists(p)]
    report = {"units": units, "pids": pids, "removed": [], "evidence": None}
    if not targets and not pids:
        return report  # already clean
    stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime(now()))
    report["evidence"] = preserve(targets, os.path.join(evidence_root, f"{hostname()}-{stamp}"))
    for pid in pids:
        _signal(kill, pid, signal.SIGSTOP)
    for unit in units:
        name = os.path.basename(unit)
        run(["systemctl", "stop", name], **QUIET)
        run(["systemctl", "disable", name], **QUIET)
    for pid in pids:
        _signal(kill, pid, signal.SIGKILL)
    for unit in units:
        for link in wants_links(os.path.basename(unit)):
            remove(link)
            report["removed"].append(link)
    for path in targets:
        try:
            remove(path)
            report["removed"].append(path)
        except FileNotFoundError:
            pass
    if units:
        run(["systemctl", "daemon-reload"], **QUIET)
        for unit in units:
            run(["systemctl", "reset-failed", os.path.basename(unit)], **QUIET)
    return report


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print("usage: fix_quarantine PATH...", file=sys.stderr)
        return 2
    try:
        print(json.dumps(quarantine(argv)))
    except (OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
