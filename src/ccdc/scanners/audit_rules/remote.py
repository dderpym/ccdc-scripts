#!/usr/bin/env python3
"""Read-only: report persistence watches not LOADED in the kernel audit subsystem (`auditctl -l`) and
whether auditing is actually enabled (`auditctl -s`); rules files are never consulted. JSON {"findings", "errors"}."""
import json
import shutil
import subprocess

from audit_watches import WATCHES, missing_watches


def status_enabled(output):
    """Kernel audit `enabled` flag (0 off, 1 on, 2 on and locked) from `auditctl -s`, or None."""
    for line in output.splitlines():
        fields = line.replace("=", " ").split()
        if len(fields) >= 2 and fields[0] == "enabled" and fields[1].isdigit():
            return int(fields[1])
    return None


def scan(run=subprocess.run, which=shutil.which):
    everything = [{"watch": path} for path, _ in WATCHES]
    if not which("auditctl"):
        return {"findings": everything, "errors": ["auditctl not installed"]}
    kw = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    result = run(["auditctl", "-l"], **kw)
    if result.returncode:
        return {"findings": everything, "errors": ["auditctl -l failed: " + result.stderr.strip()]}
    findings, errors = [{"watch": path} for path in missing_watches(result.stdout)], []
    status = run(["auditctl", "-s"], **kw)
    enabled = None if status.returncode else status_enabled(status.stdout)
    if enabled is None:
        errors.append("auditctl -s gave no enabled flag: " + (status.stderr.strip() or "unparseable"))
    elif enabled == 0:
        findings.append({"disabled": True})
    return {"findings": findings, "errors": errors}


def main():
    print(json.dumps(scan()))


if __name__ == "__main__":
    main()
