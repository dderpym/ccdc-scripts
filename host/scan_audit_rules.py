#!/usr/bin/env python3
"""Read-only: report persistence watches not loaded in auditd. JSON {"findings", "errors"}."""
import json
import shutil
import subprocess

from host.audit_watches import WATCHES, missing_watches


def scan(run=subprocess.run, which=shutil.which):
    everything = [{"watch": path} for path, _ in WATCHES]
    if not which("auditctl"):
        return {"findings": everything, "errors": ["auditctl not installed"]}
    result = run(["auditctl", "-l"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode:
        return {"findings": everything, "errors": ["auditctl -l failed: " + result.stderr.strip()]}
    return {"findings": [{"watch": path} for path in missing_watches(result.stdout)], "errors": []}


def main():
    print(json.dumps(scan()))


if __name__ == "__main__":
    main()
