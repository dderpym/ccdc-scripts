#!/usr/bin/env python3
"""Read-only: which desktop/hardware daemons are enabled or running RIGHT NOW (`systemctl is-enabled/is-active`).

Usage: scan_unneeded_services [--allow UNIT]... UNIT...
Prints {"findings": [{"unit", "enabled", "active"}], "errors": [...]}. Units that are not installed are
fine; a unit systemd cannot answer for is an error (the scan is incomplete), never silently clean.
"""
import argparse
import json
import shutil
import subprocess
import sys

ENABLED = {"enabled", "enabled-runtime", "alias", "linked", "linked-runtime"}
ACTIVE = {"active", "activating", "reloading"}


def query(verb, unit, run=subprocess.run):
    """(stdout state, returncode) of `systemctl VERB UNIT`."""
    result = run(["systemctl", verb, "--", unit], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def scan(units, allow=(), run=subprocess.run, which=shutil.which):
    if not which("systemctl"):
        return {"findings": [], "errors": ["systemctl not found; cannot inspect services"]}
    findings, errors = [], []
    for unit in units:
        if unit in allow:
            continue
        enabled, err, _ = query("is-enabled", unit, run)
        active, err2, _ = query("is-active", unit, run)
        if not enabled and "No such file" in err:
            continue  # not installed on this host
        if not enabled and not active:
            errors.append("%s: systemctl gave no answer (%s)" % (unit, err or err2 or "empty"))
            continue
        # is-enabled prints enabled/disabled/static/masked/...; is-active prints active/inactive/failed/...
        if enabled in ENABLED or active in ACTIVE:
            findings.append({"unit": unit, "enabled": enabled or "unknown", "active": active or "unknown"})
    return {"findings": findings, "errors": errors}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow", action="append", default=[])
    parser.add_argument("units", nargs="+")
    args = parser.parse_args(argv)
    print(json.dumps(scan(args.units, set(args.allow))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
