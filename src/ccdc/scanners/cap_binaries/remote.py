#!/usr/bin/env python3
"""Unowned binaries carrying cap_setuid / cap_dac_override (file capabilities via getcap -r)."""
import json
import re
import subprocess
import sys

import pkgowner

DIRS = ["/usr", "/bin", "/sbin", "/opt", "/home", "/root", "/tmp", "/var/tmp", "/dev/shm", "/srv"]
DANGEROUS = ("cap_setuid", "cap_dac_override")
LINE = re.compile(r"^(/.*?)\s+(?:=\s*)?(cap_\S.*)$")


def parse(output):
    """(path, capabilities) from both getcap output styles."""
    for line in output.splitlines():
        match = LINE.match(line.strip())
        if match:
            yield match[1], match[2]


def scan(run=subprocess.run, owned=None):
    owned = owned or pkgowner.checker()
    try:
        result = run(["getcap", "-r", *DIRS], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"findings": [], "errors": ["getcap failed: %s" % exc]}
    findings, errors = [], []
    for path, caps in parse(result.stdout):
        dangerous = [c for c in DANGEROUS if c in caps]
        if not dangerous:
            continue
        state = owned(path)
        if state is None:
            errors.append("no package manager available; capability ownership not assessed")
            break
        if not state:
            findings.append({"path": path, "capabilities": caps, "dangerous": dangerous})
    return {"findings": findings, "errors": errors}


def main():
    print(json.dumps(scan()))


if __name__ == "__main__":
    sys.exit(main())
