#!/usr/bin/env python3
"""Install the CCDC audit watch rules; JSON {"changed": bool, "missing": [...]}.

Compares content first, so repeated runs change nothing. The rules file is the
persistent copy; the loaded rule set is verified with auditctl -l.
"""
import json
import os
import subprocess
import sys

from audit_watches import missing_watches, rules_text

RULES_FILE = "/etc/audit/rules.d/99-ccdc.rules"


def loaded(run=subprocess.run):
    result = run(["auditctl", "-l"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    return result.stdout if result.returncode == 0 else ""


def install(path=RULES_FILE, run=subprocess.run):
    want = rules_text()
    try:
        with open(path) as handle:
            current = handle.read()
    except FileNotFoundError:
        current = None
    changed = current != want
    if changed:
        os.makedirs(os.path.dirname(path), mode=0o750, exist_ok=True)
        temporary = path + ".tmp"
        with open(temporary, "w") as handle:
            handle.write(want)
        os.chmod(temporary, 0o640)
        os.replace(temporary, path)
    missing = missing_watches(loaded(run))
    if missing:  # an unchanged file is not enough: the kernel may not have the rules
        load = run(["augenrules", "--load"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if load.returncode:
            run(["auditctl", "-R", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        missing = missing_watches(loaded(run))
    return {"changed": changed, "missing": missing}


def main():
    try:
        result = install()
    except OSError as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    print(json.dumps(result))
    return 1 if result["missing"] else 0


if __name__ == "__main__":
    sys.exit(main())
