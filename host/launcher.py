"""Entry point of the bundle shipped to targets: python3 bundle.pyz ENTRY [ARG...].

Every controller-to-host action runs through here, so there is exactly one way
code reaches a target. Only listed entries (or host/{scan,fix,install,detect}_*.py modules) can be requested.
"""
import importlib.util
import os
import re
import runpy
import sys

ENTRIES = (
    "apply_fixes", "apply_ssh", "discover_firewall", "discover_integrity", "discover_listeners",
    "discover_lse", "discover_ssh", "manage_updates",
)
# New entries follow a naming convention instead of editing the tuple above, so
# independent features never collide here.
PREFIXES = ("scan_", "fix_", "install_", "detect_")


def allowed(name):
    if name in ENTRIES:
        return True
    return bool(re.fullmatch(r"(?:%s)[a-z0-9_]+" % "|".join(PREFIXES), name)
                and importlib.util.find_spec("host." + name))


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv or not allowed(argv[0]):
        print("usage: bundle ENTRY [ARG...]; ENTRY is one of: " + ", ".join(ENTRIES) + ", scan_*, fix_*, install_*, detect_*", file=sys.stderr)
        return 2
    entry, *arguments = argv
    # A request too large for argv arrives as a private file and is read as stdin.
    payload = os.environ.pop("CCDC_PAYLOAD", None)
    if payload:
        sys.stdin = open(payload, encoding="utf-8")
    sys.argv = [entry, *arguments]
    runpy.run_module("host." + entry, run_name="__main__", alter_sys=True)
    return 0
