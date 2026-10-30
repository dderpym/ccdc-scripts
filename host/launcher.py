"""Entry point of the bundle shipped to targets: python3 bundle.pyz ENTRY [ARG...].

Every controller-to-host action runs through here, so there is exactly one way
code reaches a target. Only the entries listed below can be requested.
"""
import os
import runpy
import sys

ENTRIES = (
    "apply_fixes", "apply_ssh", "discover_firewall", "discover_integrity", "discover_listeners",
    "discover_lse", "discover_ssh", "manage_updates",
)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] not in ENTRIES:
        print("usage: bundle ENTRY [ARG...]; ENTRY is one of: " + ", ".join(ENTRIES), file=sys.stderr)
        return 2
    entry, *arguments = argv
    # A request too large for argv arrives as a private file and is read as stdin.
    payload = os.environ.pop("CCDC_PAYLOAD", None)
    if payload:
        sys.stdin = open(payload, encoding="utf-8")
    sys.argv = [entry, *arguments]
    runpy.run_module("host." + entry, run_name="__main__", alter_sys=True)
    return 0
