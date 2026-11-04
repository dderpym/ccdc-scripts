#!/usr/bin/env python3
"""fix_kill_process PID KIND: SIGSTOP then SIGKILL a process only if it still matches the finding.

KIND is memfd or kworker. The process is re-classified right before acting, so a
recycled PID or a changed process is left alone.
"""
import json
import os
import signal
import sys

from host import procfs, scan_kworker, scan_memfd


def matches(proc, kind):
    if kind == "memfd":
        return scan_memfd.classify(proc["exe"]) is not None
    if kind == "kworker":
        return scan_kworker.is_fake(proc)
    raise ValueError("unknown kind: " + kind)


def kill(pid, kind, root="/proc", send=os.kill):
    proc = next((p for p in procfs.processes(root) if p["pid"] == pid), None)
    if proc is None:
        return {"pid": pid, "action": "gone"}
    if not matches(proc, kind):
        return {"pid": pid, "action": "skipped", "reason": "process no longer matches"}
    send(pid, signal.SIGSTOP)  # freeze first so it cannot respawn or hand off while we work
    send(pid, signal.SIGKILL)
    return {"pid": pid, "action": "killed", "exe": proc["exe"]}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        print(json.dumps(kill(int(argv[0]), argv[1])))
    except (OSError, ValueError, IndexError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
