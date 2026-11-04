#!/usr/bin/env python3
"""Runs on the target: remote.py PID KIND [--proc DIR]. SIGSTOP then SIGKILL a process only if
it still matches the finding. KIND is memfd or kworker; the process is re-classified right
before acting, so a recycled PID or a changed process is left alone."""
import argparse
import json
import os
import signal
import sys

import procfs
import processes


def kill(pid, kind, root="/proc", send=os.kill):
    proc = next((p for p in procfs.processes(root) if p["pid"] == pid), None)
    if proc is None:
        return {"pid": pid, "action": "gone"}
    if not processes.matches(proc, kind):
        return {"pid": pid, "action": "skipped", "reason": "process no longer matches"}
    send(pid, signal.SIGSTOP)  # freeze first so it cannot respawn or hand off while we work
    send(pid, signal.SIGKILL)
    return {"pid": pid, "action": "killed", "exe": proc["exe"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("pid", type=int)
    parser.add_argument("kind")
    parser.add_argument("--proc", default="/proc")
    args = parser.parse_args()
    try:
        print(json.dumps(kill(args.pid, args.kind, args.proc)))
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}))
        sys.exit(1)
