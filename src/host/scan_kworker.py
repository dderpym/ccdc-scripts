#!/usr/bin/env python3
"""Fake kernel threads: a kernel-thread name whose /proc/PID/exe resolves (real ones have none)."""
import json
import re
import sys

from host import procfs

# Names kernel threads really use. Plain "k*" would also match kubelet, klogd, ...
KERNEL_THREAD = re.compile(r"^(kworker|ksoftirqd|kthreadd|kswapd|kcompactd|khugepaged|kdevtmpfs|kauditd|"
                           r"khungtaskd|kblockd|ksmd|kintegrityd|kpsmoused|kthrotld|kstrp|kcryptd|kmpath|kdmflush)")


def is_fake(proc):
    return bool(proc["exe"]) and bool(KERNEL_THREAD.match(proc["comm"]))


def scan(root="/proc"):
    return {"findings": [p for p in procfs.processes(root) if is_fake(p)], "errors": []}


def main():
    print(json.dumps(scan()))


if __name__ == "__main__":
    sys.exit(main())
