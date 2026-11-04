#!/usr/bin/env python3
"""Runs on the target. Fake kernel threads: a kernel-thread name whose /proc/PID/exe resolves."""
import argparse
import json

import procfs
import processes


def scan(root="/proc"):
    return {"findings": [p for p in procfs.processes(root) if processes.is_fake_kernel_thread(p)], "errors": []}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--proc", default="/proc")
    print(json.dumps(scan(parser.parse_args().proc)))
