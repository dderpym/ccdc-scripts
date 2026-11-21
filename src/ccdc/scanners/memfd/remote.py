#!/usr/bin/env python3
"""Runs on the target. Processes running fileless (exe -> /memfd:...) or from a deleted file."""
import argparse
import json

import procfs
import processes


def scan(root="/proc"):
    findings = [dict(proc, kind=kind) for proc in procfs.processes(root)
                if (kind := processes.classify_exe(proc["exe"]))]
    return {"findings": findings, "errors": []}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--proc", default="/proc")
    print(json.dumps(scan(parser.parse_args().proc)))
