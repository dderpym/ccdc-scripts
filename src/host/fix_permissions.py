#!/usr/bin/env python3
"""fix_permissions PATH [--clear OCTAL] [--root]: clear mode bits and/or chown to root, then print JSON.

Declarative: reads the current state of the opened file, so a stale scan cannot
set stale numbers. Regular files and directories only, never through a symlink.
"""
import argparse
import json
import os
import stat
import sys


def fix(path, clear=0, root=False):
    if not os.path.isabs(path):
        raise ValueError("path must be absolute")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise ValueError("not a regular file or directory")
        mode = stat.S_IMODE(info.st_mode)
        if root and (info.st_uid, info.st_gid) != (0, 0):
            os.fchown(fd, 0, 0)  # may clear setuid bits; mode is set after
        os.fchmod(fd, mode & ~clear)
        return {"path": path, "was": mode, "now": mode & ~clear}
    finally:
        os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    parser.add_argument("--clear", default="0")
    parser.add_argument("--root", action="store_true")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(fix(args.path, int(args.clear, 8), args.root)))
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
