#!/usr/bin/env python3
"""fix_permissions PATH [--clear OCTAL] [--mode OCTAL] [--uid N] [--gid N] [--root]; prints JSON.

Declarative: acts on the opened file's current state, so a stale scan cannot set
stale numbers. --mode sets an exact mode, --clear then removes bits, --root means
root:root. Regular files and directories only, never through a symlink.
"""
import argparse
import json
import os
import stat
import sys


def fix(path, clear=0, root=False, mode=None, uid=None, gid=None):
    if not os.path.isabs(path):
        raise ValueError("path must be absolute")
    if root:
        uid, gid = 0, 0
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise ValueError("not a regular file or directory")
        was = stat.S_IMODE(info.st_mode)
        new_uid = info.st_uid if uid is None else uid
        new_gid = info.st_gid if gid is None else gid
        if (new_uid, new_gid) != (info.st_uid, info.st_gid):
            os.fchown(fd, new_uid, new_gid)  # may clear setuid bits; mode is set after
        now = (was if mode is None else mode) & ~clear
        os.fchmod(fd, now)
        return {"path": path, "was": was, "now": now}
    finally:
        os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    parser.add_argument("--clear", default="0")
    parser.add_argument("--mode")
    parser.add_argument("--uid", type=int)
    parser.add_argument("--gid", type=int)
    parser.add_argument("--root", action="store_true")
    args = parser.parse_args(argv)
    try:
        mode = int(args.mode, 8) if args.mode is not None else None
        if mode is not None and mode > 0o7777:
            raise ValueError("invalid mode")
        print(json.dumps(fix(args.path, int(args.clear, 8), args.root, mode, args.uid, args.gid)))
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
