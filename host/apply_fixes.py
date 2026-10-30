#!/usr/bin/env python3
"""Apply reviewed permission fixes from integrity findings.

Reads a JSON list on stdin: [{"path", "mode", "uid", "gid"}, ...] (absolute
targets). Only regular files and directories are touched, never through a
symlink, and each is verified on the opened descriptor before changing it.
Exit status is nonzero if any fix could not be applied.
"""
import json
import os
import stat
import sys


def apply(fix):
    path, mode, uid, gid = fix["path"], fix["mode"], fix["uid"], fix["gid"]
    if not isinstance(path, str) or not os.path.isabs(path) or not all(
            isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in (mode, uid, gid)) or mode > 0o7777:
        raise ValueError("invalid fix")
    # O_NONBLOCK keeps a swapped-in FIFO from hanging us; the type check rejects it.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise ValueError("not a regular file or directory")
        if (info.st_uid, info.st_gid) != (uid, gid):
            os.fchown(fd, uid, gid)  # may clear setuid bits; mode is set after
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def main():
    failed = False
    for fix in json.load(sys.stdin):
        try:
            apply(fix)
            print("fixed %s -> %04o %d:%d" % (fix["path"], fix["mode"], fix["uid"], fix["gid"]))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            failed = True
            print("FAILED %s: %s" % (fix.get("path") if isinstance(fix, dict) else fix, exc), file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
