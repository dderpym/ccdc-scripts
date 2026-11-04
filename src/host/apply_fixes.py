#!/usr/bin/env python3
"""Apply reviewed permission fixes from integrity findings.

Reads a JSON list on stdin of either kind:
  {"path", "mode", "uid", "gid"}             absolute permission targets
  {"kind": "sysctl", "settings": {name: "0"}}  disable allow-listed features
Permission fixes touch only regular files and directories, never through a
symlink, verified on the opened descriptor. Sysctls are set live and persisted.
Exit status is nonzero if any fix could not be applied.
"""
import json
import os
import stat
import sys


SYSCTLS = {"kernel.unprivileged_userns_clone", "user.max_user_namespaces"}
SYSCTL_DROPIN = "/etc/sysctl.d/99-ccdc-userns.conf"


def apply_sysctl(fix, dropin=SYSCTL_DROPIN, proc="/proc/sys"):
    settings = fix["settings"]
    if not isinstance(settings, dict) or not settings or any(
            name not in SYSCTLS or value != "0" for name, value in settings.items()):
        raise ValueError("invalid sysctl fix")
    for name in sorted(settings):
        with open(os.path.join(proc, *name.split(".")), "w") as handle:
            handle.write("0\n")
    # Keep earlier entries of our own drop-in; replace atomically.
    try:
        with open(dropin) as handle:
            known = dict(line.strip().split(" = ", 1) for line in handle if " = " in line)
    except FileNotFoundError:
        known = {}
    known = {name: value for name, value in {**known, **settings}.items() if name in SYSCTLS}
    os.makedirs(os.path.dirname(dropin), mode=0o755, exist_ok=True)
    temporary = dropin + ".tmp"
    with open(temporary, "w") as handle:
        handle.write("# Managed by CCDC: disable unprivileged user namespaces\n"
                     + "".join("%s = %s\n" % item for item in sorted(known.items())))
    os.chmod(temporary, 0o644)
    os.replace(temporary, dropin)


def apply(fix):
    if fix.get("kind") == "sysctl":
        return apply_sysctl(fix)
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
            if fix.get("kind") == "sysctl":
                print("fixed sysctl " + ", ".join("%s=%s" % item for item in sorted(fix["settings"].items())))
            else:
                print("fixed %s -> %04o %d:%d" % (fix["path"], fix["mode"], fix["uid"], fix["gid"]))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            failed = True
            print("FAILED %s: %s" % (fix.get("path", fix.get("kind")) if isinstance(fix, dict) else fix, exc), file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
