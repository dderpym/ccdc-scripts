#!/usr/bin/env python3
"""fix_ssh_vectors remove-file PATH | remove-key FILE FINGERPRINT [--allow-key LINE]...

Both actions first copy the original into /root/ir/<host>-<time>/ (0700, SHA256SUMS), so
the cleanup is reversible. remove-file accepts only /etc/ssh/sshrc and */.ssh/rc.
remove-key drops every line with that fingerprint and refuses allowlisted keys.
sshd_config is never touched.
"""
import argparse
import hashlib
import json
import os
import shutil
import socket
import stat
import sys
import time

from sshkeys import parse_key_line

EVIDENCE = "/root/ir"


def evidence_copy(path, root=EVIDENCE, now=None):
    stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime(now))
    directory = os.path.join(root, "%s-%s" % (socket.gethostname(), stamp))
    os.makedirs(directory, mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    name = path.strip("/").replace("/", "__")
    target = os.path.join(directory, name)
    shutil.copy2(path, target)
    with open(target, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    with open(os.path.join(directory, "SHA256SUMS"), "a") as handle:
        handle.write("%s  %s\n" % (digest, name))
    return target


def removable(path):
    return os.path.isabs(path) and (path == "/etc/ssh/sshrc" or (
        os.path.basename(path) == "rc" and os.path.basename(os.path.dirname(path)) == ".ssh"))


def remove_file(path, root=EVIDENCE):
    if not removable(path):
        raise ValueError("refusing to remove %s" % path)
    if not os.path.lexists(path):
        return {"path": path, "removed": False}  # already gone: declarative no-op
    if stat.S_ISREG(os.lstat(path).st_mode):
        evidence_copy(path, root)
    os.unlink(path)
    return {"path": path, "removed": True}


def remove_key(path, wanted, allow_keys=(), root=EVIDENCE):
    allowed = {parsed[0] for parsed in map(parse_key_line, allow_keys) if parsed}
    if wanted in allowed:
        raise ValueError("refusing to remove an allowlisted key")
    if not os.path.isabs(path) or os.path.islink(path):
        raise ValueError("refusing to edit %s" % path)
    with open(path, encoding="utf-8", errors="surrogateescape") as handle:
        lines = handle.read().splitlines(True)
    kept = [line for line in lines if (parse_key_line(line) or (None,))[0] != wanted]
    if len(kept) == len(lines):
        return {"file": path, "removed": 0}
    info = os.stat(path)
    evidence_copy(path, root)
    temporary = path + ".ccdc-tmp"
    with open(temporary, "w", encoding="utf-8", errors="surrogateescape") as handle:
        handle.writelines(kept)
    os.chown(temporary, info.st_uid, info.st_gid)
    os.chmod(temporary, stat.S_IMODE(info.st_mode))
    os.replace(temporary, path)
    return {"file": path, "removed": len(lines) - len(kept)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("remove-file").add_argument("path")
    key = sub.add_parser("remove-key")
    key.add_argument("path")
    key.add_argument("fingerprint")
    key.add_argument("--allow-key", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        result = (remove_file(args.path) if args.action == "remove-file"
                  else remove_key(args.path, args.fingerprint, args.allow_key))
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
