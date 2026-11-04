#!/usr/bin/env python3
"""PAM repairs. Every action backs up first and prints JSON.

  fix_pam remove-line FILE LINE [--payload PATH]  delete rules equal to LINE (stripped) from a /etc/pam.d file,
                                                  and the payload file
  fix_pam remove-files [--limit N] PATH...        quarantine stray files under /etc/pam.d or a security dir.
                                                  Re-checked here, not trusted from the scan: a file a package
                                                  owns (any usrmerge spelling), or one whose ownership cannot be
                                                  established, is never touched; more than N (default 5) files in
                                                  one run is refused outright.

SAFETY: keep a second root SSH session open while repairing PAM and test a fresh login after.
Backups go to /root/ir/pam-<timestamp>/ (0700).
"""
import glob
import json
import os
import shutil
import subprocess
import sys
import time

import pkgowner

PAM_DIR = "/etc/pam.d"
EVIDENCE = "/root/ir"
MAX_REMOVE = 5
SECURITY_GLOBS = ("/lib*/security", "/usr/lib*/security", "/lib/*/security", "/usr/lib/*/security")


def evidence_dir(base=EVIDENCE, now=time.time):
    path = os.path.join(base, "pam-%d" % now())
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def backup(path, directory):
    if os.path.lexists(path):
        shutil.copy2(path, os.path.join(directory, path.strip("/").replace("/", "_")), follow_symlinks=False)


def remove_line(path, line, payload="", pam_dir=PAM_DIR, base=EVIDENCE):
    if os.path.dirname(os.path.realpath(path)) != os.path.realpath(pam_dir):
        raise ValueError("not a pam.d file: " + path)
    with open(path) as handle:
        lines = handle.read().splitlines(True)
    kept = [l for l in lines if l.strip() != line.strip()]
    if len(kept) == len(lines):
        return {"removed": 0, "payload": False}  # already clean: declarative no-op
    directory = evidence_dir(base)
    backup(path, directory)
    mode = os.stat(path).st_mode & 0o7777
    temporary = path + ".ccdc-tmp"
    with open(temporary, "w") as handle:
        handle.writelines(kept)
    os.chmod(temporary, mode)
    os.replace(temporary, path)
    removed_payload = False
    if payload and os.path.isabs(payload) and os.path.isfile(payload) and not os.path.islink(payload):
        backup(payload, directory)
        os.unlink(payload)
        removed_payload = True
    return {"removed": len(lines) - len(kept), "payload": removed_payload, "evidence": directory}


def allowed_dirs(pam_dir=PAM_DIR, globs=SECURITY_GLOBS):
    found = {os.path.realpath(pam_dir)}
    for pattern in globs:
        found.update(os.path.realpath(d) for d in glob.glob(pattern))
    return found


def remove_files(paths, limit=MAX_REMOVE, owned=None, base=EVIDENCE, dirs=None):
    """Quarantine stray files. Every guard is re-evaluated here, right before acting."""
    owned = pkgowner.checker() if owned is None else owned
    dirs = allowed_dirs() if dirs is None else dirs
    plan, skipped = [], []
    for path in dict.fromkeys(paths):
        if not os.path.isabs(path):
            skipped.append({"path": path, "why": "not an absolute path"})
        elif os.path.dirname(os.path.realpath(path)) not in dirs:
            skipped.append({"path": path, "why": "outside the PAM directories"})
        elif os.path.islink(path) or not os.path.isfile(path):
            continue  # already gone: declarative no-op
        else:
            verdict = owned(path)
            if verdict is True:
                skipped.append({"path": path, "why": "owned by a package"})
            elif verdict is None:
                skipped.append({"path": path, "why": "no package database: cannot prove it is unowned"})
            else:
                plan.append(path)
    if len(plan) > limit:
        raise ValueError("refusing to remove %d files in one run (limit %d); review them or raise pam_remove_limit"
                         % (len(plan), limit))
    removed, directory = [], None
    for path in plan:
        directory = directory or evidence_dir(base)
        backup(path, directory)
        os.unlink(path)
        removed.append(path)
    return {"removed": removed, "skipped": skipped, "evidence": directory}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        action = argv[0]
        if action == "remove-line":
            payload = argv[argv.index("--payload") + 1] if "--payload" in argv else ""
            result = remove_line(argv[1], argv[2], payload)
        elif action == "remove-files":
            rest = argv[1:]
            limit = MAX_REMOVE
            if rest[:1] == ["--limit"]:
                limit, rest = int(rest[1]), rest[2:]
            result = remove_files(rest, limit)
        else:
            raise ValueError("unknown action " + action)
    except (OSError, ValueError, IndexError, subprocess.CalledProcessError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
