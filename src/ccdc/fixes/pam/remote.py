#!/usr/bin/env python3
"""PAM repairs. Every action backs up first and prints JSON.

  fix_pam remove-line FILE LINE [--payload PATH]  delete rules equal to LINE (stripped) from a /etc/pam.d file,
                                                  and the payload file
  fix_pam remove-file PATH                        quarantine a stray file under /etc/pam.d or a security dir

SAFETY: keep a second root SSH session open while repairing PAM and test a fresh login after.
Backups go to /root/ir/pam-<timestamp>/ (0700).
"""
import json
import os
import shutil
import subprocess
import sys
import time

PAM_DIR = "/etc/pam.d"
EVIDENCE = "/root/ir"


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


def remove_file(path, base=EVIDENCE):
    if not os.path.isabs(path) or os.path.islink(path) or not os.path.isfile(path):
        return {"removed": False}
    directory = evidence_dir(base)
    backup(path, directory)
    os.unlink(path)
    return {"removed": True, "evidence": directory}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        action = argv[0]
        if action == "remove-line":
            payload = argv[argv.index("--payload") + 1] if "--payload" in argv else ""
            result = remove_line(argv[1], argv[2], payload)
        elif action == "remove-file":
            result = remove_file(argv[1])
        else:
            raise ValueError("unknown action " + action)
    except (OSError, ValueError, IndexError, subprocess.CalledProcessError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
