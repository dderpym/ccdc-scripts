#!/usr/bin/env python3
"""fix_sudoers FILE TEXT | --locate USER RULE --file F --line N: delete grant lines, validated with visudo.

--locate takes what the live scan reported (the `sudo -l` rule text for USER and, when sudo
says, the FILE:LINE it came from), finds the matching line(s) in the files `visudo -c` reports
as active, and removes them with the same validated procedure. No match is an error.

Order: visudo -c must pass; the original goes to /root/ir/sudoers-<ts>/ (0700);
the edit is checked with visudo -cf before and visudo -c after replacing; any
failure restores the original bytes. Matching on text, not line number, so a
file that changed since the scan is never edited blindly.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time

EVIDENCE = "/root/ir"


def find_visudo():
    return shutil.which("visudo") or next(
        (p for p in ("/usr/sbin/visudo", "/sbin/visudo") if os.access(p, os.X_OK)), None)


def allowed(path):
    real = os.path.realpath(path)
    return (not os.path.islink(path)
            and (real == "/etc/sudoers" or os.path.dirname(real) == "/etc/sudoers.d"))


def valid(visudo, *extra, run=subprocess.run):
    return run([visudo, "-c", *extra], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def write_like(path, data, info):
    with open(path, "wb") as handle:
        handle.write(data)
    os.chmod(path, info.st_mode & 0o7777)
    os.chown(path, info.st_uid, info.st_gid)


def fix(path, text, evidence=EVIDENCE, run=subprocess.run, visudo=None):
    visudo = visudo or find_visudo()
    if not visudo:
        raise RuntimeError("visudo not found")
    if not allowed(path):
        raise ValueError("not a sudoers file: " + path)
    if not valid(visudo, run=run):
        raise RuntimeError("sudoers is already invalid; refusing to edit")
    with open(path, "rb") as handle:
        original = handle.read()
    info = os.stat(path)
    lines = original.decode("utf-8", "replace").splitlines(keepends=True)
    kept = [line for line in lines if line.strip() != text.strip()]
    removed = len(lines) - len(kept)
    if not removed:
        return {"path": path, "removed": 0}
    directory = os.path.join(evidence, "sudoers-%d" % time.time())
    os.makedirs(directory, mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    with open(os.path.join(directory, os.path.basename(path)), "wb") as handle:
        handle.write(original)
    temporary = path + ".ccdc-new"
    try:
        write_like(temporary, "".join(kept).encode(), info)
        if not valid(visudo, "-f", temporary, run=run):
            raise RuntimeError("edited file failed visudo; original untouched")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    if not valid(visudo, run=run):
        try:
            write_like(temporary, original, info)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        raise RuntimeError("sudoers invalid after edit; original restored")
    return {"path": path, "removed": removed, "evidence": directory}


SPEC = re.compile(r"^(.*?)\s+([^\s=]+)\s*=\s*(.*)$")
NON_GRANT = ("Defaults", "User_Alias", "Runas_Alias", "Host_Alias", "Cmnd_Alias")


def active_files(visudo, run=subprocess.run):
    """Files `visudo -c` says it parsed: the configuration sudo actually loads."""
    out = run([visudo, "-c"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).stdout
    return [m[1] for m in (re.match(r"^(\S+): parsed OK$", line) for line in out.splitlines()) if m]


def user_groups(user, run=subprocess.run):
    out = run(["id", "-Gn", user], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).stdout
    return set(out.split())


def squash(text):
    return re.sub(r"\s+", "", text)


def grant_matches(line, user, groups, rule):
    """Does this sudoers line grant `rule` (as `sudo -l` prints it) to the user, their groups, or everyone?"""
    line = line.strip()
    spec = None if not line or line.startswith(("#",) + NON_GRANT) else SPEC.match(line)
    if not spec:
        return False
    who = {w.strip() for w in spec[1].split(",")}
    if not (who & {user, "ALL", "%ALL"} or any(w.startswith("%") and w[1:] in groups for w in who)):
        return False
    tail = spec[3] if spec[3].lstrip().startswith("(") else "(root) " + spec[3]
    return squash(tail) == squash(rule)


def read_lines(path):
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read().splitlines()


def locate(user, rule, path="", number=0, visudo=None, run=subprocess.run, read=None):
    """[(file, line text)] of grant lines for `rule`; the reported FILE:LINE is tried first."""
    visudo = visudo or find_visudo()
    if not visudo:
        raise RuntimeError("visudo not found")
    read = read or read_lines
    groups = user_groups(user, run)
    found = []
    for name in [path] if path else active_files(visudo, run):
        lines = read(name)
        if number and 0 < number <= len(lines) and path and grant_matches(lines[number - 1], user, groups, rule):
            found.append((name, lines[number - 1]))
        else:
            found.extend((name, line) for line in lines if grant_matches(line, user, groups, rule))
    return found


def fix_located(user, rule, path="", number=0, read=None, **options):
    found = locate(user, rule, path, number, options.get("visudo"), options.get("run", subprocess.run), read)
    if not found:
        raise RuntimeError("no active sudoers line grants %r to %s; nothing changed" % (rule, user))
    return [fix(name, text, **options) for name, text in found]


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["--locate"]:
        if len(argv) != 7 or argv[3] != "--file" or argv[5] != "--line":
            print("usage: fix_sudoers --locate USER RULE --file F --line N", file=sys.stderr)
            return 2
        action = lambda: fix_located(argv[1], argv[2], argv[4], int(argv[6] or 0))  # noqa: E731
    elif len(argv) == 2:
        action = lambda: fix(*argv)  # noqa: E731
    else:
        print("usage: fix_sudoers FILE TEXT | --locate USER RULE --file F --line N", file=sys.stderr)
        return 2
    try:
        print(json.dumps(action()))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
