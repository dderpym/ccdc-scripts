#!/usr/bin/env python3
"""scan_ssh_vectors [--allow-key LINE]... [--allow OPTION=VALUE]... [--allow-path PATH]...

Read-only. Prints {"findings": [row...], "errors": [...]}; rows have a "kind":
  sshd-option      option, value, severity, why
  authorized-key   file, user, line, fingerprint, comment      (key not in the allowlist)
  ssh-startup      path, what                                  (sshrc, ~/.ssh/rc)
  unowned-ssh-file path                                        (not package-owned, under /etc/ssh)
sshd settings come from `sshd -T` of the RUNNING daemon (resolved via /proc), so a
relocated sshd (e.g. /usr/local/sbin/sshd) is still the one inspected.
"""
import argparse
import base64
import binascii
import hashlib
import json
import os
import pwd
import re
import shutil
import subprocess
import sys

DEFAULT_KEY_FILES = {".ssh/authorized_keys", ".ssh/authorized_keys2"}
KEY_TYPE = re.compile(r"^(ssh-[a-z0-9]+|ecdsa-sha2-nistp\d+|sk-[a-z0-9@.-]+)$")
KNOWN_ETC_SSH = re.compile(r"^(ssh_config|sshd_config|moduli|ssh_known_hosts2?|ssh_import_id|"
                           r"ssh_host_[a-z0-9_]+_key(\.pub)?|ssh_config\.d|sshd_config\.d|"
                           r"sshd_config\.rpmnew|sshd_config\.dpkg-\w+|ssh_config\.dpkg-\w+)$")


def fingerprint(blob):
    raw = base64.b64decode(blob, validate=True)
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def parse_key_line(line):
    """(fingerprint, comment) for an authorized_keys/.pub line, else None. Options may precede the key."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    tokens = line.split()
    for index, token in enumerate(tokens[:-1]):
        if KEY_TYPE.match(token):
            try:
                return fingerprint(tokens[index + 1]), " ".join(tokens[index + 2:])
            except (binascii.Error, ValueError):
                return None
    return None


def running_sshd(proc="/proc"):
    """Executable of the listening sshd: comm 'sshd' whose parent is init."""
    try:
        pids = sorted(int(p) for p in os.listdir(proc) if p.isdigit())
    except OSError:
        pids = []
    for pid in pids:
        try:
            with open("%s/%d/comm" % (proc, pid)) as handle:
                if handle.read().strip() != "sshd":
                    continue
            with open("%s/%d/stat" % (proc, pid)) as handle:
                ppid = int(handle.read().rpartition(")")[2].split()[1])
            if ppid != 1:
                continue
            return os.readlink("%s/%d/exe" % (proc, pid)).replace(" (deleted)", "")
        except (OSError, ValueError, IndexError):
            continue
    return None


def sshd_binary():
    path = running_sshd()
    if path and os.access(path, os.X_OK):
        return path
    for candidate in ("/usr/sbin/sshd", "/usr/local/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd", shutil.which("sshd")):
        if candidate and os.access(candidate, os.X_OK):
            return candidate
    raise RuntimeError("cannot find sshd")


def parse_effective(output):
    result = {}
    for line in output.splitlines():
        key, _, value = line.partition(" ")
        if key:
            result.setdefault(key.lower(), []).append(value.strip())
    return result


def option_rows(effective, allow=()):
    """Rule-based sshd findings, independent of any saved baseline. allow: set of 'option=value'."""
    rows = []

    def add(option, value, severity, why):
        if "%s=%s" % (option, value) not in allow:
            rows.append({"kind": "sshd-option", "option": option, "value": value, "severity": severity, "why": why})

    for value in effective.get("authorizedkeysfile", []):
        for item in value.split():
            if item.lower() != "none" and item not in DEFAULT_KEY_FILES:
                add("authorizedkeysfile", item, "critical", "keys accepted from a non-standard location")
    for option in ("authorizedkeyscommand", "authorizedprincipalscommand", "trustedusercakeys", "authorizedprincipalsfile"):
        for value in effective.get(option, []):
            if value.lower() != "none":
                add(option, value, "warning", "alternate authentication source; allowlist it if the team set it up")
    for value in effective.get("banner", []):
        if value.lower() != "none":
            add("banner", value, "warning", "banner configured; proves sshd_config was edited")
    for value in effective.get("permitrootlogin", []):
        if value.lower() != "no":
            add("permitrootlogin", value, "critical", "root may log in over SSH")
    for value in effective.get("permituserenvironment", []):
        if value.lower() != "no":
            add("permituserenvironment", value, "critical", "users can set environment (LD_PRELOAD) for sshd sessions")
    return rows


def expand(pattern, home, user):
    """AuthorizedKeysFile tokens: %h home, %u user, %% percent; relative paths are under the home."""
    path = re.sub(r"%([hu%])", lambda m: {"h": home, "u": user, "%": "%"}[m[1]], pattern)
    return path if os.path.isabs(path) else os.path.join(home, path)


def key_files(effective, people):
    """{file: user} for every candidate authorized-keys file."""
    patterns = {item for value in effective.get("authorizedkeysfile", []) for item in value.split()
                if item.lower() != "none"} | DEFAULT_KEY_FILES
    files = {}
    for user, home in people:
        for pattern in sorted(patterns):
            files.setdefault(expand(pattern, home, user), user)
    return files


def key_rows(files, allowed, read=None):
    rows, errors = [], []
    read = read or (lambda path: open(path, encoding="utf-8", errors="replace").read())
    for path, user in sorted(files.items()):
        try:
            text = read(path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            errors.append("cannot read %s: %s" % (path, exc))
            continue
        for number, line in enumerate(text.splitlines(), 1):
            parsed = parse_key_line(line)
            if parsed and parsed[0] not in allowed:
                rows.append({"kind": "authorized-key", "file": path, "user": user, "line": number,
                             "fingerprint": parsed[0], "comment": parsed[1]})
    return rows, errors


def startup_rows(people, exists=os.path.lexists):
    rows = []
    candidates = [("/etc/ssh/sshrc", "system sshrc")]
    candidates += [(os.path.join(home, ".ssh", "rc"), "user ssh rc") for _, home in people]
    for path, what in dict.fromkeys(candidates):
        if exists(path):
            rows.append({"kind": "ssh-startup", "path": path, "what": what})
    return rows


def owned(path, run=subprocess.run):
    """True/False when a package database can answer, None when none is available. Tries path and realpath."""
    tools = [argv for argv in (["dpkg", "-S"], ["rpm", "-qf"]) if shutil.which(argv[0])]
    if not tools:
        return None
    for candidate in dict.fromkeys((path, os.path.realpath(path))):
        for argv in tools:
            if run([*argv, candidate], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                return True
    return False


def unowned_rows(allow_paths=(), directory="/etc/ssh", owner=owned):
    rows, errors = [], []
    try:
        names = sorted(os.listdir(directory))
    except OSError as exc:
        return rows, ["cannot list %s: %s" % (directory, exc)]
    for name in names:
        path = os.path.join(directory, name)
        if path in allow_paths or name == "sshrc":  # sshrc is reported as a startup script
            continue
        # Hidden entries (/etc/ssh/.ssh) are never part of a package; others need an owner.
        if name.startswith("."):
            rows.append({"kind": "unowned-ssh-file", "path": path})
        elif not KNOWN_ETC_SSH.match(name):
            verdict = owner(path)
            if verdict is None:
                errors.append("no package database; cannot tell whether %s is owned" % path)
            elif not verdict:
                rows.append({"kind": "unowned-ssh-file", "path": path})
    return rows, sorted(set(errors))


def accounts():
    return sorted({(entry.pw_name, entry.pw_dir) for entry in pwd.getpwall() if entry.pw_dir.startswith("/")})


def scan(allow_keys=(), allow_options=(), allow_paths=()):
    rows, errors = [], []
    allowed = {parsed[0] for parsed in map(parse_key_line, allow_keys) if parsed}
    if not allowed:
        errors.append("no key allowlist supplied; every authorized key is reported")
    people = accounts()
    try:
        output = subprocess.run([sshd_binary(), "-T"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True, timeout=30)
        if output.returncode:
            raise RuntimeError(output.stderr.strip() or "sshd -T failed")
        effective = parse_effective(output.stdout)
        rows += option_rows(effective, set(allow_options))
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        errors.append("sshd settings unavailable: %s" % exc)
        effective = {}
    found, problems = key_rows(key_files(effective, people), allowed)
    rows += found
    errors += problems
    rows += startup_rows(people)
    found, problems = unowned_rows(set(allow_paths))
    rows += found
    errors += problems
    skip = set(allow_paths)
    rows = [row for row in rows if row.get("path", row.get("file")) not in skip]
    return {"findings": rows, "errors": errors}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-key", action="append", default=[])
    parser.add_argument("--allow", action="append", default=[])
    parser.add_argument("--allow-path", action="append", default=[])
    args = parser.parse_args(argv)
    print(json.dumps(scan(args.allow_key, args.allow, args.allow_path), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
