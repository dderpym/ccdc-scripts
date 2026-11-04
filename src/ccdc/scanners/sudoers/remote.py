#!/usr/bin/env python3
"""Sudo as it is ACTIVE on this host: JSON {"findings": [...], "errors": [...]}.

No sudoers file is parsed here. Everything comes from live tooling:
  * `visudo -c`            whether the loaded configuration is valid at all
  * `sudo -n -l -U USER`   what sudo really grants each login-capable account, root and
                           `nobody` (a canary: any grant to it came from an ALL/%ALL rule),
                           from every source sudo consults (files, includes, group grants,
                           sssd/LDAP, Defaults !authenticate)
  * `sudo -n -l -l -U`     for flagged users only, the "Sudoers entry: FILE:LINE" that sudo
                           reports for each rule (newer sudo), so a fix can find the line
Independent of the account running the scan. Root's own rule is expected; `oski` is the
team account init creates. A sudo that cannot be queried is an error, never "no grants".
"""
import json
import pwd
import re
import subprocess

ALLOWED_USER = "oski"
CANARY = "nobody"
NO_LOGIN = ("nologin", "false")
RULE = re.compile(r"^\s*\(([^)]*)\)\s*(.*)$")
ENTRY = re.compile(r"^\s*Sudoers entry:\s*(\S+?)(?::(\d+))?\s*$")


def candidate_users(entries):
    """Login-capable accounts (uid >= 1000), root and the canary, in stable order."""
    names = {"root", CANARY}
    for entry in entries:
        shell = entry.pw_shell.rsplit("/", 1)[-1]
        if entry.pw_uid >= 1000 and entry.pw_uid != 65534 and entry.pw_shell and shell not in NO_LOGIN:
            names.add(entry.pw_name)
    return sorted(names)


def parse(output):
    """Rules from `sudo -l` output: [{"rule", "nopasswd", "all"}]; Defaults !authenticate applies to all."""
    rules, in_rules, no_auth = [], False, False
    for line in output.splitlines():
        if "may run the following commands" in line:
            in_rules = True
            continue
        if not in_rules:
            no_auth = no_auth or bool(re.search(r"(^|[\s,])!authenticate\b", line))
            continue
        match = RULE.match(line)
        if not match:
            continue
        commands = match[2]
        tags = re.findall(r"\b([A-Z_]+):", commands)
        stripped = re.sub(r"\b[A-Z_]+:\s*", "", commands)
        # Only the bare token ALL is a blanket grant; "!ALL" is a denial.
        everything = "ALL" in [part.strip() for part in stripped.split(",")]
        rules.append({"rule": line.strip(), "nopasswd": "NOPASSWD" in tags, "all": everything})
    for rule in rules:
        rule["nopasswd"] = rule["nopasswd"] or no_auth
    return rules


def parse_sources(output):
    """[(file, line)] per rule, in order, from `sudo -l -l`; empty when this sudo does not say."""
    return [(m[1], int(m[2] or 0)) for m in map(ENTRY.match, output.splitlines()) if m]


def flagged(user, rules):
    if user in (ALLOWED_USER, "root"):
        return []
    return [rule for rule in rules if rule["all"] or rule["nopasswd"]]


def query(argv, run):
    return run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)


def inspect(user, run=subprocess.run):
    """(rules, error) for one account; a failed sudo -l is an error, never 'no grants'."""
    try:
        result = query(["sudo", "-n", "-l", "-U", user], run)
    except (OSError, subprocess.SubprocessError) as exc:
        return [], "sudo -l -U %s failed: %s" % (user, exc)
    if re.search(r"is not allowed to run sudo", result.stdout):
        return [], None
    if result.returncode:
        return [], "sudo -l -U %s exited %s: %s" % (user, result.returncode, (result.stderr or result.stdout).strip()[:200])
    return parse(result.stdout), None


def locate(user, rules, run=subprocess.run):
    """Attach the sudoers file:line sudo reports for each rule, when it reports them."""
    try:
        sources = parse_sources(query(["sudo", "-n", "-l", "-l", "-U", user], run).stdout)
    except (OSError, subprocess.SubprocessError):
        sources = []
    for index, rule in enumerate(rules):
        rule["file"], rule["line"] = sources[index] if len(sources) == len(rules) else ("", 0)
    return rules


def validity(run=subprocess.run):
    """A finding row if `visudo -c` rejects the active configuration, plus an error if it cannot run."""
    try:
        result = query(["visudo", "-c"], run)
    except (OSError, subprocess.SubprocessError) as exc:
        return [], ["visudo -c failed to run: %s" % exc]
    if result.returncode:
        return [{"kind": "invalid", "detail": (result.stdout + result.stderr).strip()[:500]}], []
    return [], []


def scan(entries=None, run=subprocess.run):
    result = {"findings": [], "errors": []}
    rows, errors = validity(run)
    result["findings"].extend(rows)
    result["errors"].extend(errors)
    for user in candidate_users(pwd.getpwall() if entries is None else entries):
        rules, error = inspect(user, run)
        if error:
            result["errors"].append(error)
            continue
        hits = flagged(user, rules)
        if hits:
            locate(user, rules, run)
        for rule in rules:
            if rule in hits:
                result["findings"].append({"kind": "world" if user == CANARY else "grant", "user": user, **rule})
    return result


def main():
    print(json.dumps(scan(), sort_keys=True))


if __name__ == "__main__":
    main()
