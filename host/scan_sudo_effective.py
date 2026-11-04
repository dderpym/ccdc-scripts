#!/usr/bin/env python3
"""Effective sudo grants as sudo itself resolves them: JSON {"findings": [...], "errors": [...]}.

Asks `sudo -n -l -U USER` (run as root) for every login-capable local account, root,
and `nobody` as a canary: a grant for `nobody` can only come from ALL/%ALL-style rules.
This sees every source sudo consults (sudoers files, includes, group grants, sssd/LDAP,
Defaults !authenticate) that the file parser in scan_sudoers cannot. Root's own
unrestricted rule is expected and not reported. Independent of the account running the scan.
"""
import json
import pwd
import re
import subprocess

ALLOWED_USER = "oski"
CANARY = "nobody"
NO_LOGIN = ("nologin", "false")
RULE = re.compile(r"^\s*\(([^)]*)\)\s*(.*)$")


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


def flagged(user, rules):
    if user in (ALLOWED_USER, "root"):
        return []
    return [rule for rule in rules if rule["all"] or rule["nopasswd"]]


def inspect(user, run=subprocess.run):
    """(rules, error) for one account; a failed sudo -l is an error, never 'no grants'."""
    try:
        result = run(["sudo", "-n", "-l", "-U", user], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                     text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return [], "sudo -l -U %s failed: %s" % (user, exc)
    if re.search(r"is not allowed to run sudo", result.stdout):
        return [], None
    if result.returncode:
        return [], "sudo -l -U %s exited %s: %s" % (user, result.returncode, (result.stderr or result.stdout).strip()[:200])
    return parse(result.stdout), None


def scan(entries=None, run=subprocess.run):
    result = {"findings": [], "errors": []}
    for user in candidate_users(pwd.getpwall() if entries is None else entries):
        rules, error = inspect(user, run)
        if error:
            result["errors"].append(error)
            continue
        for rule in flagged(user, rules):
            result["findings"].append({"user": user, **rule})
    return result


def main():
    print(json.dumps(scan(), sort_keys=True))


if __name__ == "__main__":
    main()
