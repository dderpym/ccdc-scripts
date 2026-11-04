#!/usr/bin/env python3
"""Read-only sudoers audit: JSON {"findings": [...], "errors": [...]}.

Parses /etc/sudoers and everything it includes. Independent of the account running
the scan (no sud000-style suppression): the question is what the files grant others.
Flags user specs for everyone (ALL / %ALL) and NOPASSWD grants to anyone but the
account init creates. Init's own rule lives in /etc/sudoers.d/oski.
"""
import json
import os
import re

ALLOWED_USER = "oski"
MAX_DEPTH = 8
DIRECTIVE = re.compile(r"^[#@](include|includedir)\s+(\"?)(\S+?)\2\s*$")
NON_GRANT = ("Defaults", "User_Alias", "Runas_Alias", "Host_Alias", "Cmnd_Alias")
SPEC = re.compile(r"^(\S+(?:\s*,\s*\S+)*)\s+(\S.*=.*)$")


def logical_lines(text):
    """(line number, text) with backslash continuations joined."""
    pending, start = "", 0
    for number, line in enumerate(text.splitlines(), 1):
        if not pending:
            start = number
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        yield start, (pending + line).strip()
        pending = ""
    if pending:
        yield start, pending.strip()


def classify(line):
    """'world', 'nopasswd' or None for one logical line."""
    if not line or line.startswith(NON_GRANT):
        return None
    match = SPEC.match(line)
    if not match:
        return None
    users = {u.strip() for u in match[1].split(",")}
    if users & {"ALL", "%ALL"}:
        return "world"
    if "NOPASSWD" in match[2] and users != {ALLOWED_USER}:
        return "nopasswd"
    return None


def include_targets(directive, argument, read_dir=os.listdir):
    if directive == "include":
        return [argument]
    names = sorted(n for n in read_dir(argument) if "." not in n and not n.endswith("~"))
    return [os.path.join(argument, n) for n in names]


def audit(path, result, seen=None, depth=0, read=None, read_dir=os.listdir):
    read = read or (lambda p: open(p, encoding="utf-8", errors="replace").read())
    seen = set() if seen is None else seen
    if path in seen:
        return
    seen.add(path)
    if depth > MAX_DEPTH:
        result["errors"].append("include depth exceeded at " + path)
        return
    try:
        text = read(path)
    except OSError as exc:
        result["errors"].append("cannot read %s: %s" % (path, exc))
        return
    for number, line in logical_lines(text):
        directive = DIRECTIVE.match(line)
        if directive:
            try:
                targets = include_targets(directive[1], directive[3], read_dir)
            except OSError as exc:
                result["errors"].append("cannot list %s: %s" % (directive[3], exc))
                continue
            for target in targets:
                audit(target, result, seen, depth + 1, read, read_dir)
            continue
        if line.startswith("#"):
            continue
        kind = classify(line)
        if kind:
            result["findings"].append({"kind": kind, "file": path, "line": number, "text": line})


def main():
    result = {"findings": [], "errors": []}
    audit("/etc/sudoers", result)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
