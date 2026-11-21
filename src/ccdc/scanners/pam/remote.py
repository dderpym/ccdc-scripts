#!/usr/bin/env python3
"""PAM as it is ACTIVE on this host; prints {"findings": [...], "errors": [...]}.

libpam has no query interface, so the live checks are:
  * effective stacks   every service in /etc/pam.d is resolved the way libpam does (`@include`,
                       `include`, `substack` expanded in order), and the rules that really run are
                       judged per service. A hook in common-password is reported as running for
                       chpasswd/passwd/sudo..., not as "a line in a file".
  * mapped modules     /proc/*/maps: pam_*.so actually loaded into running processes that are
                       deleted, outside the system security dirs, or not owned by any package.
  * package integrity  dpkg --verify / rpm -V of the PAM packages, and unowned or backup files
                       next to the modules.
Finding kinds: pam-exec (pam_exec/pam_script in an effective stack), pam-foreign-module (module
path outside the security dirs in an effective stack), pam-mapped-module, pam-stray-file,
pam-module-modified. An include that cannot be resolved is an error, never a clean stack.
"""
import glob
import json
import os
import re
import subprocess
import sys

import pkgowner

PAM_DIR = "/etc/pam.d"
SECURITY_GLOBS = ("/lib/security", "/lib64/security", "/usr/lib/security", "/usr/lib64/security",
                  "/lib/*/security", "/usr/lib/*/security", "/usr/lib64/*/security")
EXEC_MODULES = ("pam_exec.so", "pam_script.so")
RULE = re.compile(r"^-?(?P<type>\w+)\s+(?P<control>\[[^\]]*\]|\S+)\s+(?P<module>\S+)\s*(?P<args>.*)$")
AT_INCLUDE = re.compile(r"^@include\s+(\S+)\s*$")
MAX_DEPTH = 16
MAPPED = re.compile(r"/(pam_[A-Za-z0-9_.+-]*\.so[0-9.]*)(?: \(deleted\))?$")


def parse_line(line):
    """(type, control, module, args) for a pam.d rule, else None (comments, @include, blanks)."""
    text = line.strip()
    if not text or text.startswith(("#", "@")):
        return None
    match = RULE.match(text)
    if not match:
        return None
    return match["type"], match["control"], match["module"], match["args"].split()


def security_dirs():
    return sorted({d for pattern in SECURITY_GLOBS for d in glob.glob(pattern) if os.path.isdir(d)})


def in_security_dir(module, dirs=None):
    dirs = security_dirs() if dirs is None else dirs
    return os.path.dirname(module).rstrip("/") in dirs


def read_service(directory, name):
    with open(os.path.join(directory, os.path.basename(name)), errors="replace") as handle:
        return handle.read().splitlines()


def effective(service, read, errors, kind=None, chain=(), depth=0):
    """Rules that run for `service`, in order: [(file, line_no, text, type, module, args)].

    `kind` restricts an `include`/`substack` expansion to the rules of that PAM type.
    """
    if service in chain or depth > MAX_DEPTH:
        errors.append("PAM include loop or depth exceeded at %s (%s)" % (service, " -> ".join(chain)))
        return []
    try:
        lines = read(service)
    except OSError as exc:
        errors.append("cannot read PAM service %s (included via %s): %s" % (service, " -> ".join(chain) or "-", exc))
        return []
    rules = []
    for number, text in enumerate(lines, 1):
        stripped = text.strip()
        at = AT_INCLUDE.match(stripped)
        if at:
            rules += effective(at[1], read, errors, kind, chain + (service,), depth + 1)
            continue
        parsed = parse_line(stripped)
        if parsed is None:
            continue
        rule_type, control, module, args = parsed
        if control in ("include", "substack"):
            if kind in (None, rule_type):
                rules += effective(module, read, errors, rule_type, chain + (service,), depth + 1)
            continue
        if kind in (None, rule_type):
            rules.append((service, number, text.rstrip("\n"), rule_type, module, args))
    return rules


def judge(rule, dirs):
    """The finding kind for one effective rule, or None."""
    _, _, _, _, module, _ = rule
    if os.path.basename(module) in EXEC_MODULES:
        return "pam-exec"
    if "/" in module and not in_security_dir(module, dirs):
        return "pam-foreign-module"
    return None


def stack_findings(directory, services, dirs, errors):
    """One finding per offending rule, listing every service in whose effective stack it runs."""
    cache = {}

    def read(name):
        if name not in cache:
            cache[name] = read_service(directory, name)
        return cache[name]

    grouped = {}
    for service in services:
        for rule in effective(service, read, errors):
            kind = judge(rule, dirs)
            if kind:
                grouped.setdefault((kind, rule[0], rule[1]), (rule, set()))[1].add(service)
    rows = []
    for (kind, file, number), (rule, runners) in sorted(grouped.items()):
        _, _, text, _, module, args = rule
        row = {"kind": kind, "file": os.path.join(directory, file), "line_no": number, "line": text,
               "module": module if kind == "pam-foreign-module" else os.path.basename(module),
               "services": sorted(runners)}
        if kind == "pam-exec":
            row["payload"] = next((a for a in args if a.startswith("/")), "")
            row["expose_authtok"] = "expose_authtok" in args
        rows.append(row)
    return rows


def _has(tool):
    return any(os.access(os.path.join(p, tool), os.X_OK) for p in os.environ.get("PATH", "").split(os.pathsep))


def owner_of(path, run=subprocess.run):
    """True owned, False unowned, None when no package database exists (any spelling of the path counts)."""
    return pkgowner.checker(run)(path)


def mapped_modules(proc="/proc", dirs=None, owner=owner_of):
    """pam_*.so loaded into running processes that are deleted, outside the security dirs, or unowned."""
    real_dirs = {os.path.realpath(d) for d in (security_dirs() if dirs is None else dirs)}
    seen, unreadable = {}, 0
    for entry in os.listdir(proc):
        if not entry.isdigit():
            continue
        try:
            with open(os.path.join(proc, entry, "maps"), errors="replace") as handle:
                lines = handle.read().splitlines()
        except FileNotFoundError:
            continue  # the process exited
        except OSError:
            unreadable += 1
            continue
        for line in lines:
            match = MAPPED.search(line)
            if match:
                path = line.split(None, 5)[5].replace(" (deleted)", "")
                seen.setdefault((path, line.endswith("(deleted)")), []).append(int(entry))
    rows = []
    for (path, deleted), pids in sorted(seen.items()):
        if deleted:
            reason = "mapped from a deleted file"
        elif os.path.dirname(os.path.realpath(path)) not in real_dirs:
            reason = "outside the system security dirs"
        elif owner(path) is False:
            reason = "not owned by any package"
        else:
            continue
        rows.append({"kind": "pam-mapped-module", "path": path, "pids": sorted(set(pids))[:5], "reason": reason})
    return rows, unreadable


def stray_files(dirs, owner=owner_of):
    findings = []
    for directory in dirs:
        for name in sorted(os.listdir(directory)):
            path = os.path.join(directory, name)
            if not os.path.isfile(path):
                continue
            if name.endswith((".bak", ".orig", ".old", "~")):
                findings.append({"kind": "pam-stray-file", "path": path, "reason": "backup copy next to modules"})
            elif (name.endswith(".so") or ".so." in name) and owner(path) is False:
                findings.append({"kind": "pam-stray-file", "path": path, "reason": "unowned module"})
    return findings


def verify_modules(run=subprocess.run):
    """Explicit owned-file verification of the PAM packages (dpkg --verify / rpm -V)."""
    findings = []
    commands = []
    if _has("dpkg"):
        commands.append((["dpkg", "--verify", "libpam-modules", "libpam-modules-bin", "libpam-runtime"], "dpkg"))
    if _has("rpm"):
        commands.append((["rpm", "-V", "pam"], "rpm"))
    for argv, tool in commands:
        result = run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        for line in result.stdout.splitlines():
            fields = line.split()
            path = fields[-1] if fields else ""
            if path.startswith("/") and "security/" in path and ".so" in path:
                findings.append({"kind": "pam-module-modified", "path": path, "detail": line.strip(), "tool": tool})
    return findings


def scan(pam_dir=PAM_DIR, dirs=None, proc="/proc"):
    result = {"findings": [], "errors": []}
    dirs = security_dirs() if dirs is None else dirs
    try:
        services = sorted(n for n in os.listdir(pam_dir)
                          if not n.endswith(("~", ".bak")) and os.path.isfile(os.path.join(pam_dir, n)))
    except OSError as exc:
        result["errors"].append("cannot read %s: %s" % (pam_dir, exc))
        services = []
    result["findings"].extend(stack_findings(pam_dir, services, dirs, result["errors"]))
    try:
        rows, unreadable = mapped_modules(proc, dirs)
        result["findings"].extend(rows)
        if unreadable:
            result["errors"].append("%d process map(s) unreadable (run as root); loaded PAM modules not fully checked"
                                    % unreadable)
        result["findings"].extend(stray_files(dirs))
        result["findings"].extend(verify_modules())
    except OSError as exc:
        result["errors"].append(str(exc))
    if not (_has("dpkg") or _has("rpm")):
        result["errors"].append("no dpkg or rpm: module ownership and integrity not verified")
    result["errors"] = list(dict.fromkeys(result["errors"]))
    return result


def main():
    print(json.dumps(scan(), sort_keys=True))


if __name__ == "__main__":
    sys.exit(main())
