#!/usr/bin/env python3
"""Read-only PAM audit; prints {"findings": [...], "errors": [...]}.

Finding kinds: pam-exec (pam_exec/pam_script line), pam-foreign-module (module path outside
the system security dirs), pam-stray-file (unowned module or *.bak in a security dir),
pam-module-modified (package verification of a PAM module failed).
"""
import glob
import json
import os
import re
import subprocess
import sys

PAM_DIR = "/etc/pam.d"
SECURITY_GLOBS = ("/lib/security", "/lib64/security", "/usr/lib/security", "/usr/lib64/security",
                  "/lib/*/security", "/usr/lib/*/security", "/usr/lib64/*/security")
EXEC_MODULES = ("pam_exec.so", "pam_script.so")
RULE = re.compile(r"^-?(?P<type>\w+)\s+(?P<control>\[[^\]]*\]|\S+)\s+(?P<module>\S+)\s*(?P<args>.*)$")


def parse_line(line):
    """(type, control, module, args) for a pam.d rule, else None (comments, @include, blanks)."""
    text = line.strip()
    if not text or text.startswith(("#", "@")):
        return None
    match = RULE.match(text)
    if not match:
        return None
    return match["type"], match["control"], match["module"], match["args"].split()


def in_security_dir(module):
    return any(os.path.dirname(module).rstrip("/") == d for d in security_dirs())


def audit_rules(name, lines, is_system_module=in_security_dir):
    findings = []
    for number, line in enumerate(lines, 1):
        rule = parse_line(line)
        if rule is None:
            continue
        _, _, module, args = rule
        base = os.path.basename(module)
        if base in EXEC_MODULES:
            payload = next((a for a in args if a.startswith("/")), "")
            findings.append({"kind": "pam-exec", "file": name, "line_no": number, "line": line.rstrip("\n"),
                             "module": base, "payload": payload, "expose_authtok": "expose_authtok" in args})
        elif module.startswith("/") and not is_system_module(module):
            findings.append({"kind": "pam-foreign-module", "file": name, "line_no": number,
                             "line": line.rstrip("\n"), "module": module})
    return findings


def security_dirs():
    return sorted({d for pattern in SECURITY_GLOBS for d in glob.glob(pattern) if os.path.isdir(d)})


def _has(tool):
    return any(os.access(os.path.join(p, tool), os.X_OK) for p in os.environ.get("PATH", "").split(os.pathsep))


def owner_of(path, run=subprocess.run):
    """True owned, False unowned, None when no package database exists. Tries path and realpath (usrmerge)."""
    tools = [t for t in (("dpkg", "-S"), ("rpm", "-qf")) if _has(t[0])]
    if not tools:
        return None
    for candidate in dict.fromkeys((path, os.path.realpath(path))):
        for tool, flag in tools:
            result = run([tool, flag, candidate], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            if result.returncode == 0:
                return True
    return False


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


def scan(pam_dir=PAM_DIR, dirs=None):
    result = {"findings": [], "errors": []}
    try:
        names = sorted(os.listdir(pam_dir))
    except OSError as exc:
        result["errors"].append("cannot read %s: %s" % (pam_dir, exc))
        names = []
    for name in names:
        path = os.path.join(pam_dir, name)
        if name.endswith((".bak", "~")) or not os.path.isfile(path):
            continue
        try:
            with open(path, errors="replace") as handle:
                result["findings"].extend(audit_rules(path, handle.read().splitlines(True)))
        except OSError as exc:
            result["errors"].append("cannot read %s: %s" % (path, exc))
    try:
        result["findings"].extend(stray_files(security_dirs() if dirs is None else dirs))
        result["findings"].extend(verify_modules())
    except OSError as exc:
        result["errors"].append(str(exc))
    if not (_has("dpkg") or _has("rpm")):
        result["errors"].append("no dpkg or rpm: module ownership and integrity not verified")
    return result


def main():
    print(json.dumps(scan(), sort_keys=True))


if __name__ == "__main__":
    sys.exit(main())
