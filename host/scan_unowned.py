#!/usr/bin/env python3
"""scan_unowned [--allowlist FILE]: files in system dirs that no package owns. Read-only.

Package verification only checks files a package owns, so red-team additions are
invisible to it. Ownership is tested on the path AND its realpath (usrmerge: dpkg
lists /usr/lib/... on one release and /lib/... on another).
Prints {"findings": [rows], "errors": [...]}; row kinds: unowned-exec, timestomped,
unit-runs-unowned, unowned-unit, unit-missing-binary.
"""
import argparse
import fnmatch
import glob
import json
import os
import re
import shutil
import subprocess
import sys

DIRS = ["/usr/bin", "/usr/sbin", "/usr/libexec", "/usr/local/bin", "/usr/local/sbin", "/usr/local/libexec",
        "/bin", "/sbin", "/opt/*/bin", "/lib*/security", "/usr/lib*/security", "/etc/ssh", "/etc/sudoers.d",
        "/etc/cron.d"]
MAX_ROWS = 100
SKEW = 86400


def expand(patterns):
    return sorted({p for pattern in patterns for p in glob.glob(pattern)})


def list_files(directories, walk=os.walk):
    """Every file under the (glob) directories, each real directory visited once (usrmerge symlinks)."""
    seen = set()
    for directory in expand(directories):
        real = os.path.realpath(directory)
        if real in seen:
            continue
        seen.add(real)
        for base, _, names in walk(directory):
            for name in names:
                yield os.path.join(base, name)


def candidates(path, root="/"):
    """Path, its realpath, and the usrmerge alias (/usr/lib/x <-> /lib/x) when /lib is a symlink into /usr."""
    forms = {path, os.path.realpath(path)}
    usr = os.path.join(root, "usr")
    for form in list(forms):
        if form.startswith(usr + "/"):
            relative = form[len(usr) + 1:]
            top = os.path.join(root, relative.split("/")[0])
            if os.path.islink(top):
                forms.add(os.path.join(root, relative))
    return forms


def owned_set(paths, backend, run=subprocess.run):
    """Subset of `paths` some package claims, asking the package database in batches."""
    paths = sorted(paths)
    owned = set()
    for start in range(0, len(paths), 200):
        batch = paths[start:start + 200]
        if backend == "dpkg":
            out = run(["dpkg", "-S", "--", *batch], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).stdout
            for line in out.splitlines():
                if line.startswith("diversion by"):
                    continue
                _, sep, path = line.partition(": ")
                if sep:
                    owned.add(path.strip())
        elif backend == "rpm":
            out = run(["rpm", "-qf", "--qf", "%{NAME}\\n", "--", *batch], stdout=subprocess.PIPE,
                      stderr=subprocess.DEVNULL, text=True).stdout
            # rpm prints one line per argument, in order.
            lines = out.splitlines()
            if len(lines) == len(batch):
                owned.update(p for p, line in zip(batch, lines) if "is not owned by" not in line)
            else:
                for path in batch:
                    one = run(["rpm", "-qf", "--", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    if one.returncode == 0:
                        owned.add(path)
    return owned


def package_backend(which=shutil.which):
    return "dpkg" if which("dpkg") else "rpm" if which("rpm") else None


def is_owned(path, owned, root="/"):
    return bool(candidates(path, root) & owned)


def is_executable(path, stat_result, opener=open):
    if stat_result.st_mode & 0o111:
        return True
    try:
        with opener(path, "rb") as handle:
            return handle.read(4) == b"\x7fELF"
    except OSError:
        return False


def timestomped(stat_result):
    return stat_result.st_mtime < stat_result.st_ctime - SKEW


EXEC_PROPS = ("ExecStart", "ExecStartPre", "ExecStartPost")
SHOW = ("Id", "LoadState", "FragmentPath", *EXEC_PROPS)


def exec_paths(show_value):
    """Binaries from systemctl's rendering `{ path=/bin/x ; argv[]=... ; ... }` (one block per command)."""
    return [m[1] for m in re.finditer(r"\{ path=(\S+) ;", show_value)]


def systemctl(*args, run=subprocess.run):
    result = run(["systemctl", "--no-pager", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                 universal_newlines=True, timeout=60)
    if result.returncode:
        raise OSError("systemctl %s: %s" % (" ".join(args[:2]), result.stderr.strip() or result.returncode))
    return result.stdout


def loaded_units(run=subprocess.run, chunk=100):
    """({fragment path: [binaries]}, errors) as the service manager has resolved them (drop-ins included)."""
    names = set()
    for args in (("list-unit-files", "--type=service", "--no-legend"),
                 ("list-units", "--all", "--type=service", "--no-legend", "--plain")):
        names.update(f[0] for f in (l.split() for l in systemctl(*args, run=run).splitlines())
                     if f and f[0].endswith(".service") and not f[0].endswith("@.service"))
    units, errors, answered = {}, [], set()
    names = sorted(names)
    for i in range(0, len(names), chunk):
        out = systemctl("show", "-p", ",".join(SHOW), *names[i:i + chunk], run=run)
        for block in out.strip("\n").split("\n\n"):
            props = dict(line.partition("=")[::2] for line in block.splitlines() if "=" in line)
            if not props.get("Id"):
                continue
            answered.add(props["Id"])
            if props.get("LoadState") in ("not-found", "masked"):
                continue
            if props.get("LoadState") != "loaded" or not props.get("FragmentPath"):
                errors.append("unit %s not inspected: LoadState=%s" % (props["Id"], props.get("LoadState") or "?"))
                continue
            units.setdefault(props["FragmentPath"], [])
            units[props["FragmentPath"]] += [b for k in EXEC_PROPS for b in exec_paths(props.get(k, ""))]
    errors += ["unit %s not inspected: systemd gave no answer" % n for n in names if n not in answered]
    return units, errors


def running_executables(proc="/proc"):
    """{exe path: [pids]}; memfd/deleted binaries never match a file on disk."""
    result = {}
    for name in os.listdir(proc):
        if name.isdigit():
            try:
                exe = os.readlink(os.path.join(proc, name, "exe"))
            except OSError:
                continue
            result.setdefault(exe.removesuffix(" (deleted)"), []).append(int(name))
            # Scripts run as `interpreter /path/script`; the process is "running" that file too.
            try:
                with open(os.path.join(proc, name, "cmdline"), "rb") as handle:
                    argv = handle.read().split(b"\0")
            except OSError:
                continue
            if len(argv) > 1 and argv[1].startswith(b"/"):
                result.setdefault(os.fsdecode(argv[1]), []).append(int(name))
    return result


def allowed(path, patterns):
    return any(fnmatch.fnmatch(path, p) for p in patterns)


def read_allowlist(path):
    if not path:
        return []
    with open(path) as handle:
        return [line.strip() for line in handle if line.strip() and not line.startswith("#")]


def analyze(files, units, owned, running, allowlist=(), lstat=os.lstat, opener=open, exists=os.path.exists):
    """Rows for unowned executables/timestomped files/units. Pure given its inputs.

    units: {unit fragment path: [binaries systemd will execute]} from the live manager."""
    rows = []
    unit_set = set(units)
    for path in sorted(set(files) - unit_set):
        if allowed(path, allowlist) or is_owned(path, owned):
            continue
        try:
            info = lstat(path)
        except OSError:
            continue
        flags = []
        if is_executable(path, info, opener):
            flags.append("unowned-exec")
        if timestomped(info):
            flags.append("timestomped")
        pids = running.get(os.path.realpath(path), []) or running.get(path, [])
        if flags and pids:
            flags.append("running")
        if flags:
            critical = {"unowned-exec", "running"} <= set(flags) or "timestomped" in flags
            kind = "timestomped" if "timestomped" in flags and "unowned-exec" not in flags else "unowned-exec"
            rows.append({"kind": kind, "path": path, "flags": flags, "pids": pids,
                         "severity": "critical" if critical else "warning"})
    for path in sorted(unit_set):
        if allowed(path, allowlist):
            continue
        unit_owned = is_owned(path, owned)
        targets = list(dict.fromkeys(units[path]))
        before = len(rows)
        for binary in targets:
            base = {"path": path, "unit": path, "binary": binary, "unit_owned": unit_owned}
            if not exists(binary):
                rows.append({**base, "kind": "unit-missing-binary", "flags": [], "pids": [], "severity": "info"})
            elif not allowed(binary, allowlist) and not is_owned(binary, owned):
                rows.append({**base, "kind": "unit-runs-unowned", "flags": ["unit-runs-unowned"],
                             "pids": running.get(os.path.realpath(binary), []),
                             "severity": "warning" if unit_owned else "critical"})
        if not unit_owned and len(rows) == before:
            rows.append({"kind": "unowned-unit", "path": path, "unit": path, "flags": ["unowned-unit"],
                         "pids": [], "unit_owned": False, "severity": "warning"})
    return rows


def cap(rows, limit=MAX_ROWS):
    """Most severe first; report what was dropped instead of hiding it."""
    order = {"critical": 0, "warning": 1, "info": 2}
    rows = sorted(rows, key=lambda r: (order[r["severity"]], r["path"]))
    errors = [f"{len(rows) - limit} lower-severity rows omitted (cap {limit})"] if len(rows) > limit else []
    return rows[:limit], errors


def scan(allowlist=(), run=subprocess.run):
    backend = package_backend()
    if backend is None:
        return {"findings": [], "errors": ["no dpkg or rpm database; ownership cannot be established"]}
    files = list(list_files(DIRS))
    try:
        units, unit_errors = loaded_units(run)
    except OSError as exc:  # no systemd (or no bus): say so rather than reporting units as clean
        units, unit_errors = {}, ["units not inspected: %s" % exc]
    asked = set(files) | set(units)
    for binaries in units.values():
        asked.update(binaries)
    for path in list(asked):
        asked |= candidates(path)
    owned = owned_set(asked, backend, run)
    rows, errors = cap(analyze(files, units, owned, running_executables(), allowlist))
    return {"findings": rows, "errors": unit_errors + errors}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allowlist", help="file of fnmatch patterns (one per line) for team-owned files")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(scan(read_allowlist(args.allowlist)), sort_keys=True))
    except (OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({"findings": [], "errors": [str(exc)]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
