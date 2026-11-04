#!/usr/bin/env python3
"""Find library injection: LD_PRELOAD/LD_LIBRARY_PATH in units, drop-ins, env files, ld.so.preload,
and unowned shared objects mapped into running processes.

Prints {"findings": [row...], "errors": [...]}. Fails closed: a unit that cannot be read or
parsed becomes a row naming it, never silence. Read-only.
"""
import glob
import json
import os
import shlex
import subprocess
import sys

VARS = ("LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT")
UNIT_DIRS = ("/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system")
ENV_FILES = ("/etc/environment",)
ENV_GLOBS = ("/etc/profile.d/*", "/etc/profile", "/etc/bash.bashrc", "/etc/environment.d/*.conf")
MAX_MAPPED = 50


def logical_lines(text):
    """Systemd-style lines: backslash continues, # and ; start comments."""
    pending = ""
    for raw in text.splitlines():
        line = pending + raw.strip()
        pending = ""
        if line.endswith("\\"):
            pending = line[:-1] + " "
            continue
        if line and line[0] not in "#;":
            yield line
    if pending.strip():
        yield pending.strip()


def parse_unit(text):
    """[(directive, name, value)] for Environment= and EnvironmentFile=; ValueError if unparseable."""
    found = []
    for line in logical_lines(text):
        key, sep, value = line.partition("=")
        key = key.strip()
        if key == "Environment" and sep:
            for assignment in shlex.split(value):
                name, eq, val = assignment.partition("=")
                found.append(("Environment", name, val if eq else ""))
        elif key == "EnvironmentFile" and sep:
            found.append(("EnvironmentFile", value.strip().lstrip("-"), ""))
    return found


def env_assignments(text):
    """(variable, value) pairs from KEY=VALUE / export KEY=VALUE lines of an env or profile file."""
    for line in logical_lines(text):
        line = line.removeprefix("export ").strip()
        name, sep, value = line.partition("=")
        if sep and name.strip() in VARS:
            yield name.strip(), value.strip().strip("\"'")


def unit_files(dirs=UNIT_DIRS):
    for directory in dirs:
        yield from sorted(glob.glob(os.path.join(directory, "*.service")))
        yield from sorted(glob.glob(os.path.join(directory, "*.socket")))
        yield from sorted(glob.glob(os.path.join(directory, "*.d", "*.conf")))


def unit_name(path):
    parent = os.path.basename(os.path.dirname(path))
    return parent[:-2] if parent.endswith(".d") else os.path.basename(path)


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read(1 << 20)


def scan_units(dirs=UNIT_DIRS, reader=read):
    rows, seen = [], set()
    for path in unit_files(dirs):
        if path in seen:
            continue
        seen.add(path)
        unit = unit_name(path)
        try:
            entries = parse_unit(reader(path))
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            rows.append({"kind": "unreadable", "file": path, "unit": unit, "reason": str(exc)})
            continue
        for directive, name, value in entries:
            if directive == "Environment" and name in VARS:
                rows.append({"kind": "unit-env", "file": path, "unit": unit, "variable": name, "value": value})
            elif directive == "EnvironmentFile":
                try:
                    pairs = list(env_assignments(reader(name)))
                except FileNotFoundError:
                    continue
                except (OSError, UnicodeDecodeError, ValueError) as exc:
                    rows.append({"kind": "unreadable", "file": name, "unit": unit, "reason": str(exc)})
                    continue
                rows.extend({"kind": "unit-env", "file": name, "unit": unit, "variable": v, "value": val}
                            for v, val in pairs)
    return rows


def scan_env_files(files=ENV_FILES, globs=ENV_GLOBS, reader=read):
    paths = list(files)
    for pattern in globs:
        paths.extend(sorted(glob.glob(pattern)))
    rows = []
    for path in paths:
        try:
            pairs = list(env_assignments(reader(path)))
        except (FileNotFoundError, IsADirectoryError):
            continue
        except (OSError, UnicodeDecodeError) as exc:
            rows.append({"kind": "unreadable", "file": path, "unit": "", "reason": str(exc)})
            continue
        rows.extend({"kind": "profile-env", "file": path, "unit": "", "variable": v, "value": val}
                    for v, val in pairs)
    return rows


def scan_ld_so_preload(path="/etc/ld.so.preload", reader=read):
    try:
        libs = list(logical_lines(reader(path)))
    except FileNotFoundError:
        return []
    except (OSError, UnicodeDecodeError) as exc:
        return [{"kind": "unreadable", "file": path, "unit": "", "reason": str(exc)}]
    return [{"kind": "ld-so-preload", "file": path, "libraries": libs}] if libs else []


def owned(path, run=subprocess.run):
    """True when a package owns the path or its realpath (usrmerge makes either form lie)."""
    forms = list(dict.fromkeys([path, os.path.realpath(path)]))
    for query in (["dpkg", "-S"], ["rpm", "-qf"]):
        try:
            for form in forms:
                if run([*query, form], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                    return True
        except FileNotFoundError:
            continue
    return False


def mapped_libraries(proc="/proc"):
    """{library path: [(pid, comm)]} for every .so mapped by a readable process."""
    libs = {}
    for pid in sorted((p for p in os.listdir(proc) if p.isdigit()), key=int):
        try:
            with open(f"{proc}/{pid}/maps") as handle:
                names = {parts[5].strip() for parts in (line.split(None, 5) for line in handle) if len(parts) == 6}
            with open(f"{proc}/{pid}/comm") as handle:
                comm = handle.read().strip()
        except OSError:
            continue
        for name in names:
            if name.startswith("/") and ".so" in os.path.basename(name) and not name.endswith("(deleted)"):
                libs.setdefault(name, []).append((int(pid), comm))
    return libs


def scan_maps(proc="/proc", is_owned=owned, exists=os.path.exists):
    rows = []
    for lib, users in sorted(mapped_libraries(proc).items()):
        if not exists(lib) or is_owned(lib):
            continue
        rows.append({"kind": "mapped-unowned", "library": lib,
                     "processes": [{"pid": p, "comm": c} for p, c in users[:5]]})
        if len(rows) >= MAX_MAPPED:
            break
    return rows


def scan():
    rows, errors = [], []
    for name, step in (("units", scan_units), ("environment files", scan_env_files),
                       ("ld.so.preload", scan_ld_so_preload), ("process maps", scan_maps)):
        try:
            rows.extend(step())
        except (OSError, ValueError) as exc:
            errors.append(f"{name}: {exc}")
    return {"findings": rows, "errors": errors}


def main():
    print(json.dumps(scan(), sort_keys=True))


if __name__ == "__main__":
    sys.exit(main())
