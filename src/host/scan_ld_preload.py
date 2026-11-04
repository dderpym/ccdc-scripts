#!/usr/bin/env python3
"""Find library injection from live state: systemd's resolved environment for every startable unit
(`systemctl show`), the environment fresh login shells and the manager really produce, ld.so.preload as
the loader applies it, and unowned shared objects mapped into running processes.

Prints {"findings": [row...], "errors": [...]}. Fails closed: a unit that cannot be read or
parsed becomes a row naming it, never silence. Read-only.
"""
import json
import os
import re
import shlex
import subprocess
import sys

VARS = ("LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT")
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


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read(1 << 20)


def systemctl(*args, run=subprocess.run):
    result = run(["systemctl", "--no-pager", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                 universal_newlines=True, timeout=60)
    if result.returncode:
        raise OSError("systemctl %s: %s" % (" ".join(args[:2]), result.stderr.strip() or result.returncode))
    return result.stdout


def unit_names(run=subprocess.run):
    """Every service/socket systemd could start: installed unit files plus anything loaded (incl. transient)."""
    names = set()
    for args in (("list-unit-files", "--type=service,socket", "--no-legend"),
                 ("list-units", "--all", "--type=service,socket", "--no-legend", "--plain")):
        for line in systemctl(*args, run=run).splitlines():
            fields = line.split()
            if fields and "." in fields[0] and not fields[0].endswith("@.service"):
                names.add(fields[0])
    return sorted(names)


SHOW = ("Id", "LoadState", "FragmentPath", "DropInPaths", "Environment", "EnvironmentFiles", "ExecStart")


def show_units(names, run=subprocess.run, chunk=100):
    """{unit: {property: value}} from `systemctl show`, the manager's own view of each unit."""
    units = {}
    for i in range(0, len(names), chunk):
        batch = names[i:i + chunk]
        out = systemctl("show", "-p", ",".join(SHOW), *batch, run=run)
        for block in out.strip("\n").split("\n\n"):
            props = dict(line.partition("=")[::2] for line in block.splitlines() if "=" in line)
            if props.get("Id"):
                units[props["Id"]] = props
    for name in names:
        units.setdefault(name, {})  # asked for but not answered: fail closed below
    return units


def environment_items(value):
    """['A=1', 'LD_PRELOAD=/x'] from systemd's rendering of Environment=; ValueError if malformed."""
    return shlex.split(value) if value.strip() else []


ENV_FILE = re.compile(r"(\S+) \(ignore_errors=(?:yes|no)\)")


def locate(variable, props):
    """Best effort: the last file among fragment + drop-ins that sets `variable` (later drop-ins win)."""
    paths = ([props["FragmentPath"]] if props.get("FragmentPath") else []) + props.get("DropInPaths", "").split()
    hit = ""
    for path in paths:
        try:
            if variable in read(path):
                hit = path
        except (OSError, UnicodeDecodeError):
            continue
    return hit or props.get("FragmentPath", "")


def scan_units(run=subprocess.run, reader=read):
    """Effective per-unit environment as systemd resolved it, not as any one file says."""
    rows = []
    for unit, props in sorted(show_units(unit_names(run), run).items()):
        state = props.get("LoadState", "")
        if state in ("not-found", "masked"):
            continue
        if state != "loaded":
            rows.append({"kind": "unreadable", "file": props.get("FragmentPath", ""), "unit": unit,
                         "reason": "systemd reports LoadState=%s" % (state or "no answer")})
            continue
        try:
            items = environment_items(props.get("Environment", ""))
        except ValueError as exc:
            rows.append({"kind": "unreadable", "file": props.get("FragmentPath", ""), "unit": unit,
                         "reason": "cannot parse Environment: %s" % exc})
            continue
        for item in items:
            name, _, value = item.partition("=")
            if name in VARS:
                rows.append({"kind": "unit-env", "file": locate(name, props), "unit": unit,
                             "variable": name, "value": value})
        for path in ENV_FILE.findall(props.get("EnvironmentFiles", "")):
            try:
                pairs = list(env_assignments(reader(path)))
            except FileNotFoundError:
                continue
            except (OSError, UnicodeDecodeError, ValueError) as exc:
                rows.append({"kind": "unreadable", "file": path, "unit": unit, "reason": str(exc)})
                continue
            rows.extend({"kind": "unit-env", "file": path, "unit": unit, "variable": v, "value": val}
                        for v, val in pairs)
        for token in props.get("ExecStart", "").replace(";", " ").split():
            name, eq, value = token.partition("=")
            if eq and name in VARS:  # e.g. ExecStart=/usr/bin/env LD_PRELOAD=/x sshd
                rows.append({"kind": "unit-env", "file": props.get("FragmentPath", ""), "unit": unit,
                             "variable": name, "value": value})
    return rows


def probe_environment(command, run=subprocess.run):
    result = run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True,
                 timeout=30, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "TERM": "dumb"})
    return dict(line.partition("=")[::2] for line in result.stdout.splitlines() if "=" in line)


PROBES = (("login shell (sh -l)", ["sh", "-lc", "env"]), ("login shell (bash -l)", ["bash", "-lc", "env"]))


def scan_environment(run=subprocess.run, probes=PROBES):
    """What a fresh login shell and the systemd manager actually hand to new processes."""
    rows = []
    sources = [(label, lambda c=command: probe_environment(c, run)) for label, command in probes]
    sources.append(("systemd manager environment", lambda: dict(
        line.partition("=")[::2] for line in systemctl("show-environment", run=run).splitlines() if "=" in line)))
    for label, get in sources:
        try:
            environment = get()
        except FileNotFoundError:
            continue  # that shell is not installed
        for name in VARS:
            if environment.get(name):
                rows.append({"kind": "profile-env", "file": label, "unit": "", "variable": name,
                             "value": environment[name]})
    return rows


def scan_ld_so_preload(path="/etc/ld.so.preload", reader=read, maps="/proc/self/maps"):
    """The loader's own input, plus whether it really took effect (mapped into this very process)."""
    try:
        libs = list(logical_lines(reader(path)))
    except FileNotFoundError:
        return []
    except (OSError, UnicodeDecodeError) as exc:
        return [{"kind": "unreadable", "file": path, "unit": "", "reason": str(exc)}]
    try:
        with open(maps) as handle:
            mapped = handle.read()
    except OSError:
        mapped = ""
    active = [lib for lib in libs if os.path.realpath(lib) in mapped or lib in mapped]
    return [{"kind": "ld-so-preload", "file": path, "libraries": libs, "active": active}] if libs else []


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
    for name, step in (("units", scan_units), ("login/manager environment", scan_environment),
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
