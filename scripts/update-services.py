"""Stdlib service inspection; restart_service is called only after explicit approval.

Snapshots contain every active service, not just stale ones. Deleted file evidence
is not proof of package ownership or update causation. No reboot, shell, or probes.
"""
import os
from pathlib import Path
import re
import runpy
import subprocess


_helpers = runpy.run_path(str(Path(__file__).with_name("discover-listeners")))
process_info = _helpers["process_info"]
service_hints = _helpers["service_hints"]
PROC = Path("/proc")
RUN = Path("/run")
TIMEOUT = 30
STALE = "process uses replaced executable/library"
INCOMPLETE = "discovery incomplete: "
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@:-]{0,254}\Z", re.ASCII)


def _name(init, name):
    if init not in ("systemd", "openrc"):
        raise ValueError("only systemd and openrc are supported")
    if (not isinstance(name, str) or not NAME.fullmatch(name)
            or (init == "systemd" and (not name.endswith(".service") or name == ".service"))):
        raise ValueError("invalid service name")
    return name


def _strings(value):
    return (isinstance(value, list) and len(value) <= 100000
            and all(isinstance(s, str) and 0 < len(s) <= 16384 for s in value))


def _before(init, before):
    if init not in ("systemd", "openrc"):
        raise ValueError("only systemd and openrc are supported")
    if before is None:
        return {}
    if (not isinstance(before, dict) or set(before) != {"services", "unmanaged", "warnings"}
            or not _strings(before["warnings"])):
        raise ValueError("invalid before snapshot")
    names, pids = {}, set()
    for key in ("services", "unmanaged"):
        rows = before[key]
        if not isinstance(rows, list) or len(rows) > 100000:
            raise ValueError("invalid before snapshot rows")
        for row in rows:
            if not isinstance(row, dict) or not _strings(row.get("reasons")):
                raise ValueError("invalid before snapshot reasons")
            if key == "services":
                if (set(row) != {"name", "active", "pids", "reasons", "confidence"}
                        or type(row["active"]) is not bool
                        or row["confidence"] not in ("high", "low", "unknown")
                        or not isinstance(row["pids"], list)):
                    raise ValueError("invalid before service")
                name = _name(init, row["name"])
                if name in names:
                    raise ValueError("duplicate before service")
                names[name] = row
                ids = row["pids"]
                if not row["active"] and ids:
                    raise ValueError("inactive before service has PIDs")
            else:
                if (set(row) != {"pid", "process", "reasons"}
                        or not isinstance(row["process"], str) or not row["process"]
                        or len(row["process"]) > 16384):
                    raise ValueError("invalid before unmanaged process")
                ids = [row["pid"]]
            for pid in ids:
                if type(pid) is not int or pid < 1 or pid in pids:
                    raise ValueError("invalid or duplicate before PID")
                pids.add(pid)
    return names


def _run(argv):
    try:
        return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, timeout=TIMEOUT,
                              env=dict(os.environ, LC_ALL="C"), check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("%s: %s" % (argv[0], exc)) from exc


def _require(argv):
    result = _run(argv)
    if result.returncode:
        raise RuntimeError("%s failed (%d): %s" % (
            " ".join(argv), result.returncode, (result.stderr or result.stdout).strip()[:2000]))
    return result


def _text(path, warnings):
    try:
        return path.read_text(errors="replace")
    except (FileNotFoundError, ProcessLookupError):
        return ""  # Normal /proc race.
    except OSError as exc:
        warnings.append(INCOMPLETE + "%s: %s" % (path, exc))
        return ""


def _exists(init, name):
    if init == "systemd":
        result = _require(["systemctl", "show", "--property=LoadState", "--value", "--", name])
        return result.stdout.strip() == "loaded"
    result = _run(["rc-service", "--exists", name])
    if result.returncode not in (0, 1):
        raise RuntimeError("rc-service existence check failed for " + name)
    return result.returncode == 0


def _native_services(init, before, warnings):
    """Current known units and their activity; do not invent services from /proc."""
    states = {}
    try:
        if init == "systemd":
            result = _require(["systemctl", "list-units", "--all", "--type=service",
                               "--no-legend", "--plain", "--no-pager"])
            for line in result.stdout.splitlines():
                if not line.strip():
                    continue
                fields = line.split()
                if len(fields) < 4:
                    raise RuntimeError("malformed systemctl list-units output")
                name, load, active = fields[:3]
                _name(init, name)
                if load == "loaded":
                    if active not in ("active", "reloading", "inactive", "failed"):
                        warnings.append(INCOMPLETE + name + " is in transitional state " + active)
                    states[name] = active in ("active", "reloading")
        else:
            started = RUN / "openrc/started"
            names = {p.name for p in started.iterdir()}
            names.update(name for name, row in before.items() if row["active"])
            for name in sorted(names):
                _name(init, name)
                if not _exists(init, name):
                    continue
                result = _run(["rc-service", name, "status"])
                if result.returncode not in (0, 3):
                    warnings.append(INCOMPLETE + "rc-service status failed for " + name)
                    continue
                states[name] = result.returncode == 0
    except (OSError, RuntimeError, ValueError) as exc:
        warnings.append(INCOMPLETE + str(exc))
    return states


def _deleted_file(path):
    return (path.startswith("/") and path.endswith(" (deleted)")
            and not path.startswith(("/dev/", "/memfd:", "/SYSV", "/anon_hugepage", "/[")))


def _stale(path, warnings):
    evidence = []
    try:
        exe = os.readlink(path / "exe")
        if _deleted_file(exe):
            evidence.append("PID %s: deleted executable: %s" % (path.name, exe))
    except (FileNotFoundError, ProcessLookupError):
        pass
    except OSError as exc:
        warnings.append(INCOMPLETE + "%s/exe: %s" % (path, exc))
    for line in _text(path / "maps", warnings).splitlines():
        fields = line.split(None, 5)
        if len(fields) != 6 or not _deleted_file(fields[5]):
            continue
        # Anonymous mappings and memfd have no real file inode/path to replace.
        try:
            if int(fields[4]) == 0:
                continue
        except ValueError:
            warnings.append(INCOMPLETE + "malformed maps entry for PID " + path.name)
            continue
        evidence.append("PID %s: deleted library/file mapping: %s" % (path.name, fields[5]))
    return sorted(set(evidence))


def _validator(name):
    if name in ("ssh", "sshd", "ssh.service", "sshd.service"):
        return ["/usr/sbin/sshd", "-t"]
    if name in ("nginx", "nginx.service"):
        return ["nginx", "-t"]
    return None


def inspect_services(init, before=None):
    previous = _before(init, before)
    warnings = []
    states = _native_services(init, previous, warnings)
    native_complete = not any(w.startswith(INCOMPLETE) for w in warnings)
    active = {name for name, running in states.items() if running}
    services = {name: dict(name=name, active=True, pids=[], reasons=[],
                          confidence="high" if init == "systemd" else "low")
                for name in active}
    for name, row in previous.items():
        if native_complete and row["active"] and name not in active:
            services[name] = dict(name=name, active=False, pids=[], confidence="high",
                                 reasons=["service stopped since update (was active in before snapshot)"])
    info, paths, hints = {}, {}, {}
    try:
        paths = {int(p.name): p for p in PROC.iterdir() if p.name.isdigit()}
    except OSError as exc:
        warnings.append(INCOMPLETE + str(exc))
    for pid, path in sorted(paths.items()):
        try:
            info[pid] = process_info(pid)
            # Helpers intentionally tolerate races; surface inaccessible metadata here.
            for file in ("stat", "comm"):
                _text(path / file, warnings)
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError as exc:
            warnings.append(INCOMPLETE + "PID %d: %s" % (pid, exc))
    if init == "openrc":
        try:
            # service_hints tolerates unreadable pidfiles; report that uncertainty.
            for path in RUN.iterdir():
                if path.name.endswith(".pid"):
                    _text(path, warnings)
            hints, _ = service_hints()
            # Stock daemons such as nginx also put their pidfile in /run/<service>/.
            # Keep this advisory/low-confidence and require an actual active unit.
            for name in active:
                pidfile = RUN / name / (name + ".pid")
                value = _text(pidfile, warnings).strip()
                if value.isdigit() and int(value) > 1 and int(value) in paths:
                    hints.setdefault(int(value), []).append((name, True))
        except OSError as exc:
            warnings.append(INCOMPLETE + str(exc))

    def owner(pid):
        if pid == 1:
            return None
        if init == "systemd":
            groups = _text(paths[pid] / "cgroup", warnings)
            records = [line.split(":", 2) for line in groups.splitlines()]
            group_paths = [record[2].split("/") for record in records if len(record) == 3
                           and (record[:2] == ["0", ""] or "name=systemd" in record[1].split(","))]
            components = [part for parts in group_paths for part in parts]
            # Nested/delegated managers (users or containers) are not our scope.
            if (any(sum(part.endswith(".service") for part in parts) > 1 for parts in group_paths)
                    or any(part == "user.slice" or part.startswith("user@") for part in components)):
                return None
            unit = info.get(pid, {}).get("service")
            units = [part for part in components if part.endswith(".service")]
            return unit if units and unit == units[-1] and unit in active else None
        current, seen, candidates = pid, set(), set()
        while current > 1 and current not in seen:
            seen.add(current)
            candidates.update(name for name, _ in hints.get(current, ()) if name in active)
            current = info.get(current, {}).get("parent", 0)
        return next(iter(candidates)) if len(candidates) == 1 else None

    old_evidence = set()
    if before is not None:
        for row in before["services"] + before["unmanaged"]:
            old_evidence.update(row["reasons"])
    unmanaged = []
    for pid, path in sorted(paths.items()):
        name = owner(pid)
        evidence = _stale(path, warnings)
        reasons = [STALE, *evidence] if evidence else []
        if evidence and before is not None:
            if any(reason in old_evidence for reason in evidence):
                reasons.append("stale file evidence already present before update; causation unknown")
            if any(reason not in old_evidence for reason in evidence):
                reasons.append("new stale file evidence since before snapshot; causation unknown")
        if name:
            services[name]["pids"].append(pid)
            services[name]["reasons"].extend(reasons)
        elif evidence:
            unmanaged.append(dict(pid=pid, process=info.get(pid, {}).get("process") or "unknown",
                                  reasons=reasons))
            if pid == 1:
                warnings.append("PID 1 uses replaced executable/library; reboot may be pending; do not restart init")
            else:
                warnings.append("unmanaged stale PID %d; investigate manually, do not blindly kill" % pid)
    for row in services.values():
        old = previous.get(row["name"], {})
        if (row["active"] and old.get("active") and old.get("pids") and row["pids"]
                and set(old["pids"]).isdisjoint(row["pids"])):
            warnings.append(row["name"] + ": running PIDs changed since before snapshot; native hooks may have restarted it")
        row["reasons"] = sorted(set(row["reasons"]))
        if row["reasons"] and _validator(row["name"]) is None:
            warnings.append(row["name"] + ": no known config validator; restart requires explicit operator approval")
    return dict(services=[services[name] for name in sorted(services)], unmanaged=unmanaged,
                warnings=sorted(set(warnings)))


def _selected(state, name):
    errors = [warning for warning in state["warnings"] if warning.startswith(INCOMPLETE)]
    if errors:
        raise RuntimeError("cannot safely restart with incomplete discovery: " + "; ".join(errors))
    return next((row for row in state["services"] if row["name"] == name), None)


def restart_service(init, name, before=None):
    """Explicit single-service restart; snapshot is evidence, never a command list."""
    _name(init, name)
    previous = _before(init, before)
    if not _exists(init, name):
        raise RuntimeError("not a current managed service: " + name)
    state = inspect_services(init, before)
    row = _selected(state, name)
    if row is None or (not row["active"] and not previous.get(name, {}).get("active")):
        raise RuntimeError("service was not active before update and is not active now: " + name)
    if not row["reasons"]:
        return dict(name=name, status="already-current", service=row, warnings=state["warnings"])
    validator = _validator(name)
    if validator:
        _require(validator)
    # Config checks can take time: re-inspect immediately before the mutation.
    state = inspect_services(init, before)
    row = _selected(state, name)
    if row is None:
        raise RuntimeError("service no longer qualifies for restart: " + name)
    if not row["reasons"]:
        return dict(name=name, status="already-current", service=row, warnings=state["warnings"])
    if not _exists(init, name):
        raise RuntimeError("service no longer exists: " + name)
    command = (["systemctl", "restart", "--", name] if init == "systemd"
               else ["rc-service", name, "restart"])
    _require(command)
    _require(["systemctl", "is-active", "--quiet", "--", name] if init == "systemd"
             else ["rc-service", name, "status"])
    after = inspect_services(init, before)
    checked = _selected(after, name)
    if checked is None or not checked["active"] or checked["reasons"]:
        raise RuntimeError("restart did not produce an active, current service: " + name
                           + "; existing sessions/workers may retain old mappings and need to exit; do not blindly kill them")
    return dict(name=name, status="restarted", service=checked,
                warnings=sorted(set(state["warnings"] + after["warnings"])))
