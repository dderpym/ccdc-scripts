#!/usr/bin/env python3
"""scan_ssh_vectors [--policy JSON] [--allow-key LINE]... [--allow OPTION=VALUE]... [--allow-path PATH]...

Judges what the RUNNING sshd does, not what its files say. Read-only. Prints
{"findings": [row...], "errors": [...]}; rows have a "kind":
  sshd-option      option, value, severity, why, contexts    (`sshd -T -C` per login user and address, so Match
                                                              blocks count; contexts like "deploy@192.0.2.1")
  sshd-policy      option, value, wanted, severity, contexts (effective value differs from --policy, the sshd
                                                              options the inventory declares; none = no check)
  authorized-key   file, user, line, fingerprint, comment    (key file the effective AuthorizedKeysFile gives that
                                                              user, key not in the allowlist)
  ssh-startup      path, what                                (sshrc that sshd would really run at login)
  unowned-ssh-file path                                      (file the effective config references, hidden or unowned)
  stale-config     path, edited, started                     (config changed after the daemon started)
  live-env         pid, name, value                          (LD_PRELOAD & co. in a live sshd process)
  live-library     pid, path, why                            (mapped library that is deleted or unowned)
  odd-listener     address, port, why                        (sshd socket that `sshd -T` does not explain)
The sshd inspected is the running one (resolved via /proc), so a relocated sshd still works.
Fail closed: anything that cannot be inspected goes into "errors", never silence.
"""
import argparse
import base64
import binascii
import glob
import hashlib
import ipaddress
import json
import os
import pwd
import re
import shutil
import subprocess
import sys

KEY_TYPE = re.compile(r"^(ssh-[a-z0-9]+|ecdsa-sha2-nistp\d+|sk-[a-z0-9@.-]+)$")
DEFAULT_KEY_FILES = {".ssh/authorized_keys", ".ssh/authorized_keys2"}
SSHD_COMMS = {"sshd", "sshd-session", "sshd-auth"}
LIVE_ENV = ("LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT")
ADDRESSES = (("localhost", "127.0.0.1"), ("remote.invalid", "192.0.2.1"))
NOLOGIN = ("nologin", "false")
LISTEN = "0A"
# Options whose value names a file or program sshd reads or runs.
REFERENCED = ("authorizedkeyscommand", "authorizedprincipalscommand", "trustedusercakeys", "revokedkeys",
              "banner", "authorizedprincipalsfile")


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


# ---- the running daemon and its effective configuration ------------------------------

def sshd_pids(proc="/proc"):
    """(master pid or None, all sshd-family pids). The master is the sshd whose parent is init."""
    master, family = None, []
    try:
        names = sorted(int(p) for p in os.listdir(proc) if p.isdigit())
    except OSError:
        return None, []
    for pid in names:
        try:
            with open("%s/%d/comm" % (proc, pid)) as handle:
                if handle.read().strip() not in SSHD_COMMS:
                    continue
            with open("%s/%d/stat" % (proc, pid)) as handle:
                ppid = int(handle.read().rpartition(")")[2].split()[1])
        except (OSError, ValueError, IndexError):
            continue
        family.append(pid)
        if ppid == 1 and master is None:
            master = pid
    return master, family


def sshd_binary(proc="/proc"):
    master, _ = sshd_pids(proc)
    if master is not None:
        try:
            path = os.readlink("%s/%d/exe" % (proc, master)).replace(" (deleted)", "")
            if os.access(path, os.X_OK):
                return path
        except OSError:
            pass
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


def sshd_T(binary, context=None, run=subprocess.run):
    argv = [binary, "-T"] + (["-C", context] if context else [])
    result = run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=30)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "sshd -T failed")
    return parse_effective(result.stdout)


def login_accounts(entries=None):
    """[(name, home)] of root and every account whose shell allows a login."""
    entries = pwd.getpwall() if entries is None else entries
    accounts = {("root", next((e.pw_dir for e in entries if e.pw_name == "root"), "/root"))}
    accounts.update((e.pw_name, e.pw_dir) for e in entries
                    if e.pw_shell and os.path.basename(e.pw_shell) not in NOLOGIN and e.pw_dir.startswith("/"))
    return sorted(accounts)


def effective_by_user(binary, accounts, run=subprocess.run):
    """({user: [(address, effective)]}, base effective, errors). One sshd -T per user and address."""
    errors, per_user = [], {}
    try:
        base = sshd_T(binary, None, run)
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        return {}, {}, ["sshd -T unavailable: %s" % exc]
    for user, _ in accounts:
        for host, addr in ADDRESSES:
            context = "user=%s,host=%s,addr=%s" % (user, host, addr)
            try:
                per_user.setdefault(user, []).append((addr, sshd_T(binary, context, run)))
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                errors.append("sshd -T -C %s failed: %s" % (context, exc))
    return per_user, base, errors


# option -> hardened value. Numeric limits: above the value is weak (clientaliveinterval: 0 = disabled).
MAX_LIMITS = {"maxauthtries", "logingracetime", "clientalivecountmax"}


def deviates(option, value, expected):
    """Does an effective sshd value differ from the inventory's declared one?

    Most options must match exactly (case-insensitive); the declared value of
    maxauthtries/logingracetime/clientalivecountmax is a maximum, and
    clientaliveinterval only deviates when it is 0 (keepalives off).
    """
    value, expected = str(value).lower(), str(expected).lower()
    if option in MAX_LIMITS:
        return value.isdigit() and expected.isdigit() and int(value) > int(expected)
    if option == "clientaliveinterval":
        return value == "0" and expected != "0"
    return value != expected


def option_rows(effective, allow=(), policy=None):
    """Findings on one effective configuration. allow: set of 'option=value'; policy: {option: expected}."""
    rows = []

    def add(option, value, severity, why, kind="sshd-option", wanted=""):
        if "%s=%s" % (option, value) not in allow:
            rows.append({"kind": kind, "option": option, "value": value, "severity": severity, "why": why,
                         "wanted": wanted})

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
    for value in effective.get("permituserenvironment", []):
        if value.lower() != "no":
            add("permituserenvironment", value, "critical", "users can set environment (LD_PRELOAD) for sshd sessions")
    for value in effective.get("permitemptypasswords", []):
        if value.lower() != "no":
            add("permitemptypasswords", value, "critical", "accounts with empty passwords may log in")
    # Policy is declared per host in inventory.yml (`ssh:`); nothing here is built in.
    for option, expected in sorted((policy or {}).items()):
        for value in effective.get(option.lower(), []):
            if deviates(option.lower(), value, expected):
                add(option.lower(), value, "critical" if option.lower() == "permitrootlogin" else "warning",
                    "inventory says %s" % expected, "sshd-policy", str(expected))
    return rows


def identity(row):
    return (row["kind"], row["option"], row["value"], row["severity"], row["why"], row.get("wanted", ""))


def effective_option_rows(per_user, base, allow=(), policy=None):
    """Every distinct option finding with the contexts it is effective for."""
    found = {}
    for row in option_rows(base, allow, policy):
        found.setdefault(identity(row), set()).add("default")
    for user, contexts in per_user.items():
        for addr, effective in contexts:
            for row in option_rows(effective, allow, policy):
                found.setdefault(identity(row), set()).add("%s@%s" % (user, addr))
    return [{"kind": k, "option": o, "value": v, "severity": s, "why": w, "wanted": wanted, "contexts": sorted(c)}
            for (k, o, v, s, w, wanted), c in sorted(found.items())]


# ---- keys, rc files and referenced files: only what the effective config makes live ----

def expand(pattern, home, user):
    """AuthorizedKeysFile tokens: %h home, %u user, %% percent; relative paths are under the home."""
    path = re.sub(r"%([hu%])", lambda m: {"h": home, "u": user, "%": "%"}[m[1]], pattern)
    return path if os.path.isabs(path) else os.path.join(home, path)


def key_files(per_user, accounts):
    """{file: user}: what sshd would read for each login user, from that user's effective AuthorizedKeysFile."""
    homes = dict(accounts)
    files = {}
    for user, contexts in per_user.items():
        patterns = {item for _, effective in contexts for value in effective.get("authorizedkeysfile", [])
                    for item in value.split() if item.lower() != "none"}
        for pattern in sorted(patterns):
            files.setdefault(expand(pattern, homes[user], user), user)
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


def startup_rows(per_user, accounts, exists=os.path.lexists):
    """sshrc files sshd runs at login. ~/.ssh/rc counts only where the user's effective
    PermitUserRC is not 'no'; /etc/ssh/sshrc is run by sshd itself for any login."""
    rows = []
    if per_user and exists("/etc/ssh/sshrc"):
        rows.append({"kind": "ssh-startup", "path": "/etc/ssh/sshrc", "what": "system sshrc"})
    homes = dict(accounts)
    for user, contexts in sorted(per_user.items()):
        live = any(value.lower() != "no" for _, effective in contexts
                   for value in effective.get("permituserrc", ["yes"]))
        path = os.path.join(homes[user], ".ssh", "rc")
        if live and exists(path):
            rows.append({"kind": "ssh-startup", "path": path, "what": "user ssh rc"})
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


def referenced_paths(per_user, base):
    """Absolute files or programs the effective configuration tells sshd to read or run."""
    paths = set()
    for effective in [base, *(e for contexts in per_user.values() for _, e in contexts)]:
        for option in REFERENCED:
            for value in effective.get(option, []):
                token = value.split()[0] if value.split() else ""
                if token.startswith("/"):
                    paths.add(token)
    return sorted(paths)


def unowned_rows(paths, allow_paths=(), owner=owned, exists=os.path.lexists):
    rows, errors = [], []
    for path in paths:
        if path in allow_paths or not exists(path):
            continue
        if any(part.startswith(".") for part in path.split("/") if part):
            rows.append({"kind": "unowned-ssh-file", "path": path})
            continue
        verdict = owner(path)
        if verdict is None:
            errors.append("no package database; cannot tell whether %s is owned" % path)
        elif not verdict:
            rows.append({"kind": "unowned-ssh-file", "path": path})
    return rows, sorted(set(errors))


# ---- daemon age vs config age --------------------------------------------------------

def start_time(pid, proc="/proc", clock_ticks=None):
    """Epoch seconds the process started (stat field 22 + btime)."""
    ticks = clock_ticks or os.sysconf("SC_CLK_TCK")
    with open("%s/%d/stat" % (proc, pid)) as handle:
        started = int(handle.read().rpartition(")")[2].split()[19])
    with open("%s/stat" % proc) as handle:
        boot = next(int(line.split()[1]) for line in handle if line.startswith("btime "))
    return boot + started / ticks


def config_files(main="/etc/ssh/sshd_config", read=None, expand_glob=glob.glob, depth=0):
    """The main file, every file it Includes, and the directories the globs live in
    (a deleted drop-in only shows as a changed directory)."""
    read = read or (lambda p: open(p).read())
    found = [main]
    if depth > 8:
        return found
    try:
        text = read(main)
    except OSError:
        return found
    for line in text.splitlines():
        tokens = line.split("#", 1)[0].split()
        if len(tokens) > 1 and tokens[0].lower() == "include":
            for pattern in tokens[1:]:
                pattern = pattern if os.path.isabs(pattern) else os.path.join(os.path.dirname(main), pattern)
                found.append(os.path.dirname(pattern))
                for path in sorted(expand_glob(pattern)):
                    found.extend(config_files(path, read, expand_glob, depth + 1))
    return list(dict.fromkeys(found))


def stale_rows(started, paths, stat=os.stat):
    """ctime cannot be backdated, so it wins over mtime."""
    rows, errors = [], []
    for path in paths:
        try:
            info = stat(path)
        except OSError as exc:
            errors.append("cannot stat %s: %s" % (path, exc))
            continue
        edited = max(info.st_mtime, info.st_ctime)
        if edited > started + 1:
            rows.append({"kind": "stale-config", "path": path, "edited": int(edited), "started": int(started)})
    return rows, errors


# ---- live processes -------------------------------------------------------------------

def environment_rows(pids, proc="/proc"):
    rows, errors = [], []
    for pid in pids:
        try:
            with open("%s/%d/environ" % (proc, pid), "rb") as handle:
                data = handle.read()
        except FileNotFoundError:
            continue  # exited meanwhile
        except OSError as exc:
            errors.append("cannot read environ of sshd pid %d: %s" % (pid, exc))
            continue
        for item in data.split(b"\0"):
            name, _, value = item.decode("utf-8", "replace").partition("=")
            if name in LIVE_ENV and value:
                rows.append({"kind": "live-env", "pid": pid, "name": name, "value": value})
    return rows, errors


def mapped_libraries(pid, proc="/proc"):
    """{path: deleted?} of file-backed shared objects mapped by the process."""
    libraries = {}
    with open("%s/%d/maps" % (proc, pid)) as handle:
        for line in handle:
            fields = line.rstrip("\n").split(None, 5)
            if len(fields) < 6 or not fields[5].startswith("/"):
                continue
            path = fields[5]
            deleted = path.endswith(" (deleted)")
            path = path.removesuffix(" (deleted)")
            if re.search(r"\.so(\.|$)", os.path.basename(path)):
                libraries[path] = libraries.get(path, False) or deleted
    return libraries


def library_rows(pids, proc="/proc", owner=owned, allow_paths=()):
    rows, errors, verdicts = [], [], {}
    for pid in pids:
        try:
            libraries = mapped_libraries(pid, proc)
        except FileNotFoundError:
            continue
        except OSError as exc:
            errors.append("cannot read maps of sshd pid %d: %s" % (pid, exc))
            continue
        for path, deleted in sorted(libraries.items()):
            if path in allow_paths:
                continue
            if deleted:
                rows.append({"kind": "live-library", "pid": pid, "path": path, "why": "mapped file was deleted"})
                continue
            if path not in verdicts:
                verdicts[path] = owner(path)
            if verdicts[path] is None:
                errors.append("no package database; cannot tell whether %s is owned" % path)
            elif not verdicts[path]:
                rows.append({"kind": "live-library", "pid": pid, "path": path, "why": "not owned by any package"})
    return rows, sorted(set(errors))


# ---- listening sockets ----------------------------------------------------------------

def decode_address(text):
    """/proc/net/tcp hex address:port -> (ip string, port)."""
    host, _, port = text.partition(":")
    raw = bytes.fromhex(host)
    if len(raw) == 4:
        address = ipaddress.IPv4Address(raw[::-1])
    else:  # four little-endian 32-bit words
        address = ipaddress.IPv6Address(b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4)))
    return str(address), int(port, 16)


def listening(proc="/proc"):
    """{inode: (ip, port)} of listening TCP sockets."""
    sockets = {}
    for name in ("tcp", "tcp6"):
        try:
            with open("%s/net/%s" % (proc, name)) as handle:
                next(handle, None)
                for line in handle:
                    fields = line.split()
                    if len(fields) > 9 and fields[3] == LISTEN:
                        sockets[int(fields[9])] = decode_address(fields[1])
        except FileNotFoundError:
            continue
    return sockets


def socket_inodes(pid, proc="/proc"):
    inodes = set()
    directory = "%s/%d/fd" % (proc, pid)
    for entry in os.listdir(directory):
        try:
            target = os.readlink(os.path.join(directory, entry))
        except OSError:
            continue
        match = re.fullmatch(r"socket:\[(\d+)\]", target)
        if match:
            inodes.add(int(match[1]))
    return inodes


def expected_listeners(effective):
    """(set of (ip, port), set of ports, exact?) from sshd -T `listenaddress`/`port`."""
    ports = {int(p) for p in effective.get("port", [])}
    pairs, exact = set(), True
    for value in effective.get("listenaddress", []):
        match = re.fullmatch(r"\[([^\]]+)\]:(\d+)|([^:]+):(\d+)", value)
        try:
            host, port = (match[1], match[2]) if match[1] else (match[3], match[4])
            pairs.add((str(ipaddress.ip_address(host)), int(port)))
            ports.add(int(port))
        except (TypeError, ValueError):
            exact = False  # hostname or odd syntax: compare ports only
    return pairs, ports, exact


def listener_rows(master, effective, proc="/proc"):
    rows = []
    try:
        inodes = socket_inodes(master, proc)
        sockets = listening(proc)
    except OSError as exc:
        return rows, ["cannot inspect sshd sockets: %s" % exc]
    pairs, ports, exact = expected_listeners(effective)
    if not ports:
        return rows, ["sshd -T gave no port; cannot judge listeners"]
    for inode in sorted(inodes & set(sockets)):
        address, port = sockets[inode]
        if port not in ports:
            rows.append({"kind": "odd-listener", "address": address, "port": port, "why": "port not in sshd configuration"})
        elif exact and pairs and (address, port) not in pairs:
            rows.append({"kind": "odd-listener", "address": address, "port": port, "why": "address not in ListenAddress"})
    return rows, []


def scan(allow_keys=(), allow_options=(), allow_paths=(), proc="/proc", run=subprocess.run, accounts=None,
         config=None, policy=None):
    rows, errors = [], []
    if not policy:
        errors.append("no ssh policy declared in inventory; policy checks skipped")
    allowed = {parsed[0] for parsed in map(parse_key_line, allow_keys) if parsed}
    if not allowed:
        errors.append("no key allowlist supplied; every authorized key is reported")
    try:
        binary = sshd_binary(proc)
    except RuntimeError as exc:
        return {"findings": [], "errors": errors + [str(exc)]}
    accounts = login_accounts() if accounts is None else accounts
    per_user, base, problems = effective_by_user(binary, accounts, run)
    errors += problems
    if not base:
        return {"findings": [], "errors": errors}
    rows += effective_option_rows(per_user, base, set(allow_options), policy)
    found, problems = key_rows(key_files(per_user, accounts), allowed)
    rows += found
    errors += problems
    rows += startup_rows(per_user, accounts)
    found, problems = unowned_rows(referenced_paths(per_user, base), set(allow_paths))
    rows += found
    errors += problems
    master, family = sshd_pids(proc)
    if master is None:
        errors.append("no running sshd found; live checks skipped")
    else:
        try:
            found, problems = stale_rows(start_time(master, proc), config_files() if config is None else config)
            rows += found
            errors += problems
        except (OSError, ValueError, StopIteration) as exc:
            errors.append("cannot compute sshd start time: %s" % exc)
        for part in (environment_rows(family, proc), library_rows(family, proc, allow_paths=set(allow_paths))):
            rows += part[0]
            errors += part[1]
        found, problems = listener_rows(master, base, proc)
        rows += found
        errors += problems
    skip = set(allow_paths)
    rows = [row for row in rows if row.get("path", row.get("file")) not in skip]
    return {"findings": rows, "errors": sorted(set(errors))}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", default="{}", help='JSON {"option": expected} from the inventory')
    parser.add_argument("--allow-key", action="append", default=[])
    parser.add_argument("--allow", action="append", default=[])
    parser.add_argument("--allow-path", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        policy = json.loads(args.policy)
        if not isinstance(policy, dict):
            raise ValueError("policy must be an object")
    except ValueError as exc:
        print(json.dumps({"findings": [], "errors": ["invalid --policy: %s" % exc]}))
        return 1
    print(json.dumps(scan(args.allow_key, args.allow, args.allow_path, policy=policy), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
