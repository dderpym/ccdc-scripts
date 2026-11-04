"""Passive, stdlib-only review candidates supplementing the vendored LSE.

No delegated commands, socket connections, writes, or filesystem-wide capability searches.
The sudo check only lists policy noninteractively; it never executes a permitted command.
Permission metadata is not exploit validation. Optional path arguments are for
isolated fixtures; scan() uses the normal Linux locations.
"""
import errno
import fnmatch
import os
from pathlib import Path
import re
import stat

from host.kernel_risks import read_regular as _read_regular

RUNTIME_PATHS = (
    "docker.sock", "docker.socket", "cri-dockerd.sock", "dockershim.sock",
    "containerd/containerd.sock", "crio/crio.sock", "podman/podman.sock",
    "buildkit/buildkitd.sock", "buildkitd.sock", "lxd/unix.socket",
)
LXD_PATHS = ("/var/lib/lxd/unix.socket", "/var/snap/lxd/common/lxd/unix.socket")
READ_LIMIT = 1024 * 1024
HEADER = re.compile(r"^\[[!*i]\]\s+([a-z]{3}\d{3})\s+.*?\s+(yes!|nope|skip)\s*$")
CAP_GROUP = r"cap_[a-z0-9_]+(?:,cap_[a-z0-9_]+)*[=+-][eip]+"
CAP_LINE = re.compile(r"^(/.+?)\s+(?:=\s+)?(" + CAP_GROUP + r"(?:\s+" + CAP_GROUP + r")*)(?:\s+\[rootid=\d+\])?$")
INTERPRETER = re.compile(r"^(?:python(?:\d+(?:\.\d+)*)?|perl(?:\d+(?:\.\d+)*)?|ruby(?:\d+(?:\.\d+)*)?|php(?:\d+(?:\.\d+)*)?|node(?:js)?|lua(?:\d+(?:\.\d+)*)?|bash|sh|dash|zsh|ksh)$")
DAC = {"cap_dac_override", "cap_dac_read_search"}
DANGEROUS = DAC | {"cap_setuid", "cap_setgid", "cap_sys_admin", "cap_sys_module", "cap_sys_ptrace"}


def _result(name, contexts=(), gaps=(), raw=""):
    test_id = "extra-" + name
    contexts = sorted(contexts, key=lambda c: (c["summary"], c["evidence"]))
    findings = []
    if contexts:
        findings.append({"id": test_id, "severity": "warning",
                         "summary": {"capabilities": "Executable capability review candidates",
                                     "runtime-sockets": "Writable root-owned runtime socket review candidates",
                                     "loader": "Writable loader path review candidates",
                                     "process-capabilities": "Dangerous effective/ambient process capabilities",
                                     "sgid": "SGID executable review candidates",
                                     "doas": "Root-capable doas policy review candidates"}[name],
                         "context": contexts})
    result = {"findings": findings, "raw": raw, "errors": []}
    if gaps:
        result["incomplete_ids"] = [test_id]
        findings.append({"id": "scanner-" + test_id, "severity": "warning",
                         "summary": "Extra %s coverage incomplete" % name,
                         "context": [{"summary": "Coverage gap", "evidence": sorted(set(gaps))}]})
    return result


def _access(path, mode):
    return os.access(path, mode, effective_ids=True)


def inspect_capabilities(raw_lse, exit_status=None):
    """Use only affirmative sec010 bodies, never the banner's claimed UID."""
    if os.geteuid() == 0:
        return _result("capabilities", gaps=["Root cannot assess unprivileged permissions"], raw=raw_lse)
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", raw_lse)
    contexts, gaps, bodies = [], [], []
    current, in_body, affirmative, empty = None, False, False, False
    for line in text.splitlines():
        header = HEADER.match(line)
        if header:
            test_id, status = header.groups()
            current, in_body = None, False
            if test_id == "sec010":
                if status == "yes!":
                    affirmative = True
                    current = []
                    bodies.append(current)
                elif status == 'nope' and exit_status == 0:
                    empty = True  # Successful native enumeration with no capabilities.
                else:
                    gaps.append("Upstream sec010 was " + status + "; getcap evidence unavailable")
        elif line.strip() == "---":
            in_body = not in_body
        elif line.startswith("==="):
            current, in_body = None, False
        elif current is not None and in_body and line.strip():
            current.append(line.strip())
    if not affirmative and not empty:
        gaps.append("No successful upstream sec010/getcap inventory")
    if exit_status is not None and exit_status != 0:
        gaps.append("Native getcap exited with status " + str(exit_status))
    for line in (line for body in bodies for line in body):
        match = CAP_LINE.fullmatch(line)
        if not match:
            gaps.append("Malformed or unavailable upstream capability evidence")
            continue
        path, groups = match.groups()
        flags = {}
        for group in groups.split():
            names, op, value = re.split(r"([=+-])", group)
            for cap in names.split(","):
                previous = flags.get(cap, set())
                flags[cap] = (set(value) if op == "=" else
                              previous | set(value) if op == "+" else previous - set(value))
        name = os.path.basename(path)
        allowed = DANGEROUS if INTERPRETER.fullmatch(name) else DAC if name in {"cp", "dd", "tar"} else set()
        caps = sorted(cap for cap in allowed if flags.get(cap, set()) & {"e", "p"})
        if not caps:
            continue
        try:
            if stat.S_ISREG(os.stat(path).st_mode) and _access(path, os.X_OK):
                rootid = re.search(r"\[rootid=(\d+)\]$", line)
                context = {"summary": "Executable with permitted/effective capabilities; namespace/bounding policy unverified",
                           "evidence": [path, ", ".join(cap + "=" + ''.join(c for c in 'eip' if c in flags[cap]) for cap in caps)]
                           + ([rootid[0]] if rootid else [])}
                if context not in contexts:
                    contexts.append(context)
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                gaps.append("Cannot inspect capability path: " + path)
    if affirmative and not any(bodies):
        gaps.append("Affirmative sec010 had no capability body")
    return _result("capabilities", contexts, gaps, raw_lse)


def inspect_runtime_sockets(paths=None, *, run_root="/run", traverse=False,
                            max_entries=2048, max_depth=4):
    """Inspect socket ownership/access only; traversal never follows directories' links."""
    if os.geteuid() == 0:
        return _result("runtime-sockets", gaps=["Root cannot assess unprivileged permissions"])
    paths = list(paths if paths is not None else
                 [os.path.join(run_root, p) for p in RUNTIME_PATHS] + list(LXD_PATHS))
    gaps, contexts = [], []
    if traverse:
        stack, count = [(os.fspath(run_root), 0)], 0
        names = {os.path.basename(p) for p in RUNTIME_PATHS}
        while stack:
            directory, depth = stack.pop()
            try:
                if not stat.S_ISDIR(os.lstat(directory).st_mode):
                    continue
                with os.scandir(directory) as entries:
                    for entry in entries:
                        count += 1
                        if count > max_entries:
                            gaps.append("Runtime traversal entry limit reached")
                            stack.clear()
                            break
                        if entry.is_dir(follow_symlinks=False):
                            if depth < max_depth:
                                stack.append((entry.path, depth + 1))
                            else:
                                gaps.append("Runtime traversal depth limit reached")
                        elif entry.name in names and (entry.name != "unix.socket" or os.path.basename(directory) == "lxd"):
                            paths.append(entry.path)
            except OSError as exc:
                if exc.errno != errno.ENOENT:
                    gaps.append("Cannot inspect runtime directory: " + directory)
    for path in sorted(set(map(os.fspath, paths))):
        try:
            metadata = os.stat(path)
            if stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == 0 and _access(path, os.W_OK):
                contexts.append({"summary": "Write permission does NOT prove API authorization or daemon mode",
                                 "evidence": [path, "root-owned socket; permissions " + stat.filemode(metadata.st_mode)]})
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                gaps.append("Cannot inspect runtime socket: " + path)
    return _result("runtime-sockets", contexts, gaps)


def inspect_loader(conf="/etc/ld.so.conf", preload="/etc/ld.so.preload", *,
                   max_files=64, max_depth=8, max_glob_entries=2048, read_limit=READ_LIMIT):
    """Bounded config parsing; findings retain paths/metadata, never file contents."""
    if os.geteuid() == 0:
        return _result("loader", gaps=["Root cannot assess unprivileged permissions"])
    uid, gaps, contexts, seen = os.geteuid(), [], [], set()
    read_limit = min(READ_LIMIT, max(0, read_limit))
    glob_count = read_count = 0

    def metadata(path, follow=True):
        try:
            return os.stat(path) if follow else os.lstat(path)
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                gaps.append("Cannot inspect loader path: " + path)

    def record(path, reason):
        context = {"summary": reason + "; permission metadata only, not validated exploitation",
                   "evidence": [path]}
        if context not in contexts:
            contexts.append(context)

    def writable(path, reason):
        # Do not lexically collapse '..' before symlink resolution: the kernel
        # interprets link/../child relative to the link's real target.
        path = os.fspath(path)
        if not os.path.isabs(path):
            path = os.path.join(os.getcwd(), path)
        target = metadata(path)
        if target and (stat.S_ISREG(target.st_mode) or stat.S_ISDIR(target.st_mode)):
            mode = os.W_OK | (os.X_OK if stat.S_ISDIR(target.st_mode) else 0)
            if _access(path, mode):
                record(path, reason)
        real = os.path.realpath(path)
        if real != path:
            writable(real, reason)
        # A writable ancestor can replace a non-writable child. Sticky parents
        # only allow replacement of entries owned by us (or the directory owner).
        while path != os.path.dirname(path):
            parent = os.path.dirname(path)
            owner, entry = metadata(parent), metadata(path, follow=False)
            if owner and stat.S_ISDIR(owner.st_mode) and _access(parent, os.W_OK | os.X_OK):
                if not owner.st_mode & stat.S_ISVTX or owner.st_uid == uid or (entry and entry.st_uid == uid):
                    record(parent, "Replaceable loader path parent")
            path = parent

    def read(path):
        nonlocal read_count
        if metadata(path) is None:
            return None  # Missing optional configs are normal, even at the read limit.
        if read_count >= max_files:
            gaps.append("Loader configuration file limit reached")
            return None
        read_count += 1
        writable(path, "Writable loader configuration")
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    gaps.append("Non-regular loader configuration: " + path)
                    return None
                with os.fdopen(fd, "rb", closefd=False) as stream:
                    data = stream.read(read_limit + 1)
                if len(data) > read_limit:
                    gaps.append("Loader configuration read limit reached: " + path)
                    return None
                return data.decode("utf-8", "replace")
            finally:
                os.close(fd)
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                gaps.append("Cannot read loader configuration: " + path)

    def expand(pattern):
        # Bounded component-wise globbing: glob.glob silently hides access errors
        # and can materialize an unbounded directory before yielding a match.
        nonlocal glob_count
        if glob_count > max_glob_entries:
            return []
        candidates = [os.path.sep]
        pattern = pattern if os.path.isabs(pattern) else os.path.join(os.getcwd(), pattern)
        components = pattern.split(os.path.sep)[1:]
        for index, component in enumerate(components):
            next_paths = []
            for base in candidates:
                glob_count += 1
                if glob_count > max_glob_entries:
                    gaps.append("Loader include glob limit reached")
                    return []
                if index == len(components) - 1:
                    writable(base, "Writable included configuration directory")
                if not any(c in component for c in "*?["):
                    next_paths.append(os.path.join(base, component))
                    continue
                try:
                    with os.scandir(base) as entries:
                        for entry in entries:
                            glob_count += 1
                            if glob_count > max_glob_entries:
                                gaps.append("Loader include glob limit reached")
                                return []
                            if fnmatch.fnmatchcase(entry.name, component) and (not entry.name.startswith(".") or component.startswith(".")):
                                next_paths.append(entry.path)
                except OSError as exc:
                    if exc.errno != errno.ENOENT:
                        gaps.append("Cannot expand loader include: " + base)
            candidates = next_paths
        return candidates

    def visit(path, depth):
        path = path if os.path.isabs(path) else os.path.join(os.getcwd(), path)
        real = os.path.realpath(path)
        if real in seen:
            return
        if depth > max_depth or len(seen) >= max_files:
            gaps.append("Loader configuration file/depth limit reached")
            return
        seen.add(real)
        text = read(path)
        if text is None:
            return
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            if '\0' in line:
                gaps.append('Invalid NUL in loader configuration path')
                continue
            if line.split()[0] == "include":
                for pattern in line.split()[1:]:
                    pattern = pattern if os.path.isabs(pattern) else os.path.join(os.path.dirname(path), pattern)
                    for included in expand(pattern):
                        visit(included, depth + 1)
            elif os.path.isabs(line):
                writable(line, "Writable library search directory")
            else:
                gaps.append('Relative library search directory cannot be resolved passively')

    visit(os.fspath(conf), 0)
    preload = os.fspath(preload)
    text = read(preload if os.path.isabs(preload) else os.path.join(os.getcwd(), preload))
    if text is not None:
        for token in re.split(r"[\s:]+", "\n".join(line.split("#", 1)[0] for line in text.splitlines())):
            if token:
                if '\0' in token:
                    gaps.append('Invalid NUL in preload library path')
                elif os.path.isabs(token):
                    writable(token, "Writable preload library")
                else:
                    gaps.append("Relative preload library cannot be resolved passively")
    return _result("loader", contexts, gaps)


def inspect_sudo():
    """List policy only; classify narrow unrestricted rules, not arbitrary sudo syntax."""
    import pwd
    import subprocess

    result = {'findings': [], 'raw': '', 'errors': []}
    test_id = 'extra-sudo'

    def gap(message):
        result['incomplete_ids'] = [test_id]
        result['findings'].append({'id': 'scanner-' + test_id, 'severity': 'warning',
                                   'summary': 'Sudo rule coverage incomplete',
                                   'context': [{'summary': 'Coverage gap', 'evidence': [message]}]})
        return result

    if os.geteuid() == 0:
        return gap('run as an unprivileged account')
    binary = next((p for p in ('/usr/bin/sudo', '/bin/sudo') if _access(p, os.X_OK)), None)
    if not binary:
        return gap('sudo is unavailable')
    try:
        command = subprocess.run([binary, '-n', '-l'], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, timeout=10, check=False,
                                 env=dict(os.environ, LC_ALL='C', LANG='C',
                                          PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'))
    except (OSError, subprocess.TimeoutExpired) as exc:
        return gap(str(exc))
    result['raw'] = 'sudo -n -l:\n' + command.stdout + command.stderr
    if command.returncode:
        return gap('noninteractive listing refused/failed; no delegated commands executed')
    try:
        account = pwd.getpwuid(os.geteuid()).pw_name
    except KeyError:
        account = None
    policy, rows = command.stdout, []
    secure = re.search(r'\bsecure_path\s*=\s*(?:"([^"]*)"|([^,\s]+))', policy)
    if secure:
        for entry in (secure[1] if secure[1] is not None else secure[2]).split(':'):
            if entry.startswith('/') and os.path.isdir(entry) and _access(entry, os.W_OK | os.X_OK):
                rows.append('Writable sudo secure_path directory: ' + entry)
    # Only complete single-line rules qualify; wrapped/complex rules need manual review.
    lines = policy.splitlines()
    # A later matching negation can override a grant. Without a full policy
    # evaluator, do not classify command grants when any explicit denial exists.
    restricted = bool(re.search(r'\)\s*.*(?:^|[\s,:])!/', policy, re.M))
    for index, line in enumerate(lines):
        rule = re.fullmatch(r'\s*\(([^)]+)\)\s*(?:(?:NO)?PASSWD:\s*)?(/[^\s,]+|ALL)\s*', line)
        continuation = lines[index + 1] if index + 1 < len(lines) else ''
        if not rule or (continuation[:1].isspace() and continuation.strip() and not continuation.lstrip().startswith('(')):
            continue
        runas, executable = rule.groups()
        users = {user.strip() for user in runas.split(':', 1)[0].split(',')}
        if users.intersection({'!root', '!#0'}) or not users.intersection({'root', '#0', 'ALL'}):
            continue
        if executable == 'ALL':
            # sud000 already covers ordinary NOPASSWD ALL; oski's grant is expected.
            if not restricted and account != 'oski' and 'NOPASSWD:' not in line:
                rows.append('Root sudo policy allows all commands (authentication may still be required)')
            continue
        if not restricted and INTERPRETER.fullmatch(os.path.basename(executable)):
            rows.append('Root sudo rule permits an unrestricted interpreter; authentication/policy still applies: ' + line.strip())
    if rows:
        result['findings'].append({'id': test_id, 'severity': 'warning',
                                   'summary': 'Root-capable sudo policy needs review',
                                   'context': sorted(set(rows))})
    return result


def inspect_process_capabilities(proc='/proc', parent=None):
    """Current/parent effective and ambient sets; never infer privilege from CapBnd."""
    if os.geteuid() == 0:
        return _result('process-capabilities', gaps=['Root capability sets are expected, not unprivileged escalation'])
    contexts, gaps = [], []
    bits = {0: 'cap_chown', 1: 'cap_dac_override', 2: 'cap_dac_read_search',
            3: 'cap_fowner', 6: 'cap_setgid', 7: 'cap_setuid', 8: 'cap_setpcap',
            16: 'cap_sys_module', 17: 'cap_sys_rawio', 19: 'cap_sys_ptrace',
            21: 'cap_sys_admin', 31: 'cap_setfcap', 39: 'cap_bpf', 40: 'cap_checkpoint_restore'}
    for label, name in (('Current process', 'self'), ('Parent process', str(os.getppid() if parent is None else parent))):
        try:
            text = _read_regular(os.path.join(proc, name, 'status'))
            uid = re.search(r'^Uid:\s+\d+\s+(\d+)\s+\d+\s+\d+\s*$', text, re.M)
            if not uid:
                raise ValueError('missing effective UID')
            if int(uid[1]) != os.geteuid():
                continue
            for field in ('CapEff', 'CapAmb'):
                value = re.search(r'^' + field + r':\s+([0-9a-fA-F]{1,16})\s*$', text, re.M)
                if not value:
                    raise ValueError('missing/malformed ' + field)
                mask = int(value[1], 16)
                dangerous = [cap for bit, cap in bits.items() if mask & (1 << bit)]
                if dangerous:
                    contexts.append({'summary': label + ' has dangerous ' + field + '; namespace/LSM constraints unverified',
                                     'evidence': sorted(dangerous)})
        except (OSError, ValueError) as exc:
            gaps.append(label + ' capability metadata unavailable: ' + str(exc))
    return _result('process-capabilities', contexts, gaps)


def inspect_sgid(directories=None, *, max_entries=20000, max_depth=16):
    """Bounded SGID check; no malformed upstream dependency and no binaries executed."""
    if os.geteuid() == 0:
        return _result('sgid', gaps=['Root cannot assess unprivileged permissions'])
    directories = directories if directories is not None else ('/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/local', '/opt')
    contexts, gaps, seen = [], [], set()
    stack = [(os.path.realpath(path), 0) for path in directories]
    groups = {os.getegid(), *os.getgroups()}
    count = 0
    while stack:
        directory, depth = stack.pop()
        if directory in seen:
            continue
        seen.add(directory)
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    count += 1
                    if count > max_entries:
                        gaps.append('SGID traversal entry limit reached')
                        stack.clear()
                        break
                    try:
                        metadata = entry.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    except OSError:
                        gaps.append('SGID entry metadata unavailable')
                        continue
                    if stat.S_ISDIR(metadata.st_mode):
                        if depth < max_depth:
                            stack.append((entry.path, depth + 1))
                        else:
                            gaps.append('SGID traversal depth limit reached')
                        continue
                    if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & stat.S_ISGID or not _access(entry.path, os.X_OK):
                        continue
                    if metadata.st_gid in groups:
                        continue
                    reasons = []
                    if _access(entry.path, os.W_OK):
                        reasons.append('Writable SGID executable')
                    if INTERPRETER.fullmatch(entry.name):
                        reasons.append('SGID interpreter; whether it retains group privilege is unverified')
                    if reasons:
                        contexts.append({'summary': '; '.join(reasons) + '; review group access, writes may clear SGID',
                                         'evidence': [entry.path, 'target GID=' + str(metadata.st_gid)]})
        except FileNotFoundError:
            continue
        except OSError:
            gaps.append('SGID traversal inaccessible directory')
    return _result('sgid', contexts, gaps)


def inspect_doas(conf='/etc/doas.conf', binaries=('/usr/bin/doas', '/usr/local/bin/doas'),
                 commands=('/bin/sh', '/usr/bin/python3')):
    """Native -C configuration-only matching honors doas rule order; no command runs."""
    import subprocess

    if os.geteuid() == 0:
        return _result('doas', gaps=['Root cannot assess unprivileged delegation'])
    contexts, gaps = [], []
    binary = None
    for candidate in binaries:
        try:
            metadata = os.stat(candidate)
            if stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0 and metadata.st_mode & stat.S_ISUID and _access(candidate, os.X_OK):
                binary = candidate
                break
        except FileNotFoundError:
            continue
        except OSError:
            gaps.append('Cannot inspect doas privilege metadata')
    if not binary:
        return _result('doas', gaps=gaps)
    try:
        metadata = os.stat(conf)
    except FileNotFoundError:
        return _result('doas', gaps=gaps)
    except OSError:
        return _result('doas', gaps=gaps + ['Cannot inspect doas configuration'])
    if not stat.S_ISREG(metadata.st_mode):
        return _result('doas', gaps=gaps + ['Non-regular doas configuration'])
    if _access(conf, os.W_OK):
        contexts.append({'summary': 'Writable configuration for root-setuid doas; runtime permission checks still apply', 'evidence': [os.fspath(conf)]})
    if metadata.st_uid != 0 or metadata.st_mode & 0o022 or metadata.st_size > READ_LIMIT:
        return _result('doas', contexts, gaps + ['Untrusted/oversized doas configuration; -C does not enforce runtime ownership/mode checks'])
    probes = []
    for command in commands:
        try:
            metadata = os.stat(command)
            # Root may execute a file that the invoking account cannot. Native
            # matching distinguishes literal basename rules from absolute paths.
            if stat.S_ISREG(metadata.st_mode) and metadata.st_mode & 0o111:
                probes.extend((os.fspath(command), os.path.basename(command)))
        except FileNotFoundError:
            continue
        except OSError:
            gaps.append('Cannot inspect doas interpreter metadata')
    if not probes:
        gaps.append('No root interpreter policy probes could be assessed')
    for command in dict.fromkeys(probes):
        try:
            response = subprocess.run([binary, '-C', os.fspath(conf), '-u', 'root', command],
                                      stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      text=True, timeout=5, check=False,
                                      env=dict(os.environ, LC_ALL='C', LANG='C',
                                               PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'))
            verdict = response.stdout.strip()
            if verdict == 'deny' and response.returncode in (0, 1):
                continue  # OpenDoas returns 1 for a valid policy denial in -C mode.
            if response.returncode != 0 or verdict not in ('permit', 'permit nopass'):
                gaps.append('doas -C policy could not be assessed (unsupported, inaccessible or invalid configuration)')
            else:
                contexts.append({'summary': 'doas policy permits a root interpreter with no arguments; configuration-only check',
                                 'evidence': [os.fspath(command), verdict + '; authentication may still be required']})
        except (OSError, subprocess.TimeoutExpired):
            gaps.append('doas -C policy check failed or timed out')
    return _result('doas', contexts, gaps)


def scan(raw_lse, capability_status=None):
    """Aggregate independently, keeping one failed check's coverage gap local."""
    result = {"findings": [], "raw": "", "errors": []}
    for name, check in (
            ('capabilities', lambda: inspect_capabilities(raw_lse, capability_status)),
            ('runtime-sockets', inspect_runtime_sockets), ('loader', inspect_loader), ('sudo', inspect_sudo),
            ('process-capabilities', inspect_process_capabilities), ('sgid', inspect_sgid), ('doas', inspect_doas)):
        try:
            part = check()
        except (OSError, ValueError, RuntimeError) as exc:
            part = _result(name, gaps=['Check failed: ' + str(exc)])
        result["findings"].extend(part["findings"])
        result["errors"].extend(part["errors"])
        if part.get('raw') and part['raw'] != raw_lse:
            result['raw'] += part['raw'] + '\n'
        if part.get("incomplete_ids"):
            result.setdefault("incomplete_ids", []).extend(part["incomplete_ids"])
    if "incomplete_ids" in result:
        result["incomplete_ids"] = sorted(set(result["incomplete_ids"]))
    return result
