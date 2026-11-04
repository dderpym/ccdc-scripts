#!/usr/bin/env python3
"""Read-only package integrity and bounded critical-path metadata discovery.

Stdlib, no saved baselines, repairs, installs, or general filesystem hashing.
Normal APK scans use --system plus a bounded /etc protected-config pass.
--deep enables added-file auditing; normal scans never use --full/--details.
Native verification can be expensive: each verifier gets 300 seconds, queries 30.
Package databases are evidence, not a trusted root or proof of compromise.

Formats/safety researched against upstream:
https://rpm.org/docs/latest/man/rpm.8 (verify output, --noscripts)
https://man7.org/linux/man-pages/man1/dpkg.1.html (--verify-format rpm)
https://github.com/alpinelinux/apk-tools/blob/master/src/app_audit.c
https://github.com/alpinelinux/apk-tools/blob/master/src/database.c
https://github.com/void-linux/xbps/tree/master/bin/xbps-pkgdb
https://github.com/void-linux/xbps/blob/master/lib/pkgdb.c
XBPS checks can flush/convert the database even with --checks files. Run only
against a temporary copy of its metadata in a PRIVATE mount namespace. This
preserves native symlink semantics, unlike a symlink-mirrored alternate root.
Without Linux mount-namespace privileges or --checks, XBPS is safely refused.
"""
import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

CRITICAL = (
    '/etc/passwd', '/etc/group', '/etc/shadow', '/etc/gshadow', '/etc/sudoers',
    '/etc/sudoers.d', '/etc/ssh', '/etc/ssh/sshd_config', '/etc/ssh/sshd_config.d', '/root/.ssh',
    '/etc/pam.d', '/etc/ld.so.preload', '/etc/crontab', '/etc/cron.d',
    '/etc/init.d', '/etc/rc.local', '/etc/inittab', '/bin/sh', '/bin/bash',
    '/bin/dash', '/bin/ash', '/usr/bin/sudo', '/usr/bin/doas', '/usr/bin/su',
    '/usr/sbin/sshd', '/usr/bin/ssh', '/usr/bin/python', '/usr/bin/python3', '/sbin/init',
)
PACKAGE_TOOLS = ('apk', 'rpm', 'dpkg', 'dpkg-query', 'apt', 'apt-get', 'dnf', 'yum',
                 'xbps-pkgdb', 'xbps-query', 'xbps-install', 'systemctl', 'systemd',
                 'rc-service', 'rc-status', 'sv', 'runsv')
SECURITY_CONFIG = ('/etc/ssh', '/etc/sudoers', '/etc/sudoers.d', '/etc/passwd',
                   '/etc/group', '/etc/shadow', '/etc/gshadow', '/etc/pam.d',
                   '/etc/ld.so.preload', '/etc/crontab', '/etc/cron.d', '/etc/inittab')
DATABASES = (('apk', '/lib/apk/db/installed'), ('rpm', '/var/lib/rpm'),
             ('rpm', '/usr/lib/sysimage/rpm'), ('dpkg', '/var/lib/dpkg/status'),
             ('xbps', '/var/db/xbps'))
MAX_CHILDREN = 128
MAX_METADATA = 2048
CRITICAL_DIRS = {'/etc/sudoers.d', '/etc/ssh', '/etc/ssh/sshd_config.d', '/root/.ssh',
                 '/etc/pam.d', '/etc/cron.d', '/etc/init.d'}


def document():
    return {'findings': [], 'raw': '', 'metadata': [], 'errors': []}


def finding(result, source, path, severity, summary, **extra):
    # Stable condition identity: a changed observation must not falsely resolve
    # and recreate the same tampered path. APK codes distinguish independent checks.
    identity = json.dumps([source, path, extra.get('code'),
                           summary if source == 'scanner' or extra.get('scanner_error') else None], sort_keys=True)
    row = {'id': source + '-' + hashlib.sha256(identity.encode()).hexdigest()[:16],
           'path': path or '', 'severity': severity, 'summary': summary, 'source': source}
    row.update(extra)
    if not any(old['id'] == row['id'] for old in result['findings']):
        result['findings'].append(row)


def warning(result, message, path=None, source='scanner'):
    finding(result, source, path, 'warning', message, scanner_error=True)
    result['errors'].append(source + (': ' + path if path else '') + ': ' + message)


def text(value):
    return value.decode('utf-8', 'replace') if isinstance(value, bytes) else (value or '')


def run(result, argv, timeout=30, preexec_fn=None, accepted=(0,)):
    """Keep both streams and partial timeout output; never shell out or raise away findings."""
    env = dict(os.environ, LC_ALL='C', LANG='C', DPKG_COLORS='never')
    # Host inspection, not an inherited frontend's alternate installation root.
    for key in ('DPKG_ROOT', 'DPKG_ADMINDIR'):
        env.pop(key, None)
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True, errors='replace', env=env,
                              timeout=timeout, preexec_fn=preexec_fn)
        out, err, code = proc.stdout, proc.stderr, proc.returncode
        if code not in accepted:
            warning(result, 'Command returned %s (incomplete scan): %s' %
                    (code, ' '.join(argv)))
    except subprocess.TimeoutExpired as exc:
        out, err, code = text(exc.stdout), text(exc.stderr), None
        warning(result, 'Command timed out after %ss: %s' % (timeout, ' '.join(argv)))
    except (OSError, subprocess.SubprocessError) as exc:
        out, err, code = '', str(exc), None
        warning(result, 'Cannot execute %s: %s' % (argv[0], exc))
    result['raw'] += '$ ' + ' '.join(argv) + '\nstdout:\n' + out + '\nstderr:\n' + err + '\n'
    return out, err, code


def critical_path(path):
    return (path in CRITICAL or
            any(path.startswith(p + '/') for p in CRITICAL) or
            path.startswith(('/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/')) or
            bool(re.search(r'/(?:lib|lib64)/.*(?:\.so(?:\.|$)|/systemd$|/init$)', path)))


def severity(path, changes, config=False, result=None):
    if changes in ('error', 'unreadable'):
        return 'warning'
    if changes in ('added', 'time'):
        return 'review'
    if changes in ('content', 'missing') and path.startswith(('/usr/share/doc/', '/usr/share/man/', '/usr/share/info/', '/usr/share/locale/')):
        return 'review'  # Keep stripped/changed ordinary data visible, below executable tampering.
    executable_config = path.startswith('/etc/init.d/') or path == '/etc/rc.local'
    if (config or path.startswith('/etc/')) and changes == 'content' and not executable_config:
        sensitive = any(path.rstrip('/') == p or path.startswith(p + '/') for p in SECURITY_CONFIG)
        return 'warning' if sensitive else 'review'
    selected = result and any(row['path'] == path for row in result['metadata'])
    return 'critical' if critical_path(path) or selected else 'warning'


def parse_apk(result, output, include_added=False):
    reasons = {'U': ('content', 'Package file content changed'),
               'M': ('metadata', 'Package file ownership or mode changed'),
               'm': ('metadata', 'Package directory ownership or mode changed'),
               'X': ('missing', 'Package file missing'),
               'x': ('metadata', 'Package extended attributes changed'),
               'A': ('added', 'File added'), 'd': ('added', 'Directory added'),
               'D': ('added', 'Directory added (contents not enumerated)'),
               'e': ('error', 'Unable to audit package path')}
    for line in output.splitlines():
        if not line.strip():
            continue
        match = re.match(r'^([UMmXxAdDe]) (.+)$', line)
        if not match:
            warning(result, 'Unrecognized APK diagnostic: ' + line, source='apk')
            continue
        code, path = match.groups()
        if code in ('A', 'd', 'D') and not include_added:
            continue  # Protected config auditing can mention unrelated added files.
        path = '/' + path.lstrip('/')  # APK prints root-relative paths.
        change, summary = reasons[code]
        priority = 'critical' if code == 'x' else 'warning' if code == 'm' else severity(path, change, path.startswith('/etc/'), result)
        finding(result, 'apk', path, priority,
                summary, code=code, diagnostic=line)
        if code == 'e':
            warning(result, 'APK could not verify path', path, 'apk')


def parse_rpm(result, output, source='rpm'):
    # dpkg uses '?' for unsupported checks; do not mistake these for failures.
    names = ('size', 'mode/type', 'digest', 'device', 'symlink', 'uid', 'gid', 'mtime', 'capabilities')
    for line in output.splitlines():
        if not line.strip():
            continue
        match = re.match(r'^(missing\s+|[.SM5DLUGTP?]{9}\s+)(?:([acdglmnrs])\s+)?(/.*)$', line)
        if not match:
            warning(result, 'Unrecognized %s diagnostic: %s' % (source, line), source=source)
            continue
        flags, attr, path = match.groups()
        flags = flags.strip()
        if flags == 'missing':
            error = re.search(r' \(([^()]*)\)$', path) if source == 'dpkg' else None
            if error:
                path = path[:error.start()]
            changes = ['missing']
            kind = 'missing'
        else:
            changes = [name for flag, name in zip(flags, names) if flag not in '.?']
            if source == 'rpm' and '?' in flags:
                warning(result, 'RPM could not perform one or more file checks', path, source)
            if not changes:
                continue
            kind = 'time' if changes == ['mtime'] else 'content' if set(changes) <= {'digest', 'size', 'mtime'} else 'metadata'
        finding(result, source, path, severity(path, kind, attr in ('c', 'n'), result),
                'Package verification: ' + ', '.join(changes), checks=changes,
                flags=flags, attribute=attr, diagnostic=line)


def parse_xbps(result, output):
    for line in output.splitlines():
        if not line.strip():
            continue
        line = re.sub(r'^(?:ERROR|WARNING):\s*', '', line)
        match = re.match(r'^(\S+): (?:hash mismatch for|unexistent file) (.+?)(?:\.)?$', line)
        kind = 'content' if ': hash mismatch for ' in line else 'missing'
        if not match:
            match = re.match(r'^(\S+): (?:broken symlink (.+?) \(target: .*\)|modified symlink (.+?) points to .* \(shall be .*\))$', line)
            kind = 'metadata'
        if match:
            package = match.group(1)
            path = next(p for p in match.groups()[1:] if p is not None)
            path = '/' + path.lstrip('/')
            finding(result, 'xbps', path, severity(path, kind, result=result), 'Package verification: ' + line,
                    package=package, diagnostic=line)
        elif re.match(r"^\S+: can't check `(.+)' \(.*\)$", line):
            path = re.match(r"^\S+: can't check `(.+)' \(.*\)$", line).group(1)
            warning(result, 'XBPS could not verify path: ' + line, '/' + path.lstrip('/'), 'xbps')
        elif re.match(r'^\S+: (?:conf files|files) check FAILED\.$', line):
            continue  # Aggregate failure already represented by individual records.
        else:
            warning(result, 'XBPS diagnostic: ' + line, source='xbps')


def parse_apk_database(output, paths):
    """APK v2 installed F/M/R/a records; file default ACL is root:root:0644."""
    expected, directory, path, package = {}, '', None, None
    for line in output.splitlines():
        key, sep, value = line.partition(':')
        if not sep:
            directory, path = '', None
        elif key == 'P':
            package = value
        elif key == 'F':
            directory = '/' + value.lstrip('/')
            path = directory
            if path in paths and path not in expected:
                expected[path] = {'uid': 0, 'gid': 0, 'mode': 0o755, 'source': 'apk', 'package': package}
        elif key == 'R':
            path = directory.rstrip('/') + '/' + value
            if path in paths:
                expected[path] = {'uid': 0, 'gid': 0, 'mode': 0o644, 'source': 'apk', 'package': package}
        elif key in ('M', 'a') and path in paths:
            uid, gid, mode = value.split(':')[:3]
            expected[path] = {'uid': int(uid), 'gid': int(gid), 'mode': int(mode, 8),
                              'source': 'apk', 'package': package}
    return expected


def read_metadata(path, limit=64 * 1024 * 1024):
    fd = os.open(str(path), os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError('Not bounded regular metadata: ' + str(path))
        data = handle.read(limit + 1)
        if len(data) > limit:
            raise ValueError('Metadata read limit reached: ' + str(path))
    return data.decode('utf-8', 'replace')


def accounts():
    maps = []
    for path in ('/etc/passwd', '/etc/group'):
        rows = read_metadata(path).splitlines()
        maps.append({p[0]: int(p[2]) for p in (r.split(':') for r in rows)
                     if len(p) > 2 and p[2].isdigit()})
    return maps


def numeric(value, names):
    # Linux root is UID/GID 0 even if a compromised passwd/group entry says otherwise.
    if value == 'root':
        return 0
    return int(value.lstrip('#')) if value.lstrip('#').isdigit() else names.get(value)


def parse_overrides(output, paths, users, groups):
    expected = {}
    for line in output.splitlines():
        if not line.strip():
            continue
        user, group, mode, path = line.split(None, 3)
        if path in paths:
            expected[path] = {'uid': numeric(user, users), 'gid': numeric(group, groups),
                              'mode': int(mode, 8), 'source': 'dpkg-statoverride'}
    return expected


def parse_rpm_metadata(output, paths, users, groups):
    expected = {}
    for line in output.splitlines():
        fields = line.split('\t')
        if len(fields) != 5:
            raise ValueError('Unexpected RPM metadata record: ' + line)
        path, mode, user, group, target = fields
        if path in paths:
            fullmode = int(mode)
            expected[path] = {'uid': numeric(user, users), 'gid': numeric(group, groups),
                              'mode': stat.S_IMODE(fullmode), 'type': stat.S_IFMT(fullmode),
                              'symlink': target or None, 'source': 'rpm'}
    return expected


def file_metadata(path):
    info = os.lstat(path)
    kind = stat.S_IFMT(info.st_mode)
    return {'path': path, 'uid': info.st_uid, 'gid': info.st_gid,
            'mode': stat.S_IMODE(info.st_mode), 'type': kind,
            'symlink': os.readlink(path) if stat.S_ISLNK(info.st_mode) else None}


def plan_fix(row, expected, changes, checks):
    """Absolute target mode/owner that resolves the fixable part of a finding.

    'simple' fixes change only the mode; ownership changes are tier 'all'.
    """
    if row['type'] not in (stat.S_IFREG, stat.S_IFDIR) or {'type', 'symlink'} & set(changes):
        return None
    target = {key: row[key] for key in ('mode', 'uid', 'gid')}
    for key in changes:
        if key in target:
            target[key] = expected[key]
    if any('writable' in check for check in checks):
        target['mode'] &= ~0o022
    if 'secret accessible to other users' in checks:
        target['mode'] &= ~0o007
    if any(check.startswith('not root-owned') for check in checks):
        target['uid'] = 0
    if all(target[key] == row[key] for key in target):
        return None
    return dict(path=row['path'], **target, was={key: row[key] for key in target},
                tier='simple' if (target['uid'], target['gid']) == (row['uid'], row['gid']) else 'all')


def security_checks(result, row, expected=None, secret=False):
    path = row['path']
    changes = []
    if expected:
        row['expected'] = expected
        changes = [key for key in ('uid', 'gid', 'mode', 'type', 'symlink')
                   if key in expected and expected[key] is not None and row[key] != expected[key]]
    # Explicit conservative security policy, NOT exact "default" permissions.
    # Group IDs vary (shadow, wheel, root); no blanket gid==0 expectation.
    # Symlink 0777 is normal; evaluate ownership and then its referent instead.
    checks = []
    if (not expected or expected.get('uid') is None) and row['uid'] != 0:
        checks.append('not root-owned (no distro ownership available)')
    if row['type'] != stat.S_IFLNK:
        if row['mode'] & 0o022:
            checks.append('group/other writable')
        if row['type'] not in (stat.S_IFREG, stat.S_IFDIR):
            checks.append('unexpected special file type')
        origin = row.get('origin', path)
        if row.get('role', 'critical') != 'parent' and origin in CRITICAL:
            required = stat.S_IFDIR if origin in CRITICAL_DIRS else stat.S_IFREG
            if row['type'] != required and (not expected or 'type' not in expected):
                checks.append('unexpected critical path type')
        if secret and row['type'] != stat.S_IFDIR and row['mode'] & 0o007:
            checks.append('secret accessible to other users')
    fix = plan_fix(row, expected, changes, checks)
    extra = {'fix': fix} if fix else {}
    if changes:
        def display(values):
            return {key: format(values[key], '04o') if key == 'mode' else values[key] for key in changes}
        finding(result, 'metadata', path, 'critical',
                'Critical path differs from distro metadata: ' + ', '.join(changes), checks=changes,
                expected=display(expected), observed=display(row), **extra)
    row['policy'] = 'root-owned; no group/other writes; regular file/directory or secure symlink; secrets not accessible to others'
    if checks:
        finding(result, 'policy', path, 'critical', 'Critical-path security policy: ' + ', '.join(checks), checks=checks, **extra)


def critical_paths(result):
    paths = set(CRITICAL)
    for name in PACKAGE_TOOLS:
        tool = shutil.which(name)
        if tool:
            paths.add(os.path.abspath(tool))
    try:
        init = os.readlink('/proc/1/exe')
        if init.endswith(' (deleted)'):
            warning(result, 'Active PID 1 executable is deleted', init)
        elif os.path.isabs(init):
            paths.add(init)
    except OSError as exc:
        warning(result, 'Cannot identify active PID 1 executable: ' + str(exc), '/proc/1/exe')
    for path in CRITICAL:
        if os.path.isdir(path):
            try:
                with os.scandir(path) as entries:
                    children = []
                    for entry in entries:
                        children.append(entry.path)
                        if len(children) > MAX_CHILDREN:
                            warning(result, 'Critical directory enumeration limit reached', path)
                            break
                paths.update(sorted(children)[:MAX_CHILDREN])
            except OSError as exc:
                warning(result, 'Cannot enumerate critical directory: ' + str(exc), path)
    return paths


def collect_metadata(result, paths):
    """Follow each symlink hop and check referents + parents, without recursion."""
    pending = [(p, p, (), 'critical') for p in sorted(paths)]
    seen = set()
    while pending:
        path, origin, chain, role = pending.pop(0)
        if path in seen:
            continue
        if len(seen) >= MAX_METADATA:
            warning(result, 'Critical metadata limit reached')
            break
        seen.add(path)
        try:
            row = file_metadata(path)
        except FileNotFoundError:
            result['metadata'].append({'path': path, 'exists': False, 'origin': origin})
            if path != origin or path in ('/etc/passwd', '/etc/group', '/bin/sh'):
                finding(result, 'metadata', path, 'critical', 'Missing required critical path, symlink referent or parent', origin=origin)
            continue  # Optional distro-specific critical paths may not exist.
        except OSError as exc:
            warning(result, 'Cannot read critical metadata: ' + str(exc), path)
            continue
        row.update(exists=True, origin=origin, role=role)
        result['metadata'].append(row)
        parent = os.path.dirname(path)
        if parent and parent != path:
            pending.append((parent, origin, (), 'parent'))
        if row['symlink'] is not None:
            try:
                os.stat(path)  # Kernel-bounded resolution also catches cycles among already-seen links.
            except FileNotFoundError:
                pass  # The queued referent below records the missing path.
            except OSError as exc:
                message = 'Critical symlink cycle or kernel resolution limit' if exc.errno == errno.ELOOP else 'Cannot resolve critical symlink referent: ' + str(exc)
                warning(result, message, path)
            if len(chain) >= 32:
                warning(result, 'Critical symlink chain limit reached', path)
                continue
            target = row['symlink']
            target = os.path.normpath(target if os.path.isabs(target) else os.path.join(parent, target))
            if target in chain or target == path:
                warning(result, 'Critical symlink cycle', path)
                continue
            # lstat follows intermediate directory links (kernel-limited), and
            # parents above are checked separately. Avoid unbounded realpath.
            pending.append((target, origin, chain + (path,), 'referent'))
    return {r['path'] for r in result['metadata'] if r.get('exists')}


def copy_xbps_metadata(dest, source='/var/db/xbps'):
    """Transient package metadata, not a host baseline. Never copy host DB links."""
    total, count = 0, 0
    for entries, entry in enumerate(Path(source).iterdir(), 1):
        if entries > 20000:
            raise ValueError('XBPS metadata directory entry limit reached')
        if not entry.name.endswith('.plist'):
            continue
        fd = os.open(str(entry), os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ValueError('Refusing non-regular XBPS metadata: ' + str(entry))
            total += info.st_size
            count += 1
            if count > 10000 or total > 128 * 1024 * 1024:
                raise ValueError('XBPS metadata copy limit reached')
            data = handle.read(info.st_size + 1)
            if len(data) != info.st_size:
                raise ValueError('XBPS metadata changed during copy: ' + str(entry))
            (Path(dest) / entry.name).write_bytes(data)
    if not count:
        raise ValueError('No XBPS metadata plists found')


def xbps_namespace(database):
    """Child-only Linux namespace setup. Failure aborts exec, never falls back.

    The script is single-threaded. Load libc before fork; the child makes its
    mounts recursively private BEFORE overlaying the live database location.
    Host file paths (including realpath on relative symlinks) remain unchanged.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    libc.unshare.argtypes = [ctypes.c_int]
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                          ctypes.c_ulong, ctypes.c_void_p]
    source = os.fsencode(database)

    def prepare():
        if libc.unshare(0x00020000) != 0:  # CLONE_NEWNS
            raise OSError(ctypes.get_errno(), 'Cannot isolate XBPS mount namespace')
        if libc.mount(None, b'/', None, (1 << 18) | 16384, None) != 0:  # MS_PRIVATE|MS_REC
            raise OSError(ctypes.get_errno(), 'Cannot make XBPS mounts private')
        if libc.mount(source, b'/var/db/xbps', None, 4096, None) != 0:  # MS_BIND
            raise OSError(ctypes.get_errno(), 'Cannot redirect XBPS package database')
    return prepare


def verify(result, backend, binary, deep):
    if backend == 'apk':
        out, err, code = run(result, [binary, 'audit', '--help'], accepted=(0, 1))
        helptext = out + err
        if code not in (0, 1) or not all(opt in helptext for opt in ('--system', '--check-permissions')):
            warning(result, 'Installed APK lacks required audit options', source='apk')
            return
        commands = [[binary, 'audit', '--system', '--check-permissions']]
        # --system intentionally skips protected config contents. A bounded
        # native /etc pass keeps vendor config differences visible too; ignore
        # added-file codes in this pass, never hash arbitrary files ourselves.
        if '--backup' in helptext:
            commands.append([binary, 'audit', '--backup', '--check-permissions', '/etc'])
        else:
            warning(result, 'Installed APK lacks --backup; protected configuration content coverage is incomplete', source='apk')
        if deep:
            if '--full' in helptext:
                commands.append([binary, 'audit', '--full', '--check-permissions'])
            else:
                warning(result, 'Installed APK lacks --full for deep added-file check', source='apk')
        for argv in commands:
            out, err, code = run(result, argv, 300, accepted=(0, 1))
            if code == 1 and not out.strip():
                warning(result, 'APK failed without verification records', source='apk')
            parse_apk(result, out, include_added='--full' in argv)
            if err.strip():
                warning(result, 'APK stderr: ' + err.strip(), source='apk')
    elif backend in ('rpm', 'dpkg'):
        argv = [binary, '--verify', '--all', '--noscripts'] if backend == 'rpm' else [binary, '--verify', '--verify-format=rpm']
        out, err, code = run(result, argv, 300, accepted=(0, 1))
        if code == 1 and not out.strip():
            warning(result, backend + ' failed without verification records', source=backend)
        parse_rpm(result, out, backend)
        if err.strip():
            warning(result, backend + ' stderr: ' + err.strip(), source=backend)
    elif backend == 'xbps':
        out, err, code = run(result, [binary, '--help'], accepted=(0, 1))
        if code not in (0, 1) or '--checks' not in out + err:
            warning(result, 'Installed XBPS lacks --checks; refusing potentially repairing default check', source='xbps')
            return
        try:
            with tempfile.TemporaryDirectory(prefix='discover-integrity-') as database:
                copy_xbps_metadata(database)
                prepare = xbps_namespace(database)
                out, err, code = run(result, [binary, '--rootdir', '/', '--all', '--checks', 'files'],
                                     300, preexec_fn=prepare, accepted=(0, 1))
                if code is None:
                    warning(result, 'XBPS isolation/execution failed; no live-database fallback', source='xbps')
                elif code == 1 and not (out + err).strip():
                    warning(result, 'XBPS failed without verification records', source='xbps')
                parse_xbps(result, out + '\n' + err)
        except (OSError, ValueError, AttributeError) as exc:
            warning(result, 'Cannot isolate XBPS verifier metadata: ' + str(exc), source='xbps')


def distro_metadata(result, backends, paths):
    expected = {}
    try:
        users, groups = accounts()
    except (OSError, ValueError) as exc:
        warning(result, 'Cannot resolve local package owner IDs: ' + str(exc))
        users, groups = {}, {}
    for backend, binary in backends:
        try:
            if backend == 'apk':
                expected.update(parse_apk_database(read_metadata('/lib/apk/db/installed'), paths))
            elif backend == 'dpkg' and os.path.exists('/var/lib/dpkg/statoverride'):
                expected.update(parse_overrides(read_metadata('/var/lib/dpkg/statoverride'), paths, users, groups))
            elif backend == 'rpm':
                # Query only owners of bounded critical paths, not all file hashes.
                fmt = '[%{FILENAMES}\t%{FILEMODES}\t%{FILEUSERNAME}\t%{FILEGROUPNAME}\t%{FILELINKTOS}\n]'
                out, err, _ = run(result, [binary, '--query', '--file'] + sorted(paths) + ['--queryformat', '%{NAME}\n'], accepted=(0, 1))
                packages = set()
                for name in out.splitlines():
                    if 'is not owned by any package' in name:
                        continue
                    if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+_.-]*', name):
                        packages.add(name)
                    elif name.strip():
                        warning(result, 'Unexpected RPM owner-query output: ' + name, source='rpm')
                errors = err
                if packages:
                    # Query each owning package once, not its complete manifest
                    # again for every critical path belonging to that package.
                    out, err, _ = run(result, [binary, '--query', *sorted(packages), '--queryformat', fmt])
                    expected.update(parse_rpm_metadata(out, paths, users, groups))
                    errors += '\n' + err
                unexpected = '\n'.join(line for line in errors.splitlines() if 'is not owned by any package' not in line)
                if unexpected.strip():
                    warning(result, 'RPM metadata query stderr: ' + unexpected.strip(), source='rpm')
            # dpkg does not store general modes/owners; XBPS file plists store
            # digests/targets, not general numeric ownership. Policy fills gaps.
        except (OSError, ValueError) as exc:
            warning(result, 'Cannot read %s distro metadata: %s' % (backend, exc), source=backend)
    return expected


def discover(deep=False):
    result = document()
    backends = []
    for backend, database in DATABASES:
        if os.path.exists(database) and not any(b == backend for b, _ in backends):
            name = 'xbps-pkgdb' if backend == 'xbps' else backend
            binary = shutil.which(name)
            if binary:
                backends.append((backend, binary))
            else:
                warning(result, 'Package database present but verifier unavailable: ' + name, database)
    if not backends:
        warning(result, 'No supported native package verifier/database found')
    paths = critical_paths(result)
    paths = collect_metadata(result, paths)
    expected = distro_metadata(result, backends, paths)
    for row in result['metadata']:
        if row.get('exists'):
            origin = row['origin']
            secret = origin in ('/etc/shadow', '/etc/gshadow') or origin.endswith(('_key', '.key', '/id_rsa', '/id_ed25519', '/id_ecdsa'))
            security_checks(result, row, expected.get(row['path']), secret)
    for backend, binary in backends:
        try:
            verify(result, backend, binary, deep)
        except (OSError, ValueError) as exc:
            warning(result, 'Verifier failed: ' + str(exc), source=backend)
    result['findings'].sort(key=lambda row: (row['severity'], row['path'] or '', row['id']))
    result['metadata'].sort(key=lambda row: row['path'])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--deep', action='store_true', help='also audit added files with APK --full')
    args = parser.parse_args()
    print(json.dumps(discover(args.deep), sort_keys=True))


if __name__ == '__main__':
    main()
