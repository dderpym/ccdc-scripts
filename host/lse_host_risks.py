"""Passive host review: effective service paths, root processes and secret metadata.

No secret contents, process arguments/environments, socket connections or delegated
execution. Permission candidates are not exploitation proofs (including SUID-file
replacement, which does not preserve privilege). Only scan(deep=True) enumerates
agent directories. Fixture arguments avoid contacting the host service manager.
"""
import contextlib
import errno
import os
from pathlib import Path
import pwd
import re
import selectors
import stat
import subprocess
import time

from host.kernel_risks import read_regular
from host.lse_extras import _access
EXEC = ('ExecStart', 'ExecStartPre', 'ExecStartPost', 'ExecReload', 'ExecStop', 'ExecStopPost')
PROPERTIES = ('User', 'DynamicUser', 'RootDirectory', 'RootImage', *EXEC,
              'FragmentPath', 'DropInPaths', 'WorkingDirectory')
HOST_SECRETS = tuple('/etc/ssh/ssh_host_' + k + '_key' for k in ('rsa', 'ecdsa', 'ed25519', 'dsa')) + (
    '/etc/krb5.keytab', '/var/lib/kubelet/pki/kubelet-client-current.pem',
    *('/etc/kubernetes/' + n + '.conf' for n in
      ('admin', 'super-admin', 'kubelet', 'controller-manager', 'scheduler')))
HOME_SECRETS = ('.netrc', '.git-credentials', '.aws/credentials', '.kube/config',
                '.docker/config.json', '.config/gcloud/application_default_credentials.json')
TOKEN_VARS = ('AWS_WEB_IDENTITY_TOKEN_FILE', 'AZURE_FEDERATED_TOKEN_FILE', 'GOOGLE_APPLICATION_CREDENTIALS')
OUTPUT_LIMIT = 128 * 1024


def _result(name, contexts=(), gaps=(), raw=''):
    test_id = 'extra-' + name
    findings = []
    if contexts:
        findings.append(dict(id=test_id, severity='warning',
                             summary=name + ': permission metadata review candidates, not validated exploitation',
                             context=[dict(summary=reason, evidence=[path]) for path, reason in sorted(set(contexts))]))
    result = dict(findings=findings, raw=raw, errors=[])
    if gaps:
        result['incomplete_ids'] = [test_id]
        findings.append(dict(id='scanner-' + test_id, severity='warning', summary=name + ': coverage incomplete',
                             context=[dict(summary='Coverage gap', evidence=sorted(set(gaps)))]))
    return result


@contextlib.contextmanager
def _elevated():
    """Briefly regain the saved root uid for read-only visibility (stat/readlink).

    discover-lse runs under sudo but drops to the login account with root kept as the
    saved uid. Access *decisions* (os.access) stay unprivileged; only metadata that
    the account cannot see, such as /proc/PID/exe or paths under 0700 homes, is read here.
    """
    ids, gids = os.getresuid(), os.getresgid()
    if ids[2] != 0 or 0 in ids[:2]:
        yield
        return
    os.setresuid(0, 0, 0)
    os.setresgid(0, 0, 0)  # ptrace-style /proc access compares gids too
    try:
        yield
    finally:
        os.setresgid(*gids)
        os.setresuid(*ids)


def _root(name):
    if os.geteuid() == 0:
        return _result(name, gaps=['Root cannot assess unprivileged permissions'])


def _metadata(path, gaps, follow=True, denied_ok=False):
    try:
        with _elevated():
            return os.stat(path) if follow else os.lstat(path)
    except OSError as exc:
        if exc.errno not in (errno.ENOENT, errno.ENOTDIR) + ((errno.EACCES,) if denied_ok else ()):
            gaps.append('Cannot inspect path metadata: ' + os.fspath(path))


def _path_risks(path, reason, contexts, gaps, directory=False):
    # Never abspath/normpath before realpath: link/../file follows the link first.
    if not os.path.isabs(path) or '\0' in path or len(path) > 4096:
        gaps.append('Unresolvable ' + reason)
        return
    target = _metadata(path, gaps)
    if not target:
        gaps.append('Unavailable ' + reason + ': ' + path)
    elif (stat.S_ISDIR(target.st_mode) if directory else stat.S_ISREG(target.st_mode)):
        if _access(path, os.W_OK | (os.X_OK if directory else 0)):
            contexts.append((path, 'Writable ' + reason))
    else:
        gaps.append('Unexpected file type for ' + reason + ': ' + path)
    for candidate in set((path, os.path.realpath(path))):
        for _ in range(128):
            parent = os.path.dirname(candidate)
            if parent == candidate:
                break
            owner, child = _metadata(parent, gaps), _metadata(candidate, gaps, False)
            # '.' and '..' are not replaceable entries. Sticky restricts unlink/rename,
            # not direct file writes. Also inspect the real target's parent chain.
            if (os.path.basename(candidate) not in ('.', '..') and owner and child
                    and stat.S_ISDIR(owner.st_mode) and _access(parent, os.W_OK | os.X_OK)
                    and (not owner.st_mode & stat.S_ISVTX or owner.st_uid == os.geteuid()
                         or child.st_uid == os.geteuid())):
                contexts.append((parent, 'Replaceable parent of ' + reason))
            candidate = parent
        else:
            gaps.append('Path ancestor limit reached')


def _run(argv):
    """Read-only systemctl, bounded pipe output and wall time; no shell or pager."""
    with subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C',
                                                         'SYSTEMD_COLORS': '0'}) as process:
        try:
            data, deadline = bytearray(), time.monotonic() + 2
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('systemctl timeout')
                    for key, _ in selector.select(remaining):
                        chunk = os.read(key.fd, min(8192, OUTPUT_LIMIT + 1 - len(data)))
                        if not chunk:
                            selector.unregister(key.fileobj)
                        data.extend(chunk)
                        if len(data) > OUTPUT_LIMIT:
                            raise ValueError('systemctl output limit reached')
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
            if process.returncode:
                raise OSError('systemctl listing/show failed')
            return data.decode('utf-8', 'surrogateescape')
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


def _trusted_systemctl():
    for path in ('/usr/bin/systemctl', '/bin/systemctl'):
        real = os.path.realpath(path)
        try:
            metadata = os.stat(real)
            if not stat.S_ISREG(metadata.st_mode) or not _access(real, os.X_OK):
                continue
            while True:
                if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                    break
                parent = os.path.dirname(real)
                if parent == real:
                    return path
                real, metadata = parent, os.stat(parent)
        except OSError:
            pass


SYSTEMD_PATH = ('/usr/local/sbin', '/usr/local/bin', '/usr/sbin', '/usr/bin', '/sbin', '/bin')


def _unescape(value, search=False):
    # Native systemd path escaping, not shell quoting or shell tokenization.
    if len(value) > 4096:
        raise ValueError('Systemd path length limit reached')
    data = bytearray()
    while value:
        if value.startswith('\\'):
            if not re.match(r'^\\x[0-9a-fA-F]{2}', value):
                raise ValueError('Unknown systemd path escape')
            data.append(int(value[2:4], 16))
            value = value[4:]
        else:
            data.extend(value[0].encode('utf-8', 'surrogateescape'))
            value = value[1:]
    path = os.fsdecode(bytes(data))
    if search and path and '/' not in path and '\0' not in path:
        # systemd resolves a bare Exec name through its built-in search path.
        found = [d + '/' + path for d in SYSTEMD_PATH if os.path.lexists(d + '/' + path)]
        if not found:
            raise ValueError('Bare systemd executable not found in search path')
        return found[0]
    if not path.startswith('/') or '\0' in path:
        raise ValueError('Nonabsolute/invalid systemd path')
    return path


def _exec_paths(value):
    paths = []
    while value.strip():
        match = re.match(r'\s*\{\s*path=(.*?) ; argv\[\]=[^{}]*;[^{}]*\}\s*', value)
        if not match:
            raise ValueError('Unknown native Exec property syntax')
        paths.append(_unescape(match[1], search=True))
        value = value[match.end():]
    return paths


def inspect_services(*, properties=None, runner=_run, manager='/run/systemd/system', max_services=64):
    """properties maps unit names to native show output; no manager access in fixtures."""
    if properties is None and not os.path.isdir(manager):
        return _result('services', raw='services: not applicable (no systemd manager)')
    root = _root('services')
    if root:
        return root
    contexts, gaps = [], []
    if properties is None:
        binary = _trusted_systemctl()
        if not binary:
            return _result('services', gaps=['Trusted absolute systemctl unavailable'])
        try:
            text = runner([binary, 'list-units', '--type=service', '--state=active',
                           '--no-legend', '--plain', '--no-pager'])
            if len(text.encode('utf-8', 'surrogateescape')) > OUTPUT_LIMIT:
                raise ValueError('systemctl output limit reached')
            properties = {}
            for line in text.splitlines():
                fields = line.split()
                if not fields:
                    continue
                if (len(fields) < 4 or fields[1:3] != ['loaded', 'active']
                        or not re.fullmatch(r'[A-Za-z0-9_@.:\\-]+\.service', fields[0])
                        or fields[0].startswith('-')):
                    gaps.append('Unrecognized active service listing')
                    continue
                if len(properties) >= max_services:
                    gaps.append('Service limit reached (maximum %d)' % max_services)
                    break
                properties[fields[0]] = None
        except (OSError, ValueError, TimeoutError, subprocess.TimeoutExpired):
            return _result('services', gaps=['Active service listing failed/timed out/limited'])
    for index, (unit, text) in enumerate(properties.items()):
        if index >= max_services:
            gaps.append('Service limit reached (maximum %d)' % max_services)
            break
        try:
            if text is None:
                text = runner([binary, 'show', '--no-pager', '--property=' + ','.join(PROPERTIES), '--', unit])
            if len(text.encode('utf-8', 'surrogateescape')) > OUTPUT_LIMIT:
                raise ValueError('show output limit reached')
            props = {}
            for line in text.splitlines():
                key, sep, value = line.partition('=')
                if not sep or key not in PROPERTIES or (key in props and key not in EXEC):
                    raise ValueError('Unknown/duplicate show property syntax')
                # Exec* properties legitimately repeat (e.g. two ExecReload= commands).
                props[key] = props[key] + ' ' + value if key in props else value
            if props.get('User', '') not in ('', 'root', '0') or props.get('DynamicUser') == 'yes':
                continue
            if props.get('DynamicUser') != 'no':
                raise ValueError('DynamicUser unavailable/unknown')
            # systemd omits empty Exec* properties from `show`, so only the rest are required.
            if any(key not in props for key in PROPERTIES if key != 'User' and key not in EXEC):
                raise ValueError('Effective properties missing')
            if props['RootDirectory'] not in ('', '/') or props['RootImage']:
                gaps.append(unit + ': root directory/image host paths untranslatable')
                continue
            for key in EXEC:
                try:
                    for path in _exec_paths(props.get(key, '')):
                        _path_risks(path, 'root service executable', contexts, gaps)
                except ValueError:
                    gaps.append(unit + ': ' + key + ' syntax/path unknown')
            for key in ('FragmentPath', 'DropInPaths', 'WorkingDirectory'):
                values = props[key].split() if key == 'DropInPaths' else [props[key]]
                try:
                    paths = [_unescape(value) for value in filter(None, values)]
                    for path in paths:
                        _path_risks(path, 'root service ' + key, contexts, gaps, directory=key == 'WorkingDirectory')
                except ValueError:
                    gaps.append(unit + ': ' + key + ' syntax/path unknown')
        except (OSError, ValueError, TimeoutError, subprocess.TimeoutExpired):
            gaps.append(unit + ': effective service inspection failed/timed out/limited')
    return _result('services', contexts, gaps)


def inspect_root_processes(*, proc='/proc', max_entries=4096):
    root = _root('root-processes')
    if root:
        return root
    contexts, gaps, seen = [], [], set()
    try:
        with os.scandir(proc) as entries:
            for index, entry in enumerate(entries):
                if index >= max_entries:
                    gaps.append('Process entry limit reached (maximum %d)' % max_entries)
                    break
                if not entry.name.isdecimal() or not entry.is_dir(follow_symlinks=False):
                    continue
                status = ''
                try:
                    status = read_regular(entry.path + '/status')
                    match = re.search(r'^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$', status, re.M)
                    if not match:
                        gaps.append('Process UID metadata unavailable/malformed')
                        continue
                    if int(match[2]) != 0:
                        continue
                    if re.search(r'^State:\s+Z', status, re.M):
                        continue  # Zombies have no executable link; nothing to assess.
                    link = entry.path + '/exe'
                    with _elevated():
                        path = os.readlink(link)
                        target, host = os.stat(link), os.stat(path)
                    if (target.st_dev, target.st_ino) != (host.st_dev, host.st_ino):
                        gaps.append('Root executable host path untranslatable')
                    elif path not in seen:
                        seen.add(path)
                        _path_risks(path, 'running root executable', contexts, gaps)
                except FileNotFoundError:
                    # A vanished PID is ordinary; live kernel threads have no exe.
                    if os.path.exists(entry.path) and not re.search(r'^Kthread:\s+1\s*$', status, re.M):
                        gaps.append('Some live root/process metadata unavailable (race/deleted executable)')
                except OSError:
                    gaps.append('Some process/root executable metadata inaccessible or read-limited')
    except OSError:
        gaps.append('Process directory inaccessible')
    return _result('root-processes', contexts, gaps,
                   'processes: visible one-shot metadata only; hidden PIDs/mount namespaces and future root execution unverified. Replacement does not preserve SUID privilege.')


def _real_directory(path, gaps):
    if not os.path.isabs(path) or any(p in ('.', '..') for p in path.split('/')):
        return False
    current = '/'
    for component in filter(None, path.split('/')):
        current = os.path.join(current, component)
        metadata = _metadata(current, gaps, False)
        if not metadata or not stat.S_ISDIR(metadata.st_mode):
            return False  # Never traverse symlink directories.
    return True


def _accounts(accounts, max_accounts, gaps):
    own_home = next((os.path.realpath(a.pw_dir) for a in accounts if a.pw_uid == os.geteuid()), None)
    for index, account in enumerate(accounts):
        if index >= max_accounts:
            gaps.append('Account limit reached (maximum %d)' % max_accounts)
            break
        if account.pw_uid != os.geteuid() and os.path.realpath(account.pw_dir) != own_home:
            yield account


def _entries(directory, budget, gaps):
    if not _real_directory(directory, gaps):
        return
    found = []
    try:
        # Listing is elevated (metadata only) but eager: never yield while holding root.
        with _elevated(), os.scandir(directory) as entries:
            for entry in entries:
                if budget[0] <= 0:
                    gaps.append('Directory entry limit reached')
                    break
                budget[0] -= 1
                found.append(entry)
    except OSError:
        gaps.append('Directory metadata inaccessible: ' + directory)
    yield from found


def inspect_credentials(*, paths=HOST_SECRETS, accounts=None, environ=None,
                        tmp='/tmp', max_accounts=128, max_entries=2048):
    root = _root('credentials')
    if root:
        return root
    contexts, gaps, budget = [], [], [max_entries]

    def inspect(path):
        path = os.fspath(path)
        if not os.path.isabs(path) or '\0' in path or len(path) > 4096:
            gaps.append('Credential path invalid/unresolvable/length-limited')
            return
        # EACCES means a parent is not searchable by us, so the credential is unreadable too.
        metadata = _metadata(path, gaps, denied_ok=True)
        if metadata and stat.S_ISREG(metadata.st_mode) and metadata.st_uid != os.geteuid() and _access(path, os.R_OK):
            contexts.append((os.fspath(path), 'Readable other-account credential (owner UID %d)' % metadata.st_uid))

    for path in paths:
        inspect(path)
    accounts = pwd.getpwall() if accounts is None else accounts
    for account in _accounts(accounts, max_accounts, gaps):
        inspect(os.path.join(tmp, 'krb5cc_' + str(account.pw_uid)))
        home = account.pw_dir
        if not _real_directory(home, gaps):
            continue
        for name in HOME_SECRETS:
            path = os.path.join(home, name)
            if _real_directory(os.path.dirname(path), gaps):
                inspect(path)
        for entry in _entries(os.path.join(home, '.ssh'), budget, gaps):
            if (entry.name.startswith('id_') or entry.name == 'identity' or entry.name.endswith(('.pem', '.key'))) and '.pub' not in entry.name:
                inspect(entry.path)
    environ = os.environ if environ is None else environ
    for name in TOKEN_VARS:
        path = environ.get(name, '')
        # Conventional projected Kubernetes tokens aren't cross-account mistakes.
        projected = tuple(base + provider for base in ('/run/secrets/', '/var/run/secrets/')
                          for provider in ('kubernetes.io/', 'eks.amazonaws.com/', 'azure/'))
        if path and ('\0' in path or len(path) > 4096 or not os.path.realpath(path).startswith(projected)):
            inspect(path)
    return _result('credentials', contexts, gaps)


def inspect_agent_sockets(*, accounts=None, tmp='/tmp', run='/run/user', max_accounts=128, max_entries=2048):
    root = _root('agent-sockets')
    if root:
        return root
    contexts, gaps, budget = [], [], [max_entries]

    def inspect(entry):
        metadata = _metadata(entry.path, gaps, False)
        if metadata and stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid != os.geteuid() and _access(entry.path, os.W_OK):
            contexts.append((entry.path, 'Writable other-account agent socket; API authorization unverified'))

    for entry in _entries(tmp, budget, gaps):
        if entry.name.startswith('ssh-') and entry.is_dir(follow_symlinks=False):
            for socket in _entries(entry.path, budget, gaps):
                if socket.name.startswith('agent.'):
                    inspect(socket)
    accounts = pwd.getpwall() if accounts is None else accounts
    for account in _accounts(accounts, max_accounts, gaps):
        for directory in (os.path.join(run, str(account.pw_uid), 'gnupg'),
                          os.path.join(run, str(account.pw_uid), 'gcr'), os.path.join(account.pw_dir, '.gnupg')):
            for entry in _entries(directory, budget, gaps):
                if directory.endswith('/gcr') or entry.name.startswith('S.gpg-agent'):
                    inspect(entry)
    return _result('agent-sockets', contexts, gaps)


def scan(deep=False):
    result = dict(findings=[], raw='', errors=[])
    checks = [('services', inspect_services), ('root-processes', inspect_root_processes),
              ('credentials', inspect_credentials)]
    if deep:
        checks.append(('agent-sockets', inspect_agent_sockets))
    for name, check in checks:
        try:
            part = check()
        except Exception as exc:
            part = _result(name, gaps=['Check failed: ' + type(exc).__name__])
        result['findings'].extend(part['findings'])
        result['errors'].extend(part['errors'])
        result['raw'] += part['raw'] + '\n' if part['raw'] else ''
        if part.get('incomplete_ids'):
            result.setdefault('incomplete_ids', []).extend(part['incomplete_ids'])
    return result
