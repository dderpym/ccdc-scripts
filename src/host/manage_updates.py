#!/usr/bin/env python3
"""Conservative native updates; JSON request on stdin, one JSON response on stdout.

No reboot or automatic rollback. Native maintainer scripts/hooks remain enabled
and may restart services. APK support is deliberately limited to apk-tools 2.14,
un-tagged repositories and transactions changing only requested packages; newer
formats and dependency changes require a reviewed resolver, not guessed output.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

from host import update_services

BACKUP_ROOT = Path('/var/backups/ccdc-updates')
LOCK = '/run/ccdc-updates.lock'
MIN_FREE_BYTES = 256 * 1024 * 1024
SELECTION_FILES = {'apk': Path('/etc/apk/world'), 'apt': Path('/var/lib/apt/extended_states')}
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
       'HOME': '/root', 'DEBIAN_FRONTEND': 'noninteractive',
       'NEEDRESTART_MODE': 'l', 'SYSTEMD_PAGER': 'cat'}
PACKAGE = r'[a-z0-9][a-z0-9+_.-]*(?::[a-z0-9][a-z0-9-]*)?'
VERSION = r'[0-9][A-Za-z0-9.+:~_-]*'
SERVICE = r'[A-Za-z0-9][A-Za-z0-9_.@:-]{0,254}'
APT_OPTIONS = ['-o', 'APT::Get::AllowUnauthenticated=false',
               '-o', 'Acquire::AllowInsecureRepositories=false',
               '-o', 'Acquire::AllowDowngradeToInsecureRepositories=false',
               '-o', 'APT::Get::allow-Downgrades=false',
               '-o', 'APT::Update::Error-Mode=any',
               '-o', 'Dpkg::Options::=--force-confdef',
               '-o', 'Dpkg::Options::=--force-confold']
APK_OPTIONS = ['--no-interactive', '--no-progress', '--cache-max-age', '5256000']


class Refusal(RuntimeError):
    def __init__(self, message, **details):
        super().__init__(message)
        self.details = details


def require(condition, message):
    if not condition:
        raise Refusal(message)


def matches(pattern, value):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def high_risk(name):
    name = name.split(':')[0]
    return bool(re.match(
        r'^(linux(?:-|$)|kernel|busybox|alpine-base|init(?:-|$)|initscripts|'
        r'sysvinit|sysv-rc|upstart|runit|s6(?:-|$)|systemd|openrc|librc|libeinfo|'
        r'libc(?:6|\d|[-.]|$)|glibc|musl|libsystemd|libudev|udev|libapt|libdpkg|'
        r'apt(?:-|$)|dpkg|apk-tools|'
        r'(?:lib)?python|pypy|sudo|postgres|(?:default-)?mysql|mariadb|'
        r'mongo(?:db)?|redis|docker|containerd|runc|podman)', name))


def risk_reason(name):
    """These are manual holds, not a claim that all other upgrades are safe."""
    name = name.split(':')[0]
    categories = (
        (r'^(linux(?:-|$)|kernel)', 'Kernel/boot components may require reboot and recovery access'),
        (r'^(busybox|alpine-base|init(?:-|$)|initscripts|sysvinit|sysv-rc|upstart|runit|s6(?:-|$)|systemd|openrc|librc|libeinfo|libsystemd|libudev|udev)',
         'Core system/init components can disrupt boot and running services'),
        (r'^(libc(?:6|\d|[-.]|$)|glibc|musl)', 'Core C runtime affects nearly every running process'),
        (r'^(libapt|libdpkg|apt(?:-|$)|dpkg|apk-tools)', 'Package manager changes need separate manual review'),
        (r'^(?:lib)?python|^pypy', 'Python runtime changes can break system tools and applications'),
        (r'^sudo', 'Privilege/access changes need separate manual review'),
        (r'^(postgres|(?:default-)?mysql|mariadb|mongo(?:db)?|redis)',
         'Database changes may need data backup, migration and compatibility review'),
        (r'^(docker|containerd|runc|podman)', 'Container runtime changes may interrupt workloads'),
    )
    for pattern, reason in categories:
        if re.match(pattern, name):
            return reason
    return 'Lower-risk candidate; maintainer scripts may still disrupt services'


def name_list(value, label):
    require(isinstance(value, list) and all(matches(PACKAGE, x) for x in value)
            and len(set(value)) == len(value), 'Invalid ' + label)


def validate_expected(plan):
    fields = {'schema', 'manager', 'platform', 'init', 'installed', 'repositories',
              'candidates', 'changes', 'selected'}
    require(isinstance(plan, dict) and fields <= set(plan) <= fields | {'held'},
            'Invalid expected plan fields')
    require(type(plan['schema']) is int and plan['schema'] == 2, 'Invalid plan schema')
    require(plan['manager'] in ('apt', 'apk'), 'Invalid plan manager')
    require(isinstance(plan['platform'], dict) and set(plan['platform']) == {'id', 'version'}
            and matches(r'[a-z0-9_-]+', plan['platform']['id'])
            and matches(r'[A-Za-z0-9_.-]+', plan['platform']['version']), 'Invalid plan platform')
    require((plan['manager'], plan['platform']['id'], plan['init']) in
            (('apt', 'debian', 'systemd'), ('apk', 'alpine', 'openrc')), 'Invalid plan init/platform')
    state = plan['installed']
    require(isinstance(state, dict) and state and all(
        matches(PACKAGE, k) and matches(VERSION, v) for k, v in state.items()),
        'Invalid installed state')
    require(matches(r'[0-9a-f]{64}', plan['repositories']), 'Invalid repositories digest')
    candidates = plan['candidates']
    require(isinstance(candidates, list), 'Invalid candidates')
    by_name = {}
    for candidate in candidates:
        require(isinstance(candidate, dict) and set(candidate) ==
                {'name', 'old', 'new', 'risk', 'reason'}, 'Invalid candidate fields')
        name, old, new = (candidate[k] for k in ('name', 'old', 'new'))
        require(matches(PACKAGE, name) and name not in by_name and name in state
                and old == state[name] and matches(VERSION, new) and old != new,
                'Invalid/addition/removal candidate')
        require(candidate['risk'] in ('lower', 'manual') and
                not (high_risk(name) and candidate['risk'] != 'manual') and
                isinstance(candidate['reason'], str) and candidate['reason'] and
                not any(c in candidate['reason'] for c in '\x00\r\n'), 'Invalid candidate risk/reason')
        by_name[name] = candidate
    require(list(by_name) == sorted(by_name), 'Candidates must be sorted')
    name_list(plan['selected'], 'selected packages')
    require(plan['selected'] == sorted(plan['selected']) and all(
        name in by_name and by_name[name]['risk'] == 'lower' for name in plan['selected']),
        'Selected package is not a discovered lower-risk candidate')
    require(isinstance(plan['changes'], list), 'Invalid changes')
    wanted = [{k: by_name[name][k] for k in ('name', 'old', 'new')}
              for name in plan['selected']]
    require(plan['changes'] == wanted, 'Changes must be the exact selected candidates')
    # Equality alone would accept unexpected keys/types in pathological JSON values.
    for change in plan['changes']:
        require(isinstance(change, dict) and set(change) == {'name', 'old', 'new'},
                'Invalid change fields')
    held = plan.get('held', [])
    require(isinstance(held, list) and all(isinstance(x, str) and x and
            not any(c in x for c in '\x00\r\n') for x in held) and held == sorted(set(held)),
            'Invalid held summaries')
    return dict(plan, held=held)


def run(argv, timeout=120, private=False, check=True):
    """Native evidence is returned for private controller diagnostics; argv is omitted."""
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, env=ENV,
                                timeout=timeout, cwd='/')
    except subprocess.TimeoutExpired as exc:
        if private:
            raise Refusal('Service command timed out') from exc
        def decoded(value):
            return value.decode(errors='replace') if isinstance(value, bytes) else value or ''
        output = decoded(exc.stdout) + decoded(exc.stderr)
        raise Refusal('Native command timed out: ' + argv[0],
                      timed_out=True, native_output=output[-16000:]) from exc
    except OSError as exc:
        raise Refusal('Service command exec failure' if private else
                      'Native command exec failure: ' + argv[0]) from exc
    if check and (result.returncode or (not private and re.search(
            r'(?im)^(?:W:|E:|WARNING:|ERROR:)', result.stdout + '\n' + result.stderr))):
        details = {} if private else {'native_output': (result.stdout + result.stderr)[-16000:]}
        raise Refusal('Service command failed' if private else 'Native command failed: ' + argv[0],
                      **details)
    return result


def platform():
    values = {}
    for line in Path('/etc/os-release').read_text().splitlines():
        key, sep, value = line.partition('=')
        if sep and key in ('ID', 'VERSION_ID'):
            words = shlex.split(value)
            require(len(words) == 1, 'Invalid os-release')
            values[key] = words[0]
    distro, version = values.get('ID'), values.get('VERSION_ID')
    require(distro in ('debian', 'alpine') and matches(r'[A-Za-z0-9_.-]+', version),
            'Unsupported distro')
    if distro == 'debian':
        require(Path('/run/systemd/system').is_dir() and shutil.which('systemctl'),
                'Debian requires running systemd')
        return 'apt', {'id': distro, 'version': version}, 'systemd'
    require(Path('/run/openrc').is_dir() and shutil.which('rc-service'),
            'Alpine requires running OpenRC')
    # ponytail: pin the reviewed output format, support apk v3 after parser review.
    require(re.search(r'\bapk-tools 2\.14\.\d+\b', run(['apk', '--version']).stdout),
            'Only apk-tools 2.14.x is supported')
    require(not Path('/etc/apk/interactive').exists(), 'Interactive APK configuration refused')
    return 'apk', {'id': distro, 'version': version}, 'openrc'


def parse_dpkg(text):
    result = {}
    for line in text.splitlines():
        fields = line.split('\t')
        require(len(fields) == 3, 'Malformed dpkg database output')
        name, version, status = fields
        require(matches(PACKAGE, name) and name not in result, 'Invalid dpkg package')
        if status in ('rc ', 'un ', 'pn '):
            continue
        require(len(status) == 3 and status[0] in 'ih' and status[1:] == 'i '
                and matches(VERSION, version), 'Package database fault: ' + name)
        result[name] = version
    require(result, 'Empty package database')
    return dict(sorted(result.items()))


def parse_apk_installed(text):
    result = {}
    require(text.endswith('\n\n'), 'Truncated APK database')
    for record in text.strip().split('\n\n'):
        fields = {}
        for line in record.splitlines():
            require(len(line) >= 2 and line[1] == ':', 'Malformed APK database')
            key, value = line[0], line[2:]
            if key in ('P', 'V', 'f'):
                require(key not in fields, 'Duplicate APK database field')
                fields[key] = value
        name, version = fields.get('P'), fields.get('V')
        require(matches(PACKAGE, name) and ':' not in name and name not in result
                and matches(VERSION, version), 'Invalid APK installed package')
        require(not fields.get('f'), 'Broken APK package: ' + name)
        result[name] = version
    require(result, 'Empty APK database')
    return dict(sorted(result.items()))


def installed(manager):
    if manager == 'apt':
        audit = run(['dpkg', '--audit'])
        require(not (audit.stdout.strip() or audit.stderr.strip()), 'dpkg audit reported faults')
        query = run(['dpkg-query', '-W',
                     '-f=${binary:Package}\t${Version}\t${db:Status-Abbrev}\n'])
        require(not query.stderr.strip(), 'dpkg database query reported faults')
        return parse_dpkg(query.stdout)
    # Native query additionally detects malformed file/directory records.
    require(not run(['apk', '--no-network', '--repositories-file', '/dev/null', 'info']).stderr.strip(),
            'APK database query reported faults')
    return parse_apk_installed(Path('/lib/apk/db/installed').read_text())


def signed_keys(text):
    keys = []
    for value in re.findall(r'(?im)\bsigned-by[ \t]*[:=][ \t]*([^\s\]]+)', text):
        require(value.startswith('/') and ',' not in value, 'Unsupported Signed-By specification')
        require(Path(value).is_file(), 'Missing Signed-By keyring')
        keys.append(value)
    # Deb822 permits multiple/inline keys; refuse rather than omit a fingerprint.
    for value in re.findall(r'(?im)^Signed-By:[ \t]*([^\n]*)', text):
        require(len(value.split()) == 1 and value.startswith('/'), 'Unsupported Signed-By keys')
    require(not re.search(r'(?m)^[ \t]+/', text), 'Continued Signed-By keys refused')
    return keys


def config_paths(manager):
    roots = ['/etc/apt', '/usr/share/keyrings'] if manager == 'apt' else ['/etc/apk']
    files = set()
    for root in roots:
        if Path(root).exists():
            for path in Path(root).rglob('*'):
                # APK cache is not configuration and can be huge.
                if manager == 'apk' and (path == Path('/etc/apk/cache') or
                                         Path('/etc/apk/cache') in path.parents):
                    continue
                require(not (path.is_symlink() and path.is_dir()),
                        'Symlinked package configuration directory refused')
                if path.is_file():
                    files.add(str(path))
    if manager == 'apt':
        if SELECTION_FILES['apt'].exists():
            files.add(str(SELECTION_FILES['apt']))
        for filename in list(files):
            if Path(filename).suffix in ('.list', '.sources'):
                files.update(signed_keys(Path(filename).read_text()))
    return sorted(files)


def apt_security(text):
    for line in text.splitlines():
        match = re.fullmatch(r'([^\s]+)\s+"((?:\\.|[^"\\])*)";', line.strip())
        require(match is not None, 'Unrecognized apt-config output')
        key, value = match[1].lower(), match[2].lower()
        if any(x in key for x in ('allowunauthenticated', 'allowinsecurerepositories',
                                  'allowdowngradetoinsecure', 'allowweakrepositories', 'allow-insecure', 'allow-weak')):
            require(value in ('false', '0', 'no', ''), 'Insecure APT configuration')
        if key.endswith(('verify-peer', 'verify-host', 'check-valid-until', 'check-date')):
            require(value not in ('false', '0', 'no', 'off'), 'Disabled APT verification')
        require(not ('gpgvcommand' in key or key == 'dir::bin::gpg'),
                'Custom APT verification executable refused')
        if key == 'dir::bin::methods':
            require(value.rstrip('/') == '/usr/lib/apt/methods', 'Custom APT methods refused')
        if key in ('dir::state', 'dir::state::status', 'dir::state::lists',
                   'dir::cache', 'dir::cache::archives'):
            defaults = {'dir::state': 'var/lib/apt', 'dir::state::status': '/var/lib/dpkg/status',
                        'dir::state::lists': 'lists', 'dir::cache': 'var/cache/apt',
                        'dir::cache::archives': 'archives'}
            require(value.rstrip('/') == defaults[key], 'Custom APT state/cache path refused')
        # Refuse external config/source directories: the fingerprint must cover all inputs.
        if key in ('dir', 'dir::etc', 'dir::etc::sourcelist', 'dir::etc::sourceparts',
                   'dir::etc::main', 'dir::etc::parts', 'dir::etc::trusted', 'dir::etc::trustedparts',
                   'dir::etc::preferences', 'dir::etc::preferencesparts',
                   'dir::etc::netrc', 'dir::etc::netrcparts'):
            allowed = {'dir': '/', 'dir::etc': 'etc/apt', 'dir::etc::sourcelist': 'sources.list',
                       'dir::etc::sourceparts': 'sources.list.d', 'dir::etc::main': 'apt.conf',
                       'dir::etc::parts': 'apt.conf.d', 'dir::etc::trusted': 'trusted.gpg',
                       'dir::etc::trustedparts': 'trusted.gpg.d',
                       'dir::etc::preferences': 'preferences', 'dir::etc::preferencesparts': 'preferences.d',
                       'dir::etc::netrc': 'auth.conf', 'dir::etc::netrcparts': 'auth.conf.d'}
            require(value.rstrip('/') == allowed[key].rstrip('/'), 'Custom APT config path refused')


def repositories(manager):
    paths = config_paths(manager)
    digest = hashlib.sha256()
    if manager == 'apt':
        config = run(['apt-config', 'dump']).stdout
        apt_security(config)
        digest.update(config.encode())
    for filename in paths:
        path = Path(filename)
        data = path.read_bytes()
        digest.update(filename.encode() + b'\0' + data + b'\0')
        if path.is_symlink():
            digest.update(os.readlink(path).encode() + b'\0')
        if manager == 'apt' and path.suffix in ('.list', '.sources'):
            text = '\n'.join(line.split('#', 1)[0] for line in data.decode().splitlines()).lower()
            # Refuse source-level verification overrides entirely: values can be
            # quoted (one-line format) or folded (Deb822), not just literal yes/no.
            require(not re.search(r'''\b(?:trusted|allow-insecure|allow-weak|allow-downgrade-to-insecure|check-valid-until|check-date|verify-peer|verify-host)["']*\s*[:=]''', text),
                    'APT repository verification override refused')
        if manager == 'apk' and (filename == '/etc/apk/repositories' or
                                path.parent == Path('/etc/apk/repositories.d')):
            for line in data.decode().splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                require(re.fullmatch(r'https://[^\s@]+', line) is not None,
                        'APK requires un-tagged HTTPS repositories')
        if manager == 'apk' and path.name in ('config', 'options'):
            require(not re.search(rb'(?:allow-untrusted|no-check-certificate|force-|no-scripts)', data),
                    'Unsafe APK options')
    require(any(Path(x).name in ('repositories', 'sources.list') or
                Path(x).suffix in ('.list', '.sources') for x in paths), 'No repositories configured')
    return digest.hexdigest()


def apt_name(name, record, state):
    arch = re.search(r'\[([a-z0-9-]+)\]\)$', record)
    if ':' not in name and arch and name + ':' + arch[1] in state:
        return name + ':' + arch[1]
    require(name in state, 'APT new dependency or ambiguous architecture')
    return name


def parse_apt(text, state):
    changes, configured, summary = {}, set(), None
    for line in text.splitlines():
        match = re.fullmatch(r'Inst (' + PACKAGE + r')(?: \[([^\]]+)\])? \(([^\s()]+) .+\)', line)
        if match:
            name, old, new = match.groups()
            name = apt_name(name, line, state)
            require(name not in changes and name in state and old == state[name]
                    and matches(VERSION, new), 'APT addition/ambiguous Inst record')
            changes[name] = {'name': name, 'old': old, 'new': new}
            continue
        match = re.fullmatch(r'Conf (' + PACKAGE + r') \(([^\s()]+) .+\)', line)
        if match:
            name, version = match.groups()
            name = apt_name(name, line, state)
            require(name in changes and name not in configured and changes[name]['new'] == version,
                    'Unexpected APT configuration action')
            configured.add(name)
            continue
        match = re.fullmatch(r'(\d+) upgraded, (\d+) newly installed, (\d+) to remove and (\d+) not upgraded\.', line)
        if match:
            require(summary is None and match[2] == '0' and match[3] == '0',
                    'APT additions/removals/ambiguous summary')
            summary = int(match[1])
            continue
        # Explicit allowlist of apt-get's informational output, not an action ignore rule.
        if not line or re.fullmatch(r'(Reading package lists\.\.\..*|Building dependency tree\.\.\..*|'
                                   r'Reading state information\.\.\..*|Calculating upgrade\.\.\..*|'
                                   r'The following packages (?:will be upgraded|have been kept back):|'
                                   r'The following additional packages will be installed:|'
                                   r'Suggested packages:|Recommended packages:|'
                                   r'The following packages were automatically installed and are no longer required:|'
                                   r"Use '(?:apt|apt-get) autoremove' to remove them\.|"
                                   r'[^ ]+ is already the newest version \([^)]+\)\.|'
                                   r'[^ ]+ set to manually installed\.)', line):
            continue
        if re.fullmatch(r'  (?:' + PACKAGE + r')(?: (?:' + PACKAGE + r'))*', line):
            continue
        raise Refusal('Unrecognized/unsafe APT simulation output')
    require(summary == len(changes) and configured == set(changes), 'Incomplete APT simulation')
    return [changes[name] for name in sorted(changes)]


def parse_apk(text, state):
    changes, total, finished = {}, None, False
    for line in text.splitlines():
        match = re.fullmatch(r'\((\d+)/(\d+)\) Upgrading (' + PACKAGE +
                             r') \(([^\s()]+) -> ([^\s()]+)\)', line)
        if match:
            index, count, name, old, new = match.groups()
            require(not finished and int(index) == len(changes) + 1 and int(count) > 0
                    and (total is None or total == int(count)), 'Ambiguous APK action count')
            total = int(count)
            require(':' not in name and name not in changes and name in state and old == state[name]
                    and matches(VERSION, new), 'APK addition/ambiguous upgrade')
            changes[name] = {'name': name, 'old': old, 'new': new}
            continue
        if re.fullmatch(r'OK: \d+ MiB in \d+ packages', line):
            require(not finished, 'Duplicate APK summary')
            finished = True
            continue
        if line:
            raise Refusal('Unrecognized/unsafe APK simulation output')
    require(finished and (total is None or total == len(changes)), 'Incomplete APK simulation')
    return [changes[name] for name in sorted(changes)]


def validate_changes(manager, changes, state, requested=None):
    for change in changes:
        name, old, new = (change[k] for k in ('name', 'old', 'new'))
        require(name in state and state[name] == old, 'New dependency/removal refused')
        if requested is not None:
            require(name in requested, 'Unselected dependency change refused: ' + name)
            require(not high_risk(name), 'High-risk transaction package: ' + name)
        if manager == 'apt':
            require(run(['dpkg', '--compare-versions', new, 'gt', old], check=False).returncode == 0,
                    'Downgrade/reinstall refused: ' + name)
        else:
            require(run(['apk', 'version', '-t', new, old]).stdout.strip() == '>',
                    'Downgrade/reinstall refused: ' + name)


def transaction_command(manager, packages, simulate):
    if manager == 'apt':
        return ['apt-get'] + APT_OPTIONS + (['--simulate'] if simulate else ['--assume-yes']) + [
            'install', '--only-upgrade', '--no-remove', '--no-install-recommends', '--'] + packages
    # --simulate disables metadata auto-refresh in APK 2.14; mutation is
    # network-free and uses separately fetched, verified exact-version archives.
    require(all(':' not in x.split('=')[0] and '.apk' not in x for x in packages),
            'Unsafe APK package/version specifier')
    options = ['--upgrade'] if simulate and not any('=' in x for x in packages) else []
    return ['apk'] + APK_OPTIONS + (['--simulate'] if simulate else ['--no-network']) + [
        'add'] + options + ['--'] + packages


def resolve(manager, packages, state):
    output = run(transaction_command(manager, packages, True))
    try:
        require(not output.stderr.strip(), 'Unrecognized native simulation diagnostics')
        changes = parse_apt(output.stdout, state) if manager == 'apt' else parse_apk(output.stdout, state)
        validate_changes(manager, changes, state, [x.split('=')[0] for x in packages])
        return changes
    except Refusal as exc:
        details = dict(exc.details)
        details.setdefault('native_output', (output.stdout + output.stderr)[-16000:])
        raise Refusal(str(exc), **details) from exc


def disk_check(paths):
    require(type(MIN_FREE_BYTES) is int and MIN_FREE_BYTES >= 256 * 1024 * 1024,
            'Invalid disk minimum')
    for path in paths:
        while not Path(path).exists():
            path = str(Path(path).parent)
        require(shutil.disk_usage(path).free >= MIN_FREE_BYTES, 'Insufficient free disk space')


def parse_apt_candidates(text, state):
    """apt-cache policy includes installed candidates omitted by conservative upgrade."""
    records, latest, current = {}, {}, None
    in_table = False
    for line in text.splitlines():
        match = re.fullmatch(r'(' + PACKAGE + r'):', line)
        if match:
            require(current is None or in_table, 'Missing APT version table')
            name = match[1]
            require(name not in records, 'Duplicate APT policy package')
            current = records[name] = {}
            in_table = False
            continue
        match = re.fullmatch(r'  (Installed|Candidate): (\S+)', line)
        if match:
            require(current is not None and not in_table and match[1] not in current,
                    'Malformed APT policy fields')
            require(matches(VERSION, match[2]) or match[2] == '(none)', 'Invalid APT policy version')
            current[match[1]] = match[2]
            continue
        if line == '  Version table:':
            require(current is not None and set(current) == {'Installed', 'Candidate'} and not in_table,
                    'Malformed APT version table')
            in_table = True
            continue
        # Repository URLs/descriptions are evidence only, never command arguments.
        match = re.fullmatch(r'(?: \*\*\* |     )(' + VERSION +
                             r') -?\d+(?: \(phased \d{1,3}%\))?', line)
        if in_table and match:
            # Native VersionList is descending. Preserve a newer version hidden
            # by policy pins as a manual candidate, never override native policy.
            latest.setdefault(name, match[1])
            continue
        if in_table and re.fullmatch(r' {7,10}-?\d+ \S.*', line):
            continue
        raise Refusal('Unrecognized APT candidate output')
    require(in_table, 'Missing APT version table')
    # FullName(true) omits the native architecture, even when dpkg's binary
    # name includes it. Explicit foreign records consume their exact names;
    # an unqualified record must match exactly one remaining installed binary.
    remaining = set(state) - set(records)
    canonical = {}
    for raw, values in records.items():
        name = raw
        if raw not in state:
            aliases = [x for x in remaining if ':' not in raw and x.split(':')[0] == raw]
            require(len(aliases) == 1, 'Unexpected/ambiguous APT policy package')
            name = aliases[0]
            remaining.remove(name)
        canonical[name] = (values, latest.get(raw))
    require(set(canonical) == set(state), 'Incomplete APT candidate output')
    changes = []
    for name, (values, newest) in sorted(canonical.items()):
        require(set(values) == {'Installed', 'Candidate'} and values['Installed'] == state[name],
                'APT policy installed state differs')
        new = values['Candidate']
        for target in (new, newest):
            if target is None or target == '(none)' or target == state[name]:
                continue
            comparison = run(['dpkg', '--compare-versions', target, 'gt', state[name]], check=False)
            require(comparison.returncode in (0, 1), 'Invalid APT candidate version comparison')
            if comparison.returncode == 0:
                changes.append({'name': name, 'old': state[name], 'new': target})
                break
    return changes


def parse_apk_candidates(text, state):
    lines = text.splitlines()
    require(lines and re.fullmatch(r'Installed: +Available:', lines[0]),
            'Unrecognized APK version header')
    changes = {}
    labels = {name + '-' + old: name for name, old in state.items()}
    require(len(labels) == len(state), 'Ambiguous APK installed names/versions')
    for line in lines[1:]:
        match = re.fullmatch(r'(\S+) +< (' + VERSION + r') *', line)
        require(match is not None, 'Unrecognized APK candidate output')
        require(match[1] in labels, 'Unexpected APK candidate name/version')
        name, new = labels[match[1]], match[2]
        require(name not in changes and new != state[name], 'Unexpected APK candidate')
        changes[name] = {'name': name, 'old': state[name], 'new': new}
    return [changes[name] for name in sorted(changes)]


def discover(manager, state):
    if manager == 'apt':
        query = ['apt-cache', 'policy', '--'] + sorted(state)
        command = ['apt-get'] + APT_OPTIONS + [
            '--simulate', 'upgrade', '--no-remove', '--no-install-recommends']
    else:
        query = ['apk'] + APK_OPTIONS + ['--no-network', 'version', '-l', '<']
        command = ['apk'] + APK_OPTIONS + ['--simulate', 'upgrade']
    output = run(query)
    try:
        require(not output.stderr.strip(), 'Unrecognized native candidate diagnostics')
        available = (parse_apt_candidates(output.stdout, state) if manager == 'apt' else
                     parse_apk_candidates(output.stdout, state))
    except Refusal as exc:
        raise Refusal(str(exc), native_output=(output.stdout + output.stderr)[-16000:]) from exc
    # APK 2.14 warns when apk-tools itself has an upgrade. Surface that known
    # warning, but never treat the simulation as authorizing a manual upgrade.
    output = run(command, check=False)
    try:
        require(output.returncode == 0, 'Native upgrade discovery failed')
        warnings = []
        for line in output.stderr.splitlines():
            require(manager == 'apk' and line in (
                'WARNING: This simulation is not reliable as apk-tools upgrade is available.',
                'WARNING: Failed to perform initial self-upgrade, continuing with full upgrade.'),
                'Unrecognized native upgrade diagnostics')
            warnings.append(line)
        full = parse_apt(output.stdout, state) if manager == 'apt' else parse_apk(output.stdout, state)
        validate_changes(manager, full, state)
        targets = {x['name']: x for x in available}
        require(all(x['name'] in targets and x == targets[x['name']] for x in full),
                'Native upgrade differs from available candidates')
        upgraded = {x['name'] for x in full}
        held = list(warnings)
        if manager == 'apt':
            count = re.search(r'(\d+) not upgraded\.', output.stdout)
            if count and int(count[1]):
                held.append('Native upgrade: ' + count[1] + ' packages not upgraded')
        candidates = []
        for change in available:
            name = change['name']
            reason = risk_reason(name)
            native_held = name not in upgraded
            if native_held:
                held_reason = 'Native upgrade held this candidate (dependencies, holds or pins need review)'
                reason = reason + '; ' + held_reason if high_risk(name) else held_reason
                held.append(name + ': native upgrade held at ' + state[name])
            manual = high_risk(name) or native_held
            candidates.append(dict(change, risk='manual' if manual else 'lower', reason=reason))
            if high_risk(name):
                held.append(name + ': ' + risk_reason(name))
        return candidates, sorted(set(held))
    except Refusal as exc:
        raise Refusal(str(exc), native_output=(output.stdout + output.stderr)[-16000:]) from exc


def make_plan(manager, release, init, refresh=False):
    state = installed(manager)
    repositories(manager)  # Reject insecure configuration before contacting repositories.
    disk_check(['/', '/var', str(BACKUP_ROOT)])
    if refresh:
        run(['apt-get'] + APT_OPTIONS + ['update'] if manager == 'apt' else
            ['apk', '--no-interactive', '--no-progress', 'update'], timeout=600)
    fingerprint = repositories(manager)
    candidates, held = discover(manager, state)
    require(installed(manager) == state and repositories(manager) == fingerprint,
            'Package/configuration state changed during discovery')
    return validate_expected({'schema': 2, 'manager': manager, 'platform': release, 'init': init,
                              'installed': state, 'repositories': fingerprint,
                              'candidates': candidates, 'held': held, 'changes': [], 'selected': []})


def pins_for(plan, selected):
    return [x['name'] + '=' + (x['new'] if x['name'] in selected else x['old'])
            for x in plan['candidates']]


def select_plan(snapshot, packages, manager, release, init):
    snapshot = validate_expected(snapshot)
    name_list(packages, 'selected packages')
    current = make_plan(manager, release, init)  # Never refresh during review/apply.
    reviewed = dict(snapshot, changes=[], selected=[])
    require(current == reviewed, 'Stale plan: installed state, configuration or candidates differ')
    by_name = {x['name']: x for x in current['candidates']}
    require(all(name in by_name and by_name[name]['risk'] == 'lower' for name in packages),
            'Selected package is not a discovered lower-risk candidate')
    selected = sorted(packages)
    wanted = [{k: by_name[name][k] for k in ('name', 'old', 'new')} for name in selected]
    pins = pins_for(current, selected)
    actual = resolve(manager, pins, current['installed']) if pins else []
    if actual != wanted:
        raise Refusal('Resolved transaction differs from exact selected candidates; exclude/retry, do not broaden',
                      resolved_changes=actual, selected=selected)
    require(installed(manager) == current['installed'] and
            repositories(manager) == current['repositories'], 'State changed during selection')
    return validate_expected(dict(current, selected=selected, changes=actual))


def capture_selection(manager):
    path = SELECTION_FILES[manager]
    try:
        info = path.lstat()
    except FileNotFoundError:
        require(manager == 'apt', 'Missing APK world file')
        return path, None, None
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            'Unsafe native package selection file')
    return path, path.read_bytes(), info


def restore_selection(snapshot):
    # Exact-version arguments are temporary review constraints, not new APK world
    # pins or APT manual-install marks. Preserve the pre-update selection policy.
    path, data, info = snapshot
    if data is None:
        path.unlink(missing_ok=True)
        return
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.ccdc-selection-', delete=False) as out:
        temporary = Path(out.name)
        try:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
            os.chmod(temporary, stat.S_IMODE(info.st_mode))
            os.chown(temporary, info.st_uid, info.st_gid)
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def trusted_directory(path, private=False):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            'Unsafe backup directory')
    if private:
        require(not info.st_mode & 0o077, 'Backup directory must be private')


def backup(plan, token):
    for path in reversed([BACKUP_ROOT] + list(BACKUP_ROOT.parents)):
        if not path.exists():
            path.mkdir(mode=0o700)
        trusted_directory(path, private=(path == BACKUP_ROOT))
    directory = BACKUP_ROOT / token
    directory.mkdir(mode=0o700)  # Never reuse/overwrite another run's evidence.
    trusted_directory(directory, private=True)
    result = {'backup_dir': str(directory), 'backup_archive': str(directory / 'backup.tar.gz')}
    try:
        (directory / 'versions.json').write_text(json.dumps(plan['installed'], sort_keys=True) + '\n')
        (directory / 'plan.json').write_text(json.dumps(plan, sort_keys=True) + '\n')
        config = ['/etc/apt', '/usr/share/keyrings', '/var/lib/dpkg'] if plan['manager'] == 'apt' else [
            '/etc/apk', '/lib/apk/db']
        config += [str(Path(p).resolve()) for p in config_paths(plan['manager'])]
        paths = sorted(set(['/etc'] + [p for p in config if Path(p).exists()]), key=lambda x: (len(x), x))
        selected = []
        with tarfile.open(result['backup_archive'], 'w:gz', dereference=False) as archive:
            for name in ('versions.json', 'plan.json'):
                archive.add(str(directory / name), arcname='ccdc-updates/' + name)
            for filename in paths:
                path = Path(filename)
                if any(path == parent or parent in path.parents for parent in selected):
                    continue
                archive.add(filename, arcname=filename.lstrip('/'), recursive=True)
                selected.append(path)
        for file in directory.iterdir():
            file.chmod(0o600)
        disk_check(['/', '/var', str(directory)])
    except Exception as exc:
        raise Refusal('Backup failed; no packages installed', **result) from exc
    return result


def stage_apk(plan, pins, directory):
    """Fetch is read-only (no index refresh). v2 fetch only accepts bare names;
    if it selects anything but the reviewed version, refuse before mutation.
    """
    directory = Path(directory) / 'packages'
    directory.mkdir(mode=0o700)
    changes = plan['changes']
    run(['apk'] + APK_OPTIONS + ['fetch', '--output', str(directory), '--'] +
        [x['name'] for x in changes], timeout=600)
    archives = [str(directory / (x['name'] + '-' + x['new'] + '.apk')) for x in changes]
    require(set(directory.iterdir()) == {Path(x) for x in archives} and
            all(Path(x).is_file() and not Path(x).is_symlink() for x in archives),
            'APK fetch did not select the reviewed exact versions')
    run(['apk', '--no-network', 'verify', '--'] + archives, timeout=600)
    command = transaction_command('apk', pins, False)
    position = command.index('--') + 1
    command[position:position] = archives
    # Archives introduce signed candidates; final name=version arguments ensure
    # world constraints use exact versions, not a local-package checksum pin.
    simulation = run(command[:position - 1] + ['--simulate'] + command[position - 1:])
    try:
        require(not simulation.stderr.strip(), 'Unrecognized offline APK simulation diagnostics')
        actual = parse_apk(simulation.stdout, plan['installed'])
        require(actual == changes, 'Offline APK transaction differs from plan')
        validate_changes('apk', actual, plan['installed'], [x.split('=')[0] for x in pins])
    except Refusal as exc:
        raise Refusal(str(exc), native_output=(simulation.stdout + simulation.stderr)[-16000:]) from exc
    return command


def apply(expected, token, manager, release, init):
    expected = validate_expected(expected)
    require(matches(r'[0-9a-fA-F]{32}', token), 'Invalid 32-hex run token')
    current = select_plan(expected, expected['selected'], manager, release, init)
    require(current == expected, 'Stale plan: selected transaction differs')
    versions = dict(expected['installed'])
    versions.update({x['name']: x['new'] for x in expected['changes']})
    pins = pins_for(expected, expected['selected'])
    selection = capture_selection(manager)
    evidence = backup(expected, token)
    installation_attempted = False
    try:
        command = transaction_command(manager, pins, False)
        if manager == 'apk' and expected['changes']:
            command = stage_apk(expected, pins, evidence['backup_dir'])
        # Backups/downloads may take time. Rediscover and re-resolve before mutation.
        require(select_plan(expected, expected['selected'], manager, release, init) == expected,
                'Stale plan after backup')
        if expected['changes']:
            installation_attempted = True
            output = run(command, timeout=1800)
            (Path(evidence['backup_dir']) / 'install-output.txt').write_text(output.stdout + output.stderr)
        after = installed(manager)
        require(after == versions, 'Installed state differs after update; manual recovery required')
        if installation_attempted:
            restore_selection(selection)
        return dict(evidence, changes=expected['changes'], installed_after=after,
                    native_hooks_may_restart=True, installation_attempted=installation_attempted,
                    rebooted=False, rollback_attempted=False, selection_metadata_preserved=True)
    except Exception as exc:
        error = dict(evidence, rollback_attempted=False,
                     installation_attempted=installation_attempted,
                     manual_recovery_required=installation_attempted)
        if isinstance(exc, Refusal):
            error.update(exc.details)
        (Path(evidence['backup_dir']) / 'failure.json').write_text(
            json.dumps(dict(error, error=str(exc)), sort_keys=True) + '\n')
        raise Refusal(str(exc), **error) from exc



def execute(document):
    require(isinstance(document, dict), 'Invalid request')
    action = document.get('action')
    fields = {
        'plan': ({'action'}, set()),
        'select': ({'action', 'snapshot', 'packages'}, set()),
        'apply': ({'action', 'expected', 'token'}, set()),
        'services': ({'action'}, {'before'}),
        'restart': ({'action', 'service'}, {'before'}),
    }
    require(isinstance(action, str) and action in fields, 'Invalid action')
    required, optional = fields[action]
    require(required <= set(document) <= required | optional, 'Invalid request fields')
    if action == 'apply':
        require(matches(r'[0-9a-fA-F]{32}', document['token']), 'Invalid 32-hex run token')
        validate_expected(document['expected'])
    if action == 'select':
        validate_expected(document['snapshot'])
        name_list(document['packages'], 'selected packages')
    if action == 'restart':
        require(matches(SERVICE, document['service']), 'Invalid service name')
    manager, release, init = platform()
    if action == 'plan':
        return make_plan(manager, release, init, refresh=True)
    if action == 'select':
        return select_plan(document['snapshot'], document['packages'], manager, release, init)
    if action == 'apply':
        return apply(document['expected'], document['token'], manager, release, init)
    try:
        if action == 'services':
            return update_services.inspect_services(init, before=document.get('before'))
        return update_services.restart_service(init, document['service'], before=document.get('before'))
    except (OSError, RuntimeError, ValueError) as exc:
        raise Refusal('Service action failed: ' + action, service_error=str(exc)) from exc


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON key')
        result[key] = value
    return result


def main():
    fd = None
    try:
        require(os.geteuid() == 0, 'Root is required')
        os.umask(0o077)
        minimum = os.environ.get('CCDC_UPDATES_MIN_FREE_BYTES')
        if minimum is not None:
            global MIN_FREE_BYTES
            MIN_FREE_BYTES = int(minimum)
            require(MIN_FREE_BYTES >= 256 * 1024 * 1024, 'Disk minimum cannot be below 256 MiB')
        fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077
                and info.st_nlink == 1, 'Unsafe update lock')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Refusal('Another update run is active') from exc
        document = json.loads(sys.stdin.read(1024 * 1024), object_pairs_hook=unique_object)
        print(json.dumps(execute(document), sort_keys=True))
        return 0
    except Exception as exc:
        details = exc.details if isinstance(exc, Refusal) else {}
        # Unexpected exceptions omit command arguments/output, which could contain credentials.
        message = str(exc) if isinstance(exc, Refusal) else 'Invalid request or host operation failed'
        print(json.dumps(dict(details, error=message), sort_keys=True))
        return 1
    finally:
        if fd is not None:
            os.close(fd)


if __name__ == '__main__':
    sys.exit(main())
