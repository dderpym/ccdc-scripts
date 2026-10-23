"""Small passive userspace CVE snapshot; installed metadata is NOT a live-binary audit.

No target network/bus calls, privileged program execution, or config evaluation.
Vendor tables: Debian Security Tracker /tracker/CVE-{2024-48990,2026-41651,
2021-4034,2021-3156}; Canonical ubuntu-security-notices/main/osv/cve/YEAR/
UBUNTU-CVE-ID.json (reviewed 2026-10-07). Unknown builds are never called fixed.
"""
import errno
import os
from pathlib import Path
import re
import stat
import subprocess

# Only releases with explicit vendor fixed-version entries are encoded. Later
# releases are deliberately not inferred from an unstable or older-release fix.
FIXES = {
    'CVE-2024-48990': {
        'ubuntu': {'16.04': '2.6-1ubuntu0.1~esm1', '18.04': '3.1-1ubuntu0.1+esm1',
                   '20.04': '3.4-6ubuntu0.1+esm1', '22.04': '3.5-5ubuntu2.2', '24.04': '3.6-7ubuntu4.3'},
        'debian': {'11': '3.5-4+deb11u4', '12': '3.6-4+deb12u2'}},
    'CVE-2026-41651': {
        'ubuntu': {'16.04': '0.8.17-4ubuntu6~gcc5.4ubuntu1.5+esm1',
                   '18.04': '1.1.9-1ubuntu2.18.04.6+esm1', '20.04': '1.1.13-2ubuntu1.1+esm1',
                   '22.04': '1.2.5-2ubuntu3.1', '24.04': '1.2.8-2ubuntu1.5',
                   '25.10': '1.3.1-1ubuntu1.1', '26.04': '1.3.4-3ubuntu1'},
        'debian': {'11': '1.2.2-2+deb11u1', '12': '1.2.6-5+deb12u1', '13': '1.3.1-1+deb13u1'}},
    'CVE-2021-4034': {
        'ubuntu': {'14.04': '0.105-4ubuntu3.14.04.6+esm1', '16.04': '0.105-14.1ubuntu0.5+esm1',
                   '18.04': '0.105-20ubuntu0.18.04.6', '20.04': '0.105-26ubuntu1.2', '22.04': '0.105-31ubuntu1'},
        'debian': {'9': '0.105-18+deb9u2', '10': '0.105-25+deb10u1', '11': '0.105-31+deb11u1'}},
    'CVE-2021-3156': {
        'ubuntu': {'14.04': '1.8.9p5-1ubuntu1.5+esm6', '16.04': '1.8.16-0ubuntu1.10',
                   '18.04': '1.8.21p2-3ubuntu1.4', '20.04': '1.8.31-1ubuntu1.2'},
        'debian': {'9': '1.8.19p1-2.1+deb9u3', '10': '1.8.27-1+deb10u3'}},
}
RULES = {
    'CVE-2024-48990': ('needrestart', ('needrestart',)),
    'CVE-2026-41651': ('packagekit', ('packagekit', 'PackageKit')),
    'CVE-2021-4034': ('policykit-1', ('policykit-1', 'pkexec', 'polkit')),
    'CVE-2021-3156': ('sudo', ('sudo', 'sudo-ldap')),
}
DEB_NAMES = ('needrestart', 'packagekit', 'policykit-1', 'pkexec', 'sudo', 'sudo-ldap')
RPM_NAMES = ('needrestart', 'PackageKit', 'polkit', 'sudo')
LIMIT = 65536
CAVEAT = ('Installed package versions do not prove an active daemon/binary was replaced or restarted; '
          'activation, custom patches, mount/nosuid, namespace and runtime policy are not verified.')


def read_regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise OSError('not a regular file')
        data = stream.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise OSError('read limit exceeded')
    return data.decode('utf-8', 'strict')


def os_release(root):
    """Parse assignments as data, without expansion, shell sourcing or ID_LIKE."""
    values = {}
    for line in read_regular(root / 'etc/os-release').splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = re.fullmatch(r'([A-Z_]+)=(?:"([^"\\]*)"|\'([^\'\\]*)\'|([a-zA-Z0-9._-]*))', line)
        if not match or match[1] in values:
            raise ValueError('malformed/duplicate os-release assignment')
        values[match[1]] = next(v for v in match.groups()[1:] if v is not None)
    return values.get('ID', ''), values.get('VERSION_ID', '')


def native_run(args):
    """Only fixed, trusted native metadata utilities, never PATH discovery."""
    if args[0] not in ('/usr/bin/dpkg-query', '/usr/bin/dpkg', '/usr/bin/rpm'):
        raise ValueError('not an allowed metadata utility')
    metadata = os.stat(args[0])
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
            or metadata.st_mode & 0o022 or not metadata.st_mode & 0o111):
        raise OSError('untrusted metadata utility')
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=8, check=False, text=True,
                            env={'LC_ALL': 'C', 'LANG': 'C', 'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent'})
    if len(result.stdout) + len(result.stderr) > LIMIT:
        raise OSError('native output limit exceeded')
    return result


def query_packages(root, manager, runner):
    """Return records and package-scoped gaps. Only exact native absence diagnostics count."""
    names = DEB_NAMES if manager == 'dpkg' else RPM_NAMES
    if manager == 'dpkg':
        fmt = '${binary:Package}\t${Status}\t${Version}\t${source:Package}\t${source:Version}\t${Origin}\t${Maintainer}\n'
        args = ['/usr/bin/dpkg-query', '--admindir=' + str(root / 'var/lib/dpkg'), '-W', '-f=' + fmt, *names]
    else:
        fmt = '%{NAME}\tinstalled\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{SOURCERPM}\t\t%{VENDOR}\t%{PACKAGER}\n'
        args = ['/usr/bin/rpm', '--root', str(root), '-q', '--qf', fmt, *names]
    records, gaps, absent = {}, {}, set()
    try:
        result = runner(args)
        if len(result.stdout) + len(result.stderr) > LIMIT or result.returncode not in (0, 1):
            raise ValueError('native query failed/truncated')
        rows = result.stdout.splitlines()
        diagnostics = result.stderr.splitlines()
        for line in rows + diagnostics:
            missing = re.fullmatch(r'dpkg-query: no packages found matching ([a-z0-9-]+)', line) if manager == 'dpkg' else re.fullmatch(r'package ([A-Za-z0-9-]+) is not installed', line)
            if missing and missing[1] in names and result.returncode == 1:
                absent.add(missing[1])
                continue
            fields = line.split('\t')
            name = fields[0].split(':')[0]
            if line in diagnostics or name not in names:
                raise ValueError('unrecognized native query diagnostic/record')
            if name in records or name in gaps or name in absent or len(fields) != 7:
                gaps[name] = 'malformed/duplicate package record'
                records.pop(name, None)
                continue
            _, state, version, source, source_version, origin, maintainer = fields
            if manager == 'dpkg' and re.fullmatch(r'(?:install|hold|deinstall|purge|unknown) ok (?:not-installed|config-files)', state):
                absent.add(name)
                continue
            installed = state == 'installed' if manager == 'rpm' else bool(re.fullmatch(r'(?:install|hold) ok installed', state))
            if not installed or not version or not source or (manager == 'dpkg' and not source_version):
                gaps[name] = 'nonempty invalid installed package record/state'
                continue
            records[name] = dict(package=name, version=version, source=source,
                                 source_version=source_version, origin=origin, maintainer=maintainer, manager=manager)
            if manager == 'rpm':
                # SOURCERPM lacks a source epoch; preserve it verbatim, do not invent one.
                match = re.fullmatch(r'(.+)-(\d[^-]*)-([^-]+)\.src\.rpm', source)
                records[name]['source_rpm'] = source
                records[name]['source_package'] = match[1] if match else None
                records[name]['source_version'] = match[2] + '-' + match[3] if match else ''
        if result.returncode == 1 and not absent:
            raise ValueError('nonzero query without proven package absence')
        if set(records) & absent:
            raise ValueError('contradictory native package state')
        for name in names:
            if name not in records and name not in absent:
                gaps.setdefault(name, 'query omitted package state')
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        return {}, {name: 'package query unavailable: ' + str(exc) for name in names}
    return records, gaps


def vendor_build(record, vendor, fixed):
    """Narrow source lineage + vendor metadata; not cryptographic authentication.

    dpkg normally has no Origin field: an official Maintainer is then required.
    Custom epochs, PPAs, binNMU source mismatches and unreviewed backports stay unknown.
    """
    if record['manager'] != 'dpkg' or record['origin'] not in ('', vendor.capitalize()):
        return False
    domain = r'(?:[a-z0-9-]+\.)*ubuntu\.com|canonical\.com' if vendor == 'ubuntu' else r'(?:[a-z0-9-]+\.)*debian\.org'
    if not re.search(r'<[^<>@\s]+@(?:' + domain + r')>$', record['maintainer']):
        return False
    version = record['source_version']
    if re.sub(r'^0:', '', record['version']) != re.sub(r'^0:', '', version):
        return False
    base, revision = fixed.rsplit('-', 1)
    if vendor == 'debian':
        rev, release = revision.split('+deb')
        pattern = re.escape(rev) + r'(?:\+deb' + release.split('u')[0] + r'u\d+)?'
    else:
        stem = re.split(r'[+~]esm', revision)[0]
        # Allow numeric updates only within the exact vendor source lineage.
        stem = re.sub(r'\.\d+$', '', stem) if '.' in stem.split('ubuntu')[-1] else stem
        pattern = re.escape(stem) + r'(?:\.\d+)*'
        if 'esm' in revision:
            pattern += r'(?:' + re.escape('~' if '~esm' in revision else '+') + r'esm\d+)?'
    return bool(re.fullmatch(r'(?:0:)?' + re.escape(base) + '-' + pattern, version))


def version_status(version, fixed, runner):
    result = runner(['/usr/bin/dpkg', '--compare-versions', version, 'lt', fixed])
    if result.returncode not in (0, 1) or result.stdout or result.stderr:
        raise ValueError('native version comparison failed')
    return 'affected' if result.returncode == 0 else 'installed-fixed'


def privileged(root, name):
    path = root / ('usr/bin/' + name)
    metadata = os.lstat(path)
    if not stat.S_ISREG(metadata.st_mode):
        raise OSError('privileged path is not a regular file')
    if metadata.st_uid != 0 or not metadata.st_mode & 0o111:
        return 'disabled'
    if metadata.st_mode & stat.S_ISUID:
        return 'root-owned SUID executable: /usr/bin/' + name
    if name == 'sudo':
        try:
            caps = os.getxattr(path, 'security.capability')
            if caps:
                raise ValueError('sudo file capabilities present but privilege semantics unverified')
        except OSError as exc:
            if exc.errno not in (errno.ENODATA, errno.ENOTSUP):
                raise
    return 'disabled'


def needrestart_surface(root):
    paths = [root / 'etc/needrestart/needrestart.conf']
    directory = root / 'etc/needrestart/conf.d'
    try:
        with os.scandir(directory) as entries:
            for count, entry in enumerate(entries):
                if count >= 64:
                    raise OSError('needrestart config entry limit exceeded')
                if entry.name.endswith('.conf'):
                    paths.append(Path(entry.path))
    except FileNotFoundError:
        pass
    enabled = '1'
    for path in [paths[0], *sorted(paths[1:])]:
        for line in read_regular(path).splitlines():
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            match = re.fullmatch(r'''\$nrconf\{(?:interpscan|'interpscan'|"interpscan")\}\s*=\s*([01]);''', line)
            if not match:
                raise ValueError('needrestart includes/dynamic or unrecognized Perl; no mitigation inferred')
            enabled = match[1]
    return 'disabled' if enabled == '0' else 'static interpreter scanning enabled/default; root invocation not verified'


def packagekit_surface(root):
    evidence = []
    for name in ('usr/share/dbus-1/system-services/org.freedesktop.PackageKit.service',
                 'usr/lib/systemd/system/packagekit.service', 'lib/systemd/system/packagekit.service',
                 'etc/systemd/system/packagekit.service'):
        path = root / name
        try:
            metadata = os.lstat(path)
            if not stat.S_ISREG(metadata.st_mode):
                raise OSError('activation metadata is not a regular file: ' + name)
            evidence.append('/' + name)
        except FileNotFoundError:
            continue
    if not evidence:
        raise OSError('PackageKit activation metadata unavailable; running daemon unknown')
    return 'activation path metadata only (not enabled/running proof): ' + ', '.join(evidence)


def upstream_candidate(cve, version):
    """Deep-only hints; NEVER use upstream boundaries to clear a vendor build."""
    match = re.match(r'(?:\d+:)?(\d+)\.(\d+)(?:\.(\d+))?(?:p(\d+))?', version)
    if not match:
        return False
    value = tuple(int(v or 0) for v in match.groups())
    if cve == 'CVE-2024-48990':
        return value < (3, 8, 0, 0)
    if cve == 'CVE-2026-41651':
        return (1, 0, 2, 0) <= value <= (1, 3, 4, 0)
    if cve == 'CVE-2021-4034':
        return value < (0, 120, 0, 0)  # Pin's heuristic only; upstream 0.120 is NOT a vendor fix.
    return (1, 8, 2, 0) <= value < (1, 9, 5, 2)


def scan(deep=False, *, root=Path('/'), runner=None):
    root, runner = Path(root), runner or native_run
    findings, raw, incomplete, details = [], [CAVEAT], set(), []
    try:
        vendor, release = os_release(root)
    except (OSError, ValueError, UnicodeError) as exc:
        vendor, release = '', ''
        details.append('os-release unavailable: ' + str(exc))
    manager = 'dpkg' if vendor in ('debian', 'ubuntu') else 'rpm'
    records, gaps = query_packages(root, manager, runner)
    raw.append('Userspace release: %s %s; package manager: %s' % (vendor, release, manager))
    for cve, (source, packages) in RULES.items():
        test_id = 'package:' + cve
        applicable = [p for p in packages if p in (DEB_NAMES if manager == 'dpkg' else RPM_NAMES)]
        if any(p in gaps for p in applicable):
            incomplete.add(test_id)
            details.extend(p + ': ' + gaps[p] for p in applicable if p in gaps)
        for package in applicable:
            record = records.get(package)
            if not record:
                continue
            raw.append(test_id + ': ' + repr(record))
            fixed = FIXES[cve].get(vendor, {}).get(release)
            status, surface = 'unknown', 'unknown'
            try:
                if fixed and record['source'] == source and vendor_build(record, vendor, fixed):
                    status = version_status(record['source_version'], fixed, runner)
                if cve == 'CVE-2024-48990':
                    surface = needrestart_surface(root)
                elif cve == 'CVE-2026-41651':
                    surface = packagekit_surface(root)
                else:
                    surface = privileged(root, 'pkexec' if cve == 'CVE-2021-4034' else 'sudo')
            except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired) as exc:
                details.append(test_id + ': ' + str(exc))
            raw.append(test_id + ': ' + status + '; ' + surface)
            if status == 'unknown' or surface == 'unknown':
                incomplete.add(test_id)
                details.append(test_id + ': vendor/source lineage or prerequisite unverified')
            if surface == 'disabled':
                continue
            # A patched disk package cannot clear a previously affected running daemon.
            if cve == 'CVE-2026-41651' and status == 'installed-fixed':
                incomplete.add(test_id)
                details.append(test_id + ': installed fix found; active daemon restart/replacement unknown')
            heuristic = status == 'unknown' and deep and upstream_candidate(cve, record['version'])
            if (status == 'affected' and surface != 'unknown') or heuristic:
                findings.append({'id': test_id, 'severity': 'review' if heuristic else 'warning',
                                 'summary': cve + (': unverified upstream-version candidate; vendor backports unknown' if heuristic else ': installed vendor build below reviewed fix; passive candidate'),
                                 'context': dict(record, fixed_version=fixed, surface=surface,
                                                 certainty='version-only heuristic' if heuristic else 'metadata candidate, not exploit proof', limitation=CAVEAT)})
    if incomplete:
        findings.append({'id': 'scanner-package-coverage', 'severity': 'warning',
                         'summary': 'Targeted package CVE coverage incomplete',
                         'context': {'checks': sorted(incomplete), 'details': sorted(set(details))}})
    result = {'findings': findings, 'raw': '\n'.join(raw + sorted(set(details))), 'errors': []}
    if incomplete:
        result['incomplete_ids'] = sorted(incomplete)
    return result
