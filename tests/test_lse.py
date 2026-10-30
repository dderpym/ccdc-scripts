"""Offline LSE fixtures, real subprocesses, and optional local Ansible transport.

No production-host scans, downloads, privilege escalation or network needed.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from test_controller import ROOT, load

lse = load('discover-lse')
SUPPLEMENTAL_SCAN = lse.supplemental_scan


def block(test_id, summary, body, marker='!', status='yes!'):
    return '[%s] %s %s....... %s\n---\n%s\n---\n' % (marker, test_id, summary, status, body)


FIXTURE = (
    '\x1b[32m LSE Version: 4.14nw\x1b[0m\n User ID: 1000\n Hostname: fixture\n'
    + block('fst000', 'Writable files outside home', '/tmp/inventory', '*')
    + block('fst010', 'Binaries with setuid bit', '/usr/bin/sudo', '*')
    + block('fst030', 'Writable setuid binaries', '/opt/suid\n/opt/suid')
    + block('fst160', 'Writable critical files', '-rw-rw-r-- 1 root staff 432 Oct 5 10:22 /etc/sudoers')
    + block('fst210', 'NFS exports', '# /disabled *(no_root_squash)\n/export *(rw,no_root_squash)')
    + block('fst210', 'NFS exports', '/ignored *(no_root_squash)', status='nope')
    + block('sys020', 'Passwd hashes', 'locked:!:1:1::/:/bin/sh\nempty::2000:2000::/:/bin/sh')
    + block('sys030', 'Readable shadow', '/etc/shadow\n---\nroot:$6$SECRET:20000:0:99999:7:::')
    + block('sys040', 'Other superusers', 'backdoor', '*')
    + block('ret050', 'Writable cron paths', '/opt/jobs/config', '*')
    + block('sof020', 'PostgreSQL template0 as postgres', 'version')
    + block('sof020', 'PostgreSQL template1 as postgres', 'version')
    + block('sof020', 'PostgreSQL template0 as psql', 'version')
    + block('sof020', 'PostgreSQL template1 as psql', 'version')
    + block('sof020', 'PostgreSQL template1 as psql', 'version')
    + block('sof000', 'MySQL root/root', 'Server version 8.0\nUptime: 2381\nThreads: 2 Questions: 7')
    + block('sys060', 'Shell inventory', '/bin/bash', 'i')
    + block('srv500', 'Writable systemd services', '/etc/systemd/hidden.service', status='skip')
    + '================( FINISHED )================\n'
)


def passive_fixtures(directory):
    """A private host/ package whose passive helpers are stubs: real wrapper, no host scan."""
    package = Path(directory) / 'host'
    package.mkdir(parents=True, exist_ok=True)
    (package / '__init__.py').write_text('')
    (package / 'lse_extras.py').write_text(
        "def scan(raw, capability_status=None):\n    return {'findings': [], 'raw': '', 'errors': []}\n")
    (package / 'kernel_risks.py').write_text(
        "def inspect_kernel(deep=False):\n    return {'findings': [], 'raw': '', 'errors': []}\n")
    (package / 'lse_host_risks.py').write_text(
        "def scan(deep=False):\n    return {'findings': [], 'raw': '', 'errors': []}\n")
    shutil.copyfile(ROOT / 'host/discover_lse.py', package / 'discover_lse.py')
    return [sys.executable, '-m', 'host.discover_lse']


class LSETests(unittest.TestCase):
    def setUp(self):
        patcher = patch.object(lse, 'supplemental_scan', return_value=[])
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_supplemental_findings_raw_and_scoped_coverage_share_contract(self):
        extra = {'findings': [{'id': 'extra-loader', 'severity': 'warning', 'summary': 'loader path writable'}],
                 'raw': 'passive metadata', 'errors': [], 'incomplete_ids': ['kernel:CVE-2026-31431']}
        failure = {'findings': [], 'raw': '', 'errors': ['kernel helper failed']}
        with patch.object(lse, 'scan_lse', return_value=lse.parse(FIXTURE)), \
                patch.object(lse, 'supplemental_scan', return_value=[extra, failure]) as supplements:
            result = lse.scan('/fixture/lse.sh', deep=True)
        supplements.assert_called_once_with(FIXTURE, True, None)
        self.assertIn('extra-loader', {f['id'] for f in result['findings']})
        self.assertIn('fst030', {f['id'] for f in result['findings']})
        self.assertIn('passive metadata', result['raw'])
        self.assertIn(FIXTURE, result['raw'])
        self.assertEqual(result['incomplete_ids'], ['kernel:CVE-2026-31431'])
        self.assertEqual(result['errors'], ['kernel helper failed'])

    def test_every_supplemental_helper_is_local_and_failure_is_isolated(self):
        calls = []
        state = {'findings': [], 'raw': '', 'errors': []}

        def helper(name):
            def scan(*args):
                calls.append((name, args))
                return dict(state)
            return scan

        with patch.object(lse.lse_extras, 'scan', helper('lse_extras')), \
                patch.object(lse.kernel_risks, 'inspect_kernel', side_effect=ValueError('fixture failure')), \
                patch.object(lse.lse_host_risks, 'scan', helper('lse_host_risks')):
            states = SUPPLEMENTAL_SCAN('fixture raw', True, 7)
        self.assertEqual(len(states), 3)
        self.assertEqual(calls, [('lse_extras', ('fixture raw', 7)),
                                 ('lse_host_risks', (True,))])
        self.assertEqual(states[1]['errors'], ['kernel_risks: fixture failure'])
        self.assertEqual(states[2:], [state])

    def test_native_capability_exit_receipt_does_not_repeat_enumeration(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / 'native-getcap'
            calls = Path(directory) / 'calls'
            fake.write_text('#!/bin/sh\nprintf "call\\n" >> ' + str(calls) + '\nexit 7\n')
            fake.chmod(0o700)
            script = Path(directory) / 'fixture-lse.sh'
            script.write_text('#!/bin/sh\ngetcap -r /\nprintf "[!] sec010 Capabilities nope\\n"\n')
            with patch.object(lse, 'coverage', return_value=[]), \
                    patch.object(lse.shutil, 'which', return_value=str(fake)):
                result = lse.scan_lse(script)
            self.assertEqual(result['_capability_status'], 7)
            self.assertEqual(calls.read_text().splitlines(), ['call'])
            self.assertIn('sec010', result['raw'])

    def test_affirmative_actionable_only_and_multiple_independent_contexts(self):
        result = lse.parse(FIXTURE)
        by_id = {finding['id']: finding for finding in result['findings']}
        self.assertEqual(set(result), {'findings', 'raw', 'errors'})
        self.assertEqual(set(by_id), {'fst030', 'fst160', 'fst210', 'sys020', 'sys030', 'sys040', 'ret050', 'sof020', 'sof000'})
        self.assertEqual(by_id['sys040']['severity'], 'critical')
        self.assertEqual(by_id['ret050']['severity'], 'warning')
        self.assertEqual(by_id['ret050']['context'][0]['evidence'], ['/opt/jobs/config'])
        self.assertEqual(len(by_id['sof020']['context']), 4)
        self.assertEqual(by_id['fst030']['context'][0]['evidence'], ['/opt/suid'])
        self.assertEqual(by_id['sys030']['context'][0]['evidence'], ['/etc/shadow'])
        self.assertEqual(by_id['fst160']['context'][0]['evidence'], ['-rw-rw-r-- root staff /etc/sudoers'])
        for unwanted in ('SECRET', 'inventory', 'fixture', 'Uptime', 'Threads', 'Oct 5', '/disabled', '/ignored', 'locked:', 'hidden.service', '\x1b'):
            self.assertNotIn(unwanted, json.dumps(result['findings']))
        self.assertEqual(result['raw'], FIXTURE)
        self.assertEqual(result['errors'], [])
        self.assertEqual(by_id['fst210']['severity'], 'critical')
        self.assertIn('sys040', {finding['id'] for finding in lse.parse(FIXTURE, deep=True)['findings']})

    def test_long_titles_without_dot_padding_are_not_lost(self):
        text = '[!] sof010 Can we connect to mysql as root without password and execute commands? yes!\n---\nServer version 8\n---\n'
        finding = lse.parse(text)['findings'][0]
        self.assertEqual(finding['id'], 'sof010')
        self.assertFalse(finding['context'][0]['summary'].endswith('.'))

    def test_normalized_reruns_identical_without_losing_distinct_evidence(self):
        first = FIXTURE + block('fst200', 'Possible history credentials',
                                '2026-10-05T10:20:30Z PID=812 login=test\nRuntime: 3.1s\nElapsed: 4s')
        second = first.replace('Oct 5 10:22', 'Nov 6 2025').replace('432', '999')
        second = second.replace('2026-10-05T10:20:30Z', '2027-11-06T11:21:31Z').replace('PID=812', 'PID=991')
        self.assertEqual(lse.parse(first)['findings'], lse.parse(second)['findings'])
        text = block('fst030', 'Writable setuid binaries', '/opt/a') + block('fst030', 'Writable setuid binaries', '/opt/b')
        self.assertEqual(len(lse.parse(text)['findings'][0]['context']), 2)
        sockets = block('sof160', 'Writable screen sockets', 'srw-rw-rw- 1 other other 0 Oct 5 10:22 /run/screen/S-other/123.pts-0.host')
        self.assertEqual(lse.parse(sockets)['findings'], lse.parse(sockets.replace('/123.', '/999.'))['findings'])
        mongo = block('sof170', 'MongoDB without credentials', 'admin 0.005GB', '*')
        self.assertEqual(lse.parse(mongo, True)['findings'], lse.parse(mongo.replace('0.005GB', '1.000GB'), True)['findings'])

    def test_negative_skipped_warning_and_inventory_not_findings(self):
        text = block('fst030', 'Writable setuid', '/fake', status='skip')
        text += block('fst030', 'Writable setuid', '/fake', status='nope')
        text += block('fst030', 'Writable setuid', 'WARNING: missing utility')
        text += block('net550', 'TCP inventory', '0.0.0.0:80', 'i')
        text += block('sys020', 'Passwd hashes', 'locked:*:1:1\nlocked2:!!:2:2')
        self.assertEqual(lse.parse(text), {'findings': [], 'raw': text, 'errors': []})

    def test_root_permissions_not_misreported_as_vulnerabilities(self):
        text = FIXTURE.replace('User ID: 1000', 'User ID: 0')
        ids = {finding['id'] for finding in lse.parse(text)['findings']}
        self.assertNotIn('fst030', ids)
        self.assertNotIn('sys030', ids)
        self.assertIn('fst210', ids)
        self.assertIn('LSE ran as root; permission checks cannot assess an unprivileged account', lse.parse(text)['errors'])

    def test_pin_and_selection_match_actual_upstream_source(self):
        data = (ROOT / 'vendor/lse.sh').read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), 'a0c526f560189c81bc66303b81e828edabc68deed7e7bd28aed55a792c6d25c3')
        source = data.decode()
        self.assertIn('lse_version="4.14nw"', source)
        for test_id in lse.selection(True).split(','):
            self.assertIn('lse_test "%s"' % test_id, source)
        self.assertIn('sys040', lse.SELECTION.split(','))
        self.assertEqual(sum(level == 0 for level, _, _ in lse.TESTS.values()), 30)
        self.assertEqual(len(lse.SELECTION.split(',')), 34)
        for deep_only in ('sof170', 'srv020', 'srv030', 'srv040', 'srv050', 'srv520'):
            self.assertNotIn(deep_only, lse.SELECTION.split(','))
        self.assertIn('sys040', lse.selection(True).split(','))
        for test_id in ('fst000', 'fst010', 'usr070', 'sec010', 'ret050'):
            self.assertIn(test_id, lse.SELECTION.split(','))
        for omitted in ('net010', 'pro000', 'sys060', 'srv010', 'srv510', 'ctn010', 'cve'):
            self.assertNotIn(omitted, lse.SELECTION.split(','))

    def test_pinned_flags_execute_without_interaction_or_monitor_wait(self):
        # Only a harmless account check; never run a full scan of the test host.
        with tempfile.TemporaryDirectory() as directory:
            env = dict(os.environ, TMPDIR=directory, LC_ALL='C')
            result = subprocess.run(['/bin/sh', str(ROOT / 'vendor/lse.sh'), '-c', '-i', '-l', '1', '-p', '0', '-s', 'sys040'],
                                    stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('sys040', result.stdout)
            self.assertIn('Current Output Verbosity Level: 1', result.stdout)
            self.assertNotIn('\x1b', result.stdout)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_cli_execution_default_deep_and_warnings(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / 'fixture with spaces.sh'
            script.write_text('#!/bin/sh\ncase "$8" in "' + lse.SELECTION + '"|"' + lse.selection(True) + '") ;; *) exit 9;; esac\n'
                              '[ "$1 $2 $3 $4 $5 $6 $7" = "-c -i -l 1 -p 0 -s" ] || exit 9\n'
                              'read answer && exit 8\n'
                              'printf "%s\\n" "level=$4" "selection=$8" >&2\n'
                              "cat <<'OUTPUT'\n" + FIXTURE + 'OUTPUT\nexit 3\n')
            command = passive_fixtures(directory)
            for deep in (False, True):
                args = command + ['--script', str(script)]
                result = subprocess.run(args + (['--deep'] if deep else []), capture_output=True, text=True,
                                        timeout=10, cwd=directory)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, '')
                state = json.loads(result.stdout)
                self.assertIn('level=1', state['errors'])
                self.assertIn('selection=' + lse.selection(deep), state['errors'])
                self.assertIn('LSE exited with status 3; findings may be incomplete', state['errors'])
                self.assertEqual(state['findings'], lse.parse(FIXTURE, deep)['findings'])
                self.assertIn(FIXTURE, state['raw'])
                self.assertIn('level=1', state['raw'])

    def test_missing_script_returns_json_error(self):
        with tempfile.TemporaryDirectory() as directory:
            command = passive_fixtures(directory)
            result = subprocess.run(command + ['--script', '/nonexistent/ccdc/lse.sh'],
                                    capture_output=True, text=True, timeout=10, cwd=directory)
        state = json.loads(result.stdout)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(state['findings'], [])
        self.assertTrue(state['errors'])

    def test_expected_oski_sudo_is_raw_evidence_not_an_alert(self):
        raw = FIXTURE + block('sud000', 'Sudo without password', 'uid=0(root) gid=0(root)')
        process = MagicMock()
        process.__enter__.return_value = process
        process.returncode = 0
        process.communicate.return_value = (raw, '')
        # Policy follows the effective account, not the spoofable USER variable
        # or the upstream banner. Unknown accounts fail closed.
        for account in ('oski', 'other', None):
            with self.subTest(account=account), \
                    patch.dict(lse.os.environ, {'USER': 'oski'}), \
                    patch.object(lse, 'coverage', return_value=[]), \
                    patch.object(lse.subprocess, 'Popen', return_value=process), \
                    patch('pwd.getpwuid', side_effect=KeyError if account is None else None,
                          return_value=MagicMock(pw_name=account)):
                state = lse.scan('/pinned/lse.sh')
            by_id = {finding['id']: finding for finding in state['findings']}
            self.assertEqual('sud000' in by_id, account != 'oski')
            if account != 'oski':
                self.assertEqual(by_id['sud000']['severity'], 'critical')
            self.assertIn('fst160', by_id)
            self.assertIn('sys040', by_id)
            self.assertEqual(state['raw'], raw)

    def test_unprivileged_login_path_can_still_find_admin_utilities(self):
        process = MagicMock()
        process.__enter__.return_value = process
        process.returncode = 0
        process.communicate.return_value = (FIXTURE, '')
        with patch.dict(lse.os.environ, {'PATH': '/usr/bin:/bin'}), \
                patch.object(lse, 'coverage', return_value=[]), \
                patch.object(lse.subprocess, 'Popen', return_value=process) as popen:
            lse.scan('/pinned/lse.sh')
        self.assertIn('/usr/sbin', popen.call_args.kwargs['env']['PATH'].split(':'))

    def test_optional_utility_gaps_are_explicit_and_scoped(self):
        with patch.object(lse.shutil, 'which', return_value=None):
            gaps = lse.coverage('/unused')
        self.assertEqual({gap[0] for gap in gaps}, {'find', 'getcap', 'sudo'})
        with patch.object(lse.shutil, 'which', return_value='/usr/bin/tool'), \
                patch.object(lse.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, b'', b'unsupported -writable')):
            busybox = lse.coverage('/unused')
        self.assertEqual(busybox[0][0], 'find-writable')
        self.assertIn('fst160', busybox[0][2])
        process = MagicMock()
        process.__enter__.return_value = process
        process.returncode = 0
        process.communicate.return_value = (FIXTURE, '')
        with patch.object(lse.subprocess, 'Popen', return_value=process), patch.object(lse, 'coverage', return_value=busybox):
            state = lse.scan('/pinned/local.sh')
        self.assertFalse(state['errors'])
        self.assertIn('fst160', state['incomplete_ids'])
        self.assertIn('scanner-find-writable', {f['id'] for f in state['findings']})
        self.assertEqual(state['raw'], FIXTURE)

    def test_timeout_kills_children_keeps_partial_and_cleans_scratch(self):
        process = MagicMock()
        process.__enter__.return_value = process
        process.pid = 123456
        process.returncode = -9
        process.communicate.side_effect = [subprocess.TimeoutExpired('lse', 180), (FIXTURE, 'warning: partial scan\n')]
        with patch.object(lse.subprocess, 'Popen', return_value=process) as popen, \
                patch.object(lse.os, 'killpg') as kill, patch.object(lse, 'coverage', return_value=[]):
            state = lse.scan('/local/pinned.sh')
        kill.assert_called_once_with(123456, lse.signal.SIGKILL)
        self.assertTrue(state['findings'])
        self.assertIn('LSE timed out after 180 seconds; findings may be incomplete', state['errors'])
        self.assertFalse(Path(popen.call_args.kwargs['env']['TMPDIR']).exists())
        self.assertTrue(popen.call_args.kwargs['start_new_session'])


if __name__ == '__main__':
    unittest.main()


class PermissionFixTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.lse = load('discover-lse')

    def fixes(self, test_id, *lines):
        return self.lse.permission_fixes(test_id, [{'evidence': list(lines)}])

    def test_path_and_listing_evidence_strip_group_other_write(self):
        suid, conf = self.root / 'suid', self.root / 'conf'
        suid.write_text('x')
        conf.write_text('x')
        suid.chmod(0o4777)
        conf.chmod(0o666)
        fixes = self.fixes('fst030', str(suid)) + self.fixes('fst160', f'-rw-rw-rw- {os.getuid()} {os.getgid()} {conf}')
        self.assertEqual([f['mode'] for f in fixes], [0o4755, 0o644])
        self.assertEqual({f['tier'] for f in fixes}, {'simple' if os.getuid() == 0 else 'all'})

    def test_path_dirs_keep_owner_and_shadow_only_loses_other_access(self):
        path = self.root / 'bin'
        path.mkdir()
        path.chmod(0o777)
        fix, = self.fixes('fst180', f'drwxrwxrwx {os.getuid()} {os.getgid()} {path}')
        self.assertEqual((fix['mode'], fix['uid'], fix['tier']), (0o755, os.getuid(), 'simple'))
        shadow = self.root / 'shadow'
        shadow.write_text('x')
        shadow.chmod(0o644)
        fix, = self.fixes('sys030', str(shadow))
        self.assertEqual(fix['mode'], 0o640)

    def test_symlinks_sticky_dirs_missing_and_clean_paths_get_no_fix(self):
        target, sticky, clean = self.root / 't', self.root / 's', self.root / 'c'
        target.write_text('x')
        target.chmod(0o666)
        (self.root / 'link').symlink_to(target)
        sticky.mkdir()
        sticky.chmod(0o1777)
        clean.write_text('x')
        clean.chmod(0o600)
        evidence = [str(self.root / 'link'), str(sticky), str(clean), str(self.root / 'missing'), 'relative']
        self.assertEqual(self.fixes('fst180', *evidence), [])
