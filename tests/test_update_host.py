"""Offline update safety tests: no native package/service mutations."""
import contextlib
import copy
import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('manage_updates', str(ROOT / 'scripts/manage-updates'))
spec = importlib.util.spec_from_loader(loader.name, loader)
updates = importlib.util.module_from_spec(spec)
loader.exec_module(updates)

APT = '''Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following packages will be upgraded:
  nginx
1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
Inst nginx [1.24.0-1] (1.24.0-2 Debian:12/stable [amd64])
Conf nginx (1.24.0-2 Debian:12/stable [amd64])
'''
APK = '(1/1) Upgrading nginx (1.24.0-r0 -> 1.24.0-r1)\nOK: 30 MiB in 24 packages\n'


def completed(stdout='', rc=0, stderr=''):
    return subprocess.CompletedProcess([], rc, stdout, stderr)


class UpdateHostTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.backup_root = self.directory / 'backups'
        self.token = 'abcdef12' * 4
        self.plan = {'schema': 2, 'manager': 'apt', 'platform': {'id': 'debian', 'version': '12'},
                     'init': 'systemd', 'installed': {'curl': '1', 'nginx': '1.24.0-1',
                                                    'sudo': '1', 'zlib1g': '1.2.13'},
                     'repositories': 'a' * 64, 'candidates': [
                         {'name': 'curl', 'old': '1', 'new': '2', 'risk': 'lower',
                          'reason': updates.risk_reason('curl')},
                         {'name': 'nginx', 'old': '1.24.0-1', 'new': '1.24.0-2', 'risk': 'lower',
                          'reason': updates.risk_reason('nginx')},
                         {'name': 'sudo', 'old': '1', 'new': '2', 'risk': 'manual',
                          'reason': updates.risk_reason('sudo')}],
                     'changes': [{'name': 'nginx', 'old': '1.24.0-1', 'new': '1.24.0-2'}],
                     'selected': ['nginx'], 'held': ['sudo: ' + updates.risk_reason('sudo')]}
        self.snapshot = dict(self.plan, changes=[], selected=[])
        self.addCleanup(patch.stopall)
        patch.object(updates, 'BACKUP_ROOT', self.backup_root).start()

    def selection_mocks(self):
        patch.object(updates, 'make_plan', return_value=copy.deepcopy(self.snapshot)).start()
        patch.object(updates, 'installed', return_value=self.plan['installed']).start()
        patch.object(updates, 'repositories', return_value=self.plan['repositories']).start()

    def select(self, packages=None, snapshot=None):
        return updates.select_plan(snapshot or self.snapshot,
                                   ['nginx'] if packages is None else packages,
                                   'apt', self.plan['platform'], 'systemd')

    def apply_mocks(self):
        patch.object(updates, 'select_plan', return_value=copy.deepcopy(self.plan)).start()
        patch.object(updates, 'installed', return_value=dict(self.plan['installed'], nginx='1.24.0-2')).start()
        patch.object(updates, 'disk_check').start()
        patch.object(updates, 'trusted_directory').start()
        patch.object(updates, 'config_paths', return_value=[]).start()
        patch.object(updates, 'capture_selection', return_value=(None, None, None)).start()
        patch.object(updates, 'restore_selection').start()
        self.archive = patch.object(updates.tarfile, 'open').start().return_value.__enter__.return_value

    def do_apply(self, plan=None):
        return updates.apply(plan or self.plan, self.token, 'apt', self.plan['platform'], 'systemd')

    def test_apt_suggestions_and_recommendations_do_not_authorize_installations(self):
        text = APT.replace('The following packages will be upgraded:',
                           'Suggested packages:\n  perl\nRecommended packages:\n  curl\nThe following packages will be upgraded:')
        self.assertEqual(updates.parse_apt(text, self.plan['installed']), self.plan['changes'])
        with self.assertRaises(updates.Refusal):
            updates.parse_apt(text.replace('0 newly installed', '1 newly installed'), self.plan['installed'])

    def test_temporary_package_pins_do_not_persist_as_world_or_auto_marks(self):
        import os
        import stat
        from types import SimpleNamespace
        for manager in ('apk', 'apt'):
            file = self.directory / manager
            file.write_bytes(b'nginx\n')
            fake_info = SimpleNamespace(st_mode=stat.S_IFREG | 0o640, st_uid=0, st_gid=os.getgid())
            with patch.dict(updates.SELECTION_FILES, {manager: file}), \
                    patch.object(updates.Path, 'lstat', return_value=fake_info):
                snapshot = updates.capture_selection(manager)
            file.write_bytes(b'nginx=2\nsudo=1\n')
            with patch.object(updates.os, 'chown'):
                updates.restore_selection(snapshot)
            self.assertEqual(file.read_bytes(), b'nginx\n')
            self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o640)
        absent = self.directory / 'missing'
        with patch.dict(updates.SELECTION_FILES, {'apt': absent}):
            snapshot = updates.capture_selection('apt')
        absent.write_bytes(b'new marks')
        updates.restore_selection(snapshot)
        self.assertFalse(absent.exists())

    def test_plan_refreshes_once_and_never_resolves_a_group(self):
        with patch.object(updates, 'installed', return_value=self.plan['installed']), \
                patch.object(updates, 'repositories', return_value='a' * 64), \
                patch.object(updates, 'disk_check'), \
                patch.object(updates, 'discover', return_value=(self.plan['candidates'], self.plan['held'])), \
                patch.object(updates, 'resolve') as resolve, \
                patch.object(updates, 'run', return_value=completed()) as native:
            result = updates.make_plan('apt', self.plan['platform'], 'systemd', refresh=True)
            self.assertEqual(result, self.snapshot)
            self.assertEqual(native.call_args.args[0][-1], 'update')
            resolve.assert_not_called()
            native.reset_mock()
            updates.make_plan('apt', self.plan['platform'], 'systemd')
            native.assert_not_called()

    def test_security_and_installed_faults_precede_refresh(self):
        for fault in ('installed', 'repositories'):
            with patch.object(updates, 'installed', return_value=self.plan['installed']), \
                    patch.object(updates, 'repositories', return_value='a' * 64), \
                    patch.object(updates, fault, side_effect=updates.Refusal('unsafe')), \
                    patch.object(updates, 'run') as native, self.assertRaises(updates.Refusal):
                updates.make_plan('apt', self.plan['platform'], 'systemd', refresh=True)
            native.assert_not_called()

    def test_selection_freezes_all_declined_and_manual_targets(self):
        self.selection_mocks()
        with patch.object(updates, 'resolve', return_value=self.plan['changes']) as resolve:
            self.assertEqual(self.select(), self.plan)
        self.assertEqual(resolve.call_args.args, (
            'apt', ['curl=1', 'nginx=1.24.0-2', 'sudo=1'], self.plan['installed']))
        # Caller ordering is canonicalized, never an excuse to change the transaction.
        with patch.object(updates, 'resolve', return_value=[
                {'name': 'curl', 'old': '1', 'new': '2'}] + self.plan['changes']):
            result = self.select(['nginx', 'curl'])
        self.assertEqual(result['selected'], ['curl', 'nginx'])

    def test_selection_refuses_manual_unknown_and_duplicate_names(self):
        self.selection_mocks()
        for packages in (['sudo'], ['unknown'], ['nginx', 'nginx'], ['nginx=2'], '--all'):
            with self.subTest(packages=packages), patch.object(updates, 'resolve') as resolve, \
                    self.assertRaises(updates.Refusal):
                self.select(packages)
            resolve.assert_not_called()

    def test_solver_does_not_silently_broaden_and_retains_diagnostics(self):
        self.selection_mocks()
        extra = {'name': 'curl', 'old': '1', 'new': '2'}
        with patch.object(updates, 'resolve', return_value=[extra] + self.plan['changes']), \
                self.assertRaisesRegex(updates.Refusal, 'exclude/retry') as error:
            self.select()
        self.assertEqual(error.exception.details['resolved_changes'][0], extra)
        with patch.object(updates, 'resolve', side_effect=updates.Refusal(
                'Native command failed', native_output='unable to select packages')), \
                self.assertRaises(updates.Refusal) as error:
            self.select()
        self.assertEqual(error.exception.details['native_output'], 'unable to select packages')

    def test_empty_selection_still_holds_all_candidates_and_resolves(self):
        self.selection_mocks()
        with patch.object(updates, 'resolve', return_value=[]) as resolve:
            self.assertEqual(self.select([]), self.snapshot)
        self.assertEqual(resolve.call_args.args[1], ['curl=1', 'nginx=1.24.0-1', 'sudo=1'])
        empty = dict(self.snapshot, candidates=[], held=[])
        with patch.object(updates, 'make_plan', return_value=empty), \
                patch.object(updates, 'resolve') as resolve:
            self.assertEqual(self.select([], empty), empty)
        resolve.assert_not_called()

    def test_entire_snapshot_staleness_including_candidates_and_empty_selection(self):
        self.selection_mocks()
        for field, value in (
                ('installed', dict(self.snapshot['installed'], zlib1g='1.2.14')),
                ('repositories', 'b' * 64), ('platform', {'id': 'debian', 'version': '13'}),
                ('candidates', []), ('held', ['new native hold'])):
            current = dict(self.snapshot, **{field: value})
            with self.subTest(field=field), patch.object(updates, 'make_plan', return_value=current), \
                    patch.object(updates, 'resolve') as resolve, self.assertRaisesRegex(updates.Refusal, 'Stale'):
                self.select([])
            resolve.assert_not_called()

    def test_state_change_during_selection_is_refused(self):
        self.selection_mocks()
        with patch.object(updates, 'resolve', return_value=self.plan['changes']), \
                patch.object(updates, 'installed', return_value=dict(self.plan['installed'], curl='2')), \
                self.assertRaisesRegex(updates.Refusal, 'State changed'):
            self.select()

    def test_expected_exact_schema2_validation(self):
        self.assertEqual(updates.validate_expected(self.plan), self.plan)
        no_held = dict(self.snapshot, held=[])
        del no_held['held']
        self.assertEqual(updates.validate_expected(no_held)['held'], [])
        invalid = []
        for key, value in [('schema', True), ('schema', 1), ('manager', 'yum'),
                           ('platform', 'debian/12'), ('init', 'sysv'), ('installed', {}),
                           ('repositories', 'wrong'), ('changes', {}), ('selected', ['sudo']),
                           ('selected', ['nginx', 'nginx']), ('selected', []),
                           ('held', ['z', 'a']), ('held', ['a', 'a']), ('held', ['bad\n']),
                           ('candidates', {})]:
            invalid.append(dict(self.plan, **{key: value}))
        for key, value in [('name', 'newdep'), ('old', 'wrong'), ('new', None),
                           ('new', '1'), ('risk', 'safe'), ('reason', ''), ('extra', 1)]:
            plan = copy.deepcopy(self.plan)
            plan['candidates'][0][key] = value
            invalid.append(plan)
        plan = copy.deepcopy(self.plan)
        plan['candidates'][-1]['risk'] = 'lower'
        invalid.append(plan)
        invalid += [dict(self.plan, changes=self.plan['changes'] * 2),
                    dict(self.plan, candidates=list(reversed(self.plan['candidates']))),
                    dict(self.plan, policy={})]
        for plan in invalid:
            with self.subTest(plan=plan), self.assertRaises(updates.Refusal):
                updates.validate_expected(plan)

    def test_apt_discovery_includes_manual_and_native_held_candidates(self):
        state = {'curl': '1', 'nginx': '1', 'sudo': '1'}
        policy = ''.join(name + ':\n  Installed: 1\n  Candidate: 2\n  Version table:\n'
                         '     2 500\n        500 https://repo stable/main amd64 Packages\n'
                         ' *** 1 100\n        100 /var/lib/dpkg/status\n' for name in state)
        full = ('The following packages have been kept back:\n  curl\n'
                '2 upgraded, 0 newly installed, 0 to remove and 1 not upgraded.\n')
        for name in ('nginx', 'sudo'):
            full += f'Inst {name} [1] (2 Debian:12/stable [amd64])\nConf {name} (2 Debian:12/stable [amd64])\n'
        def native(argv, **kwargs):
            return completed(policy if argv[0] == 'apt-cache' else full if argv[0] == 'apt-get' else '')
        with patch.object(updates, 'run', side_effect=native) as run:
            candidates, held = updates.discover('apt', state)
        self.assertEqual([x['name'] for x in candidates], ['curl', 'nginx', 'sudo'])
        self.assertEqual([x['risk'] for x in candidates], ['manual', 'lower', 'manual'])
        self.assertIn('held', candidates[0]['reason'])
        self.assertIn('Privilege', candidates[2]['reason'])
        self.assertIn('Native upgrade: 1 packages not upgraded', held)
        commands = [call.args[0] for call in run.call_args_list]
        upgrade = next(argv for argv in commands if argv[0] == 'apt-get')
        self.assertIn('upgrade', upgrade)
        self.assertIn('--no-remove', upgrade)
        self.assertNotIn('dist-upgrade', upgrade)
        self.assertFalse(any('update' in argv for argv in commands))

    def test_apt_candidate_parser_requires_complete_canonical_native_fields(self):
        policy = 'nginx:amd64:\n  Installed: 1\n  Candidate: 2\n  Version table:\n     2 500\n *** 1 100\n'
        with patch.object(updates, 'run', return_value=completed()):
            self.assertEqual(updates.parse_apt_candidates(policy, {'nginx:amd64': '1'}),
                             [{'name': 'nginx:amd64', 'old': '1', 'new': '2'}])
        for text in (policy.replace('Installed: 1', 'Installed: 3'),
                     policy + 'warning\n', policy.replace('Candidate: 2', 'Candidate: bad'),
                     policy.replace('nginx:amd64:', 'newdep:'), policy + policy):
            with self.subTest(text=text), self.assertRaises(updates.Refusal):
                updates.parse_apt_candidates(text, {'nginx:amd64': '1'})
        with patch.object(updates, 'run', return_value=completed(rc=1)):
            self.assertEqual(updates.parse_apt_candidates(policy, {'nginx:amd64': '1'}), [])

    def test_apt_native_architecture_alias_and_pinned_available_upgrades(self):
        text = ('libfoo:\n  Installed: 1\n  Candidate: 1\n  Version table:\n'
                '     2 1 (phased 20%)\n          500 https://repo stable/main amd64 Packages\n'
                ' *** 1 100\n        100 /var/lib/dpkg/status\n'
                'libfoo:i386:\n  Installed: 1\n  Candidate: 2\n  Version table:\n'
                '     2 500\n       1000 https://repo stable/main i386 Packages\n'
                ' *** 1 100\n        100 /var/lib/dpkg/status\n')
        with patch.object(updates, 'run', return_value=completed()):
            result = updates.parse_apt_candidates(text, {'libfoo:amd64': '1', 'libfoo:i386': '1'})
        self.assertEqual(result, [{'name': name, 'old': '1', 'new': '2'}
                                  for name in ('libfoo:amd64', 'libfoo:i386')])
        ambiguous = text.split('libfoo:i386:')[0]
        with self.assertRaises(updates.Refusal):
            updates.parse_apt_candidates(ambiguous, {'libfoo:amd64': '1', 'libfoo:i386': '1'})

    def test_apk_discovery_warns_and_holds_manual_without_blanket_refusal(self):
        state = {'apk-tools': '2.14.0-r0', 'nginx': '1.24.0-r0', 'curl': '1-r0'}
        versions = ('Installed:                               Available:\n'
                    'apk-tools-2.14.0-r0                     < 2.14.1-r0 \n'
                    'curl-1-r0                              < 2-r0 \n'
                    'nginx-1.24.0-r0                        < 1.24.0-r1 \n')
        full = '(1/2) Upgrading apk-tools (2.14.0-r0 -> 2.14.1-r0)\n' + APK.replace('(1/1)', '(2/2)')
        warning = 'WARNING: This simulation is not reliable as apk-tools upgrade is available.'
        def native(argv, **kwargs):
            if 'version' in argv:
                return completed('>\n' if '-t' in argv else versions)
            return completed(full, stderr=warning + '\n')
        with patch.object(updates, 'run', side_effect=native) as run:
            candidates, held = updates.discover('apk', state)
        self.assertEqual([x['risk'] for x in candidates], ['manual', 'manual', 'lower'])
        self.assertIn(warning, held)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertTrue(any('--simulate' in argv and 'upgrade' in argv for argv in commands))
        self.assertFalse(any('update' in argv for argv in commands))

    def test_apk_selection_pins_manual_and_declined_candidates_without_upgrade_flag(self):
        snapshot = {'schema': 2, 'manager': 'apk', 'platform': {'id': 'alpine', 'version': '3.20'},
                    'init': 'openrc', 'installed': {'curl': '1-r0', 'nginx': '1.24.0-r0', 'sudo': '1-r0'},
                    'repositories': 'a' * 64, 'changes': [], 'selected': [], 'held': [],
                    'candidates': [dict(name=name, old=old, new=new, risk=risk,
                                        reason=updates.risk_reason(name)) for name, old, new, risk in (
                        ('curl', '1-r0', '2-r0', 'lower'), ('nginx', '1.24.0-r0', '1.24.0-r1', 'lower'),
                        ('sudo', '1-r0', '2-r0', 'manual'))]}
        def native(argv, **kwargs):
            return completed('>\n' if 'version' in argv else APK)
        with patch.object(updates, 'make_plan', return_value=snapshot), \
                patch.object(updates, 'installed', return_value=snapshot['installed']), \
                patch.object(updates, 'repositories', return_value='a' * 64), \
                patch.object(updates, 'run', side_effect=native) as run:
            result = updates.select_plan(snapshot, ['nginx'], 'apk', snapshot['platform'], 'openrc')
        self.assertEqual(result['selected'], ['nginx'])
        command = run.call_args_list[0].args[0]
        self.assertEqual(command[-3:], ['curl=1-r0', 'nginx=1.24.0-r1', 'sudo=1-r0'])
        self.assertIn('--simulate', command)
        self.assertNotIn('--upgrade', command)
        self.assertEqual(result['candidates'], snapshot['candidates'])

    def test_apk_candidate_parser_matches_installed_names_not_greedy_version_splits(self):
        text = 'Installed:   Available:\nfoo-bar-1-2020 < 2-2021 \n'
        self.assertEqual(updates.parse_apk_candidates(text, {'foo-bar': '1-2020'}),
                         [{'name': 'foo-bar', 'old': '1-2020', 'new': '2-2021'}])
        for bad in (text.replace(' < ', ' > '), text.replace('2-2021', '2@testing'),
                    text + 'unknown\n', text.replace('Installed:', 'wrong:'), text + text.splitlines()[1] + '\n'):
            with self.subTest(text=bad), self.assertRaises(updates.Refusal):
                updates.parse_apk_candidates(bad, {'foo-bar': '1-2020'})

    def test_discovery_refuses_unsafe_native_actions_and_preserves_evidence(self):
        for manager, available, state, native in (
                ('apt', 'nginx:\n  Installed: 1.24.0-1\n  Candidate: 1.24.0-2\n  Version table:\n',
                 {'nginx': '1.24.0-1'}, APT.replace('0 newly installed', '1 newly installed')),
                ('apk', 'Installed: Available:\nnginx-1.24.0-r0 < 1.24.0-r1\n',
                 {'nginx': '1.24.0-r0'}, APK.replace('Upgrading', 'Installing'))):
            def run(argv, **kwargs):
                if argv[0] == 'apt-cache' or '-l' in argv:
                    return completed(available)
                return completed('' if argv[0] == 'dpkg' else native)
            with self.subTest(manager=manager), patch.object(updates, 'run', side_effect=run), \
                    self.assertRaises(updates.Refusal) as error:
                updates.discover(manager, state)
            self.assertEqual(error.exception.details['native_output'], native)
        with patch.object(updates, 'run', side_effect=[completed(
                'Installed: Available:\nnginx-1.24.0-r0 < 1.24.0-r1\n'),
                completed(APK, stderr='WARNING: unknown warning\n')]), self.assertRaises(updates.Refusal) as error:
            updates.discover('apk', {'nginx': '1.24.0-r0'})
        self.assertIn('unknown warning', error.exception.details['native_output'])

    def test_dependency_changes_and_high_risk_are_refused_in_both_resolvers(self):
        for manager in ('apt', 'apk'):
            for name in ('curl', 'sudo'):
                with self.subTest(manager=manager, name=name), \
                        self.assertRaises(updates.Refusal):
                    updates.validate_changes(manager, [{'name': name, 'old': '1', 'new': '2'}],
                                             {name: '1'}, ['nginx'])
        with patch.object(updates, 'run', return_value=completed()) as run, self.assertRaises(updates.Refusal):
            updates.validate_changes('apt', [{'name': 'sudo', 'old': '1', 'new': '2'}], {'sudo': '1'}, ['sudo'])
        run.assert_not_called()
        # Discovery itself can see a high-risk update without authorizing it.
        with patch.object(updates, 'run', return_value=completed()):
            updates.validate_changes('apt', [{'name': 'sudo', 'old': '1', 'new': '2'}], {'sudo': '1'})

    def test_high_risk_categories_all_have_helpful_reasons(self):
        for name in ('linux-image-amd64', 'linux-libc-dev', 'systemd', 'openrc', 'init', 'libc6:amd64',
                     'glibc', 'musl', 'apt', 'dpkg', 'apk-tools', 'libpython3.11', 'python3-minimal',
                     'sudo', 'postgresql-15', 'mysql-server', 'mariadb-server', 'mongodb-org',
                     'redis-server', 'docker-ce', 'containerd.io', 'busybox'):
            with self.subTest(name=name):
                self.assertTrue(updates.high_risk(name))
                self.assertNotIn('Lower-risk', updates.risk_reason(name))

    def test_apply_rediscovery_and_exact_resolution_before_and_after_backup(self):
        self.selection_mocks()
        with patch.object(updates, 'resolve', return_value=self.plan['changes']) as resolve, \
                patch.object(updates, 'backup', return_value={'backup_dir': str(self.directory), 'backup_archive': 'saved'}) as backup, \
                patch.object(updates, 'run', return_value=completed()) as native, \
                patch.object(updates, 'installed', side_effect=[self.plan['installed'], self.plan['installed'],
                                                               dict(self.plan['installed'], nginx='1.24.0-2')]):
            result = self.do_apply()
        self.assertEqual(resolve.call_count, 2)
        self.assertEqual(resolve.call_args.args[1], ['curl=1', 'nginx=1.24.0-2', 'sudo=1'])
        backup.assert_called_once_with(self.plan, self.token)
        self.assertEqual(native.call_count, 1)
        self.assertEqual(native.call_args.args[0][-3:], ['curl=1', 'nginx=1.24.0-2', 'sudo=1'])
        self.assertTrue(result['installation_attempted'])
        self.assertFalse(result['rebooted'])
        self.assertFalse(result['rollback_attempted'])
        self.assertTrue(result['native_hooks_may_restart'])
        self.assertNotIn('services_before', result)

    def test_apply_empty_plan_still_rediscovers_and_resolves_without_mutation(self):
        self.selection_mocks()
        with patch.object(updates, 'resolve', return_value=[]) as resolve, \
                patch.object(updates, 'backup', return_value={'backup_dir': str(self.directory), 'backup_archive': 'saved'}), \
                patch.object(updates, 'run') as native:
            result = self.do_apply(self.snapshot)
        self.assertEqual(resolve.call_count, 2)
        self.assertFalse(result['installation_attempted'])
        native.assert_not_called()
        stale = dict(self.snapshot, repositories='b' * 64)
        with patch.object(updates, 'make_plan', return_value=stale), \
                patch.object(updates, 'backup') as backup, self.assertRaisesRegex(updates.Refusal, 'Stale'):
            self.do_apply(self.snapshot)
        backup.assert_not_called()

    def test_backup_defaults_private_etc_and_native_database_before_install(self):
        self.apply_mocks()
        def native(argv, **kwargs):
            directory = self.backup_root / self.token
            self.assertEqual(json.loads((directory / 'versions.json').read_text()), self.plan['installed'])
            self.assertEqual(json.loads((directory / 'plan.json').read_text()), self.plan)
            self.assertTrue((directory / 'versions.json').stat().st_mode & 0o777 == 0o600)
            self.assertIn('sudo=1', argv)
            return completed('installed\n')
        exists = Path.exists
        with patch.object(updates, 'run', side_effect=native), patch.object(
                updates.Path, 'exists', lambda path: str(path) == '/var/lib/dpkg' or exists(path)):
            result = self.do_apply()
        archived = [call.args[0] for call in self.archive.add.call_args_list]
        self.assertIn('/etc', archived)
        self.assertIn('/var/lib/dpkg', archived)
        self.assertEqual(Path(result['backup_dir']).stat().st_mode & 0o777, 0o700)

    def test_apply_failure_keeps_private_diagnostics_and_never_rolls_back(self):
        self.apply_mocks()
        with patch.object(updates, 'run', side_effect=updates.Refusal('Native command failed', native_output='solver failure')), \
                self.assertRaises(updates.Refusal) as failure:
            self.do_apply()
        directory = self.backup_root / self.token
        evidence = json.loads((directory / 'failure.json').read_text())
        self.assertTrue(evidence['manual_recovery_required'])
        self.assertTrue(evidence['installation_attempted'])
        self.assertFalse(evidence['rollback_attempted'])
        self.assertEqual(evidence['native_output'], 'solver failure')
        self.assertEqual(failure.exception.details['backup_dir'], str(directory))

    def test_backup_failure_and_staleness_prevent_mutation(self):
        self.apply_mocks()
        with patch.object(updates, 'backup', side_effect=updates.Refusal('Backup failed')), \
                patch.object(updates, 'run') as native, self.assertRaises(updates.Refusal):
            self.do_apply()
        native.assert_not_called()
        with patch.object(updates, 'select_plan', side_effect=[self.plan, updates.Refusal('Stale plan')]), \
                patch.object(updates, 'run') as native, self.assertRaisesRegex(updates.Refusal, 'Stale') as error:
            self.do_apply()
        native.assert_not_called()
        self.assertFalse(error.exception.details['installation_attempted'])
        self.assertFalse(error.exception.details['manual_recovery_required'])

    def test_installed_postcondition_failure_retains_backup(self):
        self.apply_mocks()
        with patch.object(updates, 'run', return_value=completed()), \
                patch.object(updates, 'installed', return_value=self.plan['installed']), \
                self.assertRaisesRegex(updates.Refusal, 'Installed state differs'):
            self.do_apply()
        self.assertTrue((self.backup_root / self.token / 'failure.json').exists())

    def test_request_contract_has_no_policy_config_or_probe_inputs(self):
        invalid = [
            {'action': 'plan', 'policy': {}}, {'action': 'plan', 'packages': ['nginx']},
            {'action': 'plan', 'token': self.token}, {'action': 'check'},
            {'action': 'select', 'snapshot': self.snapshot},
            {'action': 'apply', 'expected': self.plan, 'token': 'short'},
            {'action': 'apply', 'expected': self.plan, 'token': 'a' * 31},
            {'action': 'apply', 'expected': self.plan, 'token': 'a' * 33},
            {'action': 'restart', 'service': '--all'}, {'action': 'restart', 'service': 'nginx;reboot'},
            {'action': 'services', 'probes': []}, {'action': []}]
        with patch.object(updates, 'platform') as platform:
            for request in invalid:
                with self.subTest(request=request), self.assertRaises(updates.Refusal):
                    updates.execute(request)
        platform.assert_not_called()
        with patch.object(updates, 'platform', return_value=('apt', self.plan['platform'], 'systemd')), \
                patch.object(updates, 'make_plan', return_value=self.snapshot) as plan:
            self.assertEqual(updates.execute({'action': 'plan'}), self.snapshot)
        plan.assert_called_once_with('apt', self.plan['platform'], 'systemd', refresh=True)
        with patch.object(updates, 'platform', return_value=('apt', self.plan['platform'], 'systemd')), \
                patch.object(updates, 'select_plan', return_value=self.plan) as select:
            self.assertEqual(updates.execute({'action': 'select', 'snapshot': self.snapshot, 'packages': ['nginx']}), self.plan)
        select.assert_called_once_with(self.snapshot, ['nginx'], 'apt', self.plan['platform'], 'systemd')

    def test_services_and_explicit_restart_delegate_with_optional_before(self):
        from unittest.mock import Mock
        inspect, restart = Mock(return_value={'services': []}), Mock(return_value={'restarted': 'nginx'})
        before = [{'name': 'nginx', 'running': True}]
        for init in ('systemd', 'openrc'):
            with patch.object(updates, 'platform', return_value=('apt', self.plan['platform'], init)), \
                    patch.object(updates.runpy, 'run_path', return_value={
                        'inspect_services': inspect, 'restart_service': restart}) as load, \
                    patch.object(updates, 'installed') as installed:
                self.assertEqual(updates.execute({'action': 'services'}), {'services': []})
                inspect.assert_called_with(init, before=None)
                updates.execute({'action': 'services', 'before': before})
                inspect.assert_called_with(init, before=before)
                result = updates.execute({'action': 'restart', 'service': 'nginx', 'before': before})
                self.assertEqual(result, {'restarted': 'nginx'})
                restart.assert_called_with(init, 'nginx', before=before)
                load.assert_called_with(str(ROOT / 'scripts/update-services.py'))
                installed.assert_not_called()

    def test_apt_simulation(self):
        self.assertEqual(updates.parse_apt(APT, self.plan['installed']), self.plan['changes'])
        self.assertEqual(updates.parse_apt('0 upgraded, 0 newly installed, 0 to remove and 3 not upgraded.\n',
                                           self.plan['installed']), [])


    def test_apt_autoremove_advice_is_visible_but_never_an_authorized_removal(self):
        advice = ("The following packages were automatically installed and are no longer required:\n"
                  "  curl\nUse 'apt autoremove' to remove them.\n")
        self.assertEqual(updates.parse_apt(advice + APT, self.plan['installed']), self.plan['changes'])
        with self.assertRaises(updates.Refusal):
            updates.parse_apt(advice + APT + 'Remv curl [1]\n', self.plan['installed'])

    def test_apt_multiarch(self):
        output = APT.replace('nginx', 'libfoo').replace('1.24.0-1', '1.0').replace('1.24.0-2', '1.1')
        self.assertEqual(updates.parse_apt(output, {'libfoo:amd64': '1.0'}), [
            {'name': 'libfoo:amd64', 'old': '1.0', 'new': '1.1'}])


    def test_apt_existing_dependency(self):
        output = APT.replace('1 upgraded,', '2 upgraded,').replace(
            'The following packages will be upgraded:',
            'The following additional packages will be installed:\n  libfoo\nThe following packages will be upgraded:')
        output += 'Inst libfoo [1] (2 Debian:12/stable [amd64])\nConf libfoo (2 Debian:12/stable [amd64])\n'
        self.assertEqual([x['name'] for x in updates.parse_apt(output, dict(self.plan['installed'], libfoo='1'))],
                         ['libfoo', 'nginx'])


    def test_apt_additions_removals_and_ambiguity_fail_closed(self):
        bad = [APT.replace('1 upgraded, 0 newly', '0 upgraded, 1 newly'),
               APT.replace('0 to remove', '1 to remove'), APT + 'Remv zlib1g [1.2.13]\n',
               APT.replace(' [1.24.0-1]', ''), APT.replace(' [1.24.0-1]', ' [wrong]'),
               APT.replace('1 upgraded,', '2 upgraded,'), APT + 'Inst nginx [1.24.0-1] (2 repo [amd64])\n',
               APT + 'Purg nginx\n', APT.replace('Conf nginx', 'Bogus nginx'),
               APT + 'WARNING: skipping signature verification\n', APT.replace('Inst nginx', 'Inst newdep')]
        for text in bad:
            with self.subTest(text=text), self.assertRaises(updates.Refusal):
                updates.parse_apt(text, self.plan['installed'])


    def test_resolver_refusal_retains_simulation_evidence(self):
        unsafe = APT.replace('0 newly installed', '1 newly installed')
        with patch.object(updates, 'run', return_value=completed(unsafe)), self.assertRaises(updates.Refusal) as error:
            updates.resolve('apt', ['nginx'], self.plan['installed'])
        self.assertEqual(error.exception.details['native_output'], unsafe)


    def test_apk_reviewed_native_format(self):
        self.assertEqual(updates.parse_apk(APK, {'nginx': '1.24.0-r0'}), [
            {'name': 'nginx', 'old': '1.24.0-r0', 'new': '1.24.0-r1'}])
        self.assertEqual(updates.parse_apk('OK: 30 MiB in 24 packages\n', {'nginx': '1'}), [])


    def test_apk_addition_removal_downgrade_replacement_and_ambiguity(self):
        bad = [APK.replace('Upgrading', word) for word in (
            'Installing', 'Purging', 'Downgrading', 'Replacing', 'Reinstalling', 'Updating pinning')]
        bad += [APK.replace('(1/1)', '(2/2)'), APK.replace('(1/1)', '(1/2)'),
                APK.replace('nginx', 'nginx@testing'), APK.replace('1.24.0-r0 ->', '1.23.0-r0 ->'),
                APK.replace('OK:', '1 error;'), APK + 'unknown output\n', APK + APK,
                APK.replace('nginx', 'newdep'), APK.split('OK:')[0]]
        for text in bad:
            with self.subTest(text=text), self.assertRaises(updates.Refusal):
                updates.parse_apk(text, {'nginx': '1.24.0-r0'})


    def test_native_version_comparison_refuses_downgrades(self):
        with patch.object(updates, 'run', return_value=completed(rc=1)) as command:
            with self.assertRaises(updates.Refusal):
                updates.validate_changes('apt', [{'name': 'nginx', 'old': '2', 'new': '1'}],
                                         {'nginx': '2'}, ['nginx'])
            self.assertEqual(command.call_args.args[0], ['dpkg', '--compare-versions', '1', 'gt', '2'])
        with patch.object(updates, 'run', return_value=completed('<\n')):
            with self.assertRaises(updates.Refusal):
                updates.validate_changes('apk', [{'name': 'nginx', 'old': '2', 'new': '1'}],
                                         {'nginx': '2'}, ['nginx'])


    def test_database_faults(self):
        self.assertEqual(updates.parse_dpkg('nginx\t1\tii \nheld\t2\thi \nremoved\t1\trc \n'),
                         {'held': '2', 'nginx': '1'})
        for text in ('nginx\t1\tiF \n', 'nginx\t1\tiiR\n', 'garbage\n', ''):
            with self.subTest(text=text), self.assertRaises(updates.Refusal):
                updates.parse_dpkg(text)
        self.assertEqual(updates.parse_apk_installed('P:nginx\nV:1-r0\nF:etc\nR:config\n\n'),
                         {'nginx': '1-r0'})
        for text in ('P:nginx\nV:1\nf:s\n\n', 'P:nginx\nV:1\nf:f\n\n',
                     'P:nginx\nV:1\nf:x\n\n', 'P:nginx\nV:1\n', 'P:nginx\nV:1\nV:2\n\n'):
            with self.subTest(text=text), self.assertRaises(updates.Refusal):
                updates.parse_apk_installed(text)


    def test_apk_installed_query_does_not_require_cached_repository_indexes(self):
        with patch.object(updates, 'run', return_value=completed()) as run, \
                patch.object(updates.Path, 'read_text', return_value='P:nginx\nV:1-r0\n\n'):
            self.assertEqual(updates.installed('apk'), {'nginx': '1-r0'})
        self.assertEqual(run.call_args.args[0], ['apk', '--no-network', '--repositories-file', '/dev/null', 'info'])


    def test_insecure_configuration(self):
        updates.apt_security('Dir "/";\nDir::Etc "etc/apt";\nAcquire::AllowInsecureRepositories "false";\n')
        for text in ('APT::Get::AllowUnauthenticated "true";', 'Acquire::AllowWeakRepositories "1";',
                     'Acquire::https::Verify-Peer "false";', 'Acquire::AllowInsecureRepositories "true";',
                     'Acquire::AllowDowngradeToInsecureRepositories "true";', 'Dir::Etc "/tmp/apt";',
                     'Apt::Key::gpgvcommand "evil";'):
            with self.subTest(text=text), self.assertRaises(updates.Refusal):
                updates.apt_security(text)
        for text in ('deb [trusted=yes] https://example.org stable main\n',
                     'Types: deb\nTrusted: yes\nURIs: https://example.org\n',
                     'deb [allow-insecure=true] https://example.org stable main\n',
                     'deb [trusted="yes"] https://example.org stable main\n',
                     'Types: deb\nTrusted:\n yes\nURIs: https://example.org\n',
                     'Types: deb\nCheck-Valid-Until:\n no\nURIs: https://example.org\n'):
            source = self.directory / 'test.sources'
            source.write_text(text)
            with patch.object(updates, 'config_paths', return_value=[str(source)]), \
                    patch.object(updates, 'run', return_value=completed('Dir "/";\n')), \
                    self.assertRaises(updates.Refusal):
                updates.repositories('apt')


    def test_low_disk_space(self):
        with patch.object(updates.shutil, 'disk_usage', return_value=type('Usage', (), {'free': 255 * 1024 ** 2})()), \
                self.assertRaisesRegex(updates.Refusal, 'Insufficient'):
            updates.disk_check([str(self.directory)])


    def test_no_reboot_or_unsafe_flags_and_exact_pins(self):
        for manager in ('apt', 'apk'):
            for simulation in (True, False):
                command = updates.transaction_command(manager, ['nginx=1.24.0-2'], simulation)
                self.assertIn('nginx=1.24.0-2', command)
                self.assertFalse(set(command) & {'--no-scripts', '--allow-untrusted', '--force',
                                                '--allow-downgrades', '--allow-unauthenticated', 'reboot'})
                self.assertNotIn('update', command)
        for package in ('--option', 'nginx.apk'):
            if package.endswith('.apk'):
                with self.assertRaises(updates.Refusal):
                    updates.transaction_command('apk', [package], False)


    def test_native_subprocess_is_no_shell_bounded_and_sanitized(self):
        with patch.object(updates.subprocess, 'run', return_value=completed()) as native:
            updates.run(['apt-get', 'update'])
        kwargs = native.call_args.kwargs
        self.assertNotIn('shell', kwargs)
        self.assertEqual(kwargs['timeout'], 120)
        self.assertEqual(kwargs['env']['LC_ALL'], 'C')
        self.assertNotIn('APT_CONFIG', kwargs['env'])
        self.assertNotIn('SSL_NO_VERIFY_HOSTNAME', kwargs['env'])
        self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)


    def test_apk_staging_is_verified_pinned_and_network_free(self):
        plan = dict(self.plan, manager='apk', installed={'nginx': '1.24.0-r0'}, changes=[
            {'name': 'nginx', 'old': '1.24.0-r0', 'new': '1.24.0-r1'}])
        calls = []
        def native(argv, **kwargs):
            calls.append(argv)
            if 'fetch' in argv:
                directory = Path(argv[argv.index('--output') + 1])
                (directory / 'nginx-1.24.0-r1.apk').write_bytes(b'package fixture')
            return completed('>\n' if 'version' in argv else APK if '--simulate' in argv else '')
        with patch.object(updates, 'run', side_effect=native):
            command = updates.stage_apk(plan, ['nginx=1.24.0-r1'], str(self.directory))
        self.assertIn('--no-network', command)
        self.assertNotIn('--simulate', command)
        self.assertNotIn('--no-scripts', command)
        self.assertEqual(command[-1], 'nginx=1.24.0-r1')
        self.assertTrue(command[-2].endswith('/nginx-1.24.0-r1.apk'))
        self.assertEqual(calls[1][:4], ['apk', '--no-network', 'verify', '--'])
        self.assertIn('--simulate', calls[2])
        self.assertFalse(any('update' in argv for argv in calls))


    def test_apk_offline_staging_refuses_unreviewed_dependency_actions_with_evidence(self):
        plan = dict(self.plan, manager='apk', installed={'nginx': '1.24.0-r0'}, changes=[
            {'name': 'nginx', 'old': '1.24.0-r0', 'new': '1.24.0-r1'}])
        unsafe = APK.replace('Upgrading', 'Installing')
        def native(argv, **kwargs):
            if 'fetch' in argv:
                directory = Path(argv[argv.index('--output') + 1])
                (directory / 'nginx-1.24.0-r1.apk').write_bytes(b'package fixture')
            return completed(unsafe if '--simulate' in argv else '')
        with patch.object(updates, 'run', side_effect=native), self.assertRaises(updates.Refusal) as error:
            updates.stage_apk(plan, ['nginx=1.24.0-r1'], str(self.directory))
        self.assertEqual(error.exception.details['native_output'], unsafe)

    def test_apk_fetch_wrong_version_refused_before_install(self):
        plan = dict(self.plan, manager='apk', installed={'nginx': '1.24.0-r0'}, changes=[
            {'name': 'nginx', 'old': '1.24.0-r0', 'new': '1.24.0-r1'}])
        with patch.object(updates, 'run', return_value=completed()) as run, \
                self.assertRaisesRegex(updates.Refusal, 'reviewed exact versions'):
            updates.stage_apk(plan, ['nginx=1.24.0-r1'], str(self.directory))
        self.assertEqual(run.call_count, 1)


    def test_repository_fingerprint_and_external_signing_key_changes(self):
        key = self.directory / 'custom.gpg'
        key.write_bytes(b'key1')
        source = self.directory / 'sources.list'
        source.write_text('deb [signed-by=' + str(key) + '] https://example.org stable main\n')
        with patch.object(updates, 'config_paths', return_value=[str(source), str(key)]), \
                patch.object(updates, 'run', return_value=completed('Dir "/";\n')):
            first = updates.repositories('apt')
            self.assertEqual(updates.repositories('apt'), first)
            key.write_bytes(b'key2')
            self.assertNotEqual(updates.repositories('apt'), first)
        self.assertEqual(updates.signed_keys(source.read_text()), [str(key)])
        with self.assertRaises(updates.Refusal):
            updates.signed_keys('Signed-By: ' + str(key) + ' /another-key\n')


    def test_insecure_apk_repositories_are_refused(self):
        repository = Path('/etc/apk/repositories')
        for text in ('http://example.org/alpine\n', '--allow-untrusted\n',
                     '@testing https://example.org/alpine\n', '/local/unsigned\n'):
            with patch.object(updates, 'config_paths', return_value=[str(repository)]), \
                    patch.object(updates.Path, 'read_bytes', return_value=text.encode()), \
                    patch.object(updates.Path, 'is_symlink', return_value=False), \
                    self.assertRaises(updates.Refusal):
                updates.repositories('apk')


    def test_native_failure_and_timeout_output_is_private_for_service_commands(self):
        for private in (True, False):
            with patch.object(updates.subprocess, 'run', return_value=completed('secret', 1)), \
                    self.assertRaises(updates.Refusal) as error:
                updates.run(['probe', 'password'], private=private)
            self.assertEqual('secret' in str(error.exception.details), not private)
            with patch.object(updates.subprocess, 'run', side_effect=subprocess.TimeoutExpired(
                    ['probe', 'password'], 1, output=b'secret', stderr=b'evidence')), \
                    self.assertRaises(updates.Refusal) as error:
                updates.run(['probe', 'password'], private=private)
            self.assertEqual('secret' in str(error.exception.details), not private)
            self.assertNotIn('password', str(error.exception))


    def test_unsupported_distro_init_and_apk_version(self):
        with patch.object(updates.Path, 'read_text', return_value='ID=ubuntu\nVERSION_ID=22.04\n'), \
                self.assertRaisesRegex(updates.Refusal, 'Unsupported distro'):
            updates.platform()
        with patch.object(updates.Path, 'read_text', return_value='ID=debian\nVERSION_ID=12\n'), \
                patch.object(updates.Path, 'is_dir', return_value=False), \
                self.assertRaisesRegex(updates.Refusal, 'systemd'):
            updates.platform()
        with patch.object(updates.Path, 'read_text', return_value='ID=alpine\nVERSION_ID=3.23\n'), \
                patch.object(updates.Path, 'is_dir', return_value=True), \
                patch.object(updates.shutil, 'which', return_value='/sbin/rc-service'), \
                patch.object(updates, 'run', return_value=completed('apk-tools 3.0.0, compiled for x86_64.\n')), \
                self.assertRaisesRegex(updates.Refusal, '2.14'):
            updates.platform()


    def test_main_invalid_json_and_duplicate_keys_produce_json_rc1(self):
        for request in ('{bad', '{"action":"plan","action":"apply"}'):
            output = io.StringIO()
            with patch.object(updates.os, 'geteuid', return_value=0), \
                    patch.object(updates.os, 'umask'), patch.object(updates.os, 'open', return_value=42), \
                    patch.object(updates.os, 'fstat', return_value=type('Stat', (), {
                        'st_mode': 0o100600, 'st_uid': 0, 'st_nlink': 1})()), \
                    patch.object(updates.os, 'close'), patch.object(updates.fcntl, 'flock'), \
                    patch.object(updates.sys, 'stdin', io.StringIO(request)), \
                    contextlib.redirect_stdout(output):
                self.assertEqual(updates.main(), 1)
            self.assertIn('error', json.loads(output.getvalue()))


    def test_lock_is_nonblocking_and_root_owned(self):
        for uid, blocked in ((1000, False), (0, True)):
            output = io.StringIO()
            with patch.object(updates.os, 'geteuid', return_value=0), \
                    patch.object(updates.os, 'umask'), patch.object(updates.os, 'open', return_value=42), \
                    patch.object(updates.os, 'fstat', return_value=type('Stat', (), {
                        'st_mode': 0o100600, 'st_uid': uid, 'st_nlink': 1})()), \
                    patch.object(updates.os, 'close'), \
                    patch.object(updates.fcntl, 'flock', side_effect=BlockingIOError if blocked else None) as flock, \
                    contextlib.redirect_stdout(output):
                self.assertEqual(updates.main(), 1)
            self.assertIn('error', json.loads(output.getvalue()))
            if blocked:
                self.assertEqual(flock.call_args.args[1], updates.fcntl.LOCK_EX | updates.fcntl.LOCK_NB)


if __name__ == '__main__':
    unittest.main()
