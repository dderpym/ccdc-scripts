"""Offline interactive update UX, exact-plan and restart-consent checks."""
import contextlib
import copy
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    loader = importlib.machinery.SourceFileLoader(name, str(ROOT / 'scripts' / filename))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


ctl = load('interactive_updates_ctl', 'ccdcctl')
update = load('interactive_updates', 'update-controller.py')
VARS = {'ansible_host': '192.0.2.1'}
CATALOG = {'schema': 2, 'manager': 'apt', 'platform': {'id': 'debian', 'version': '12'},
           'init': 'systemd', 'installed': {'nginx': '1', 'libssl3': '1', 'postgresql': '1'},
           'repositories': 'a' * 64, 'selected': [], 'changes': [], 'candidates': [
               {'name': 'nginx', 'old': '1', 'new': '2', 'risk': 'lower', 'reason': 'ordinary package update'},
               {'name': 'libssl3', 'old': '1', 'new': '2', 'risk': 'lower', 'reason': 'library update'},
               {'name': 'postgresql', 'old': '1', 'new': '2', 'risk': 'manual', 'reason': 'database migrations/data risk'}]}
EXACT = dict(CATALOG, selected=['libssl3', 'nginx'], changes=[
    {'name': 'libssl3', 'old': '1', 'new': '2'}, {'name': 'nginx', 'old': '1', 'new': '2'}])
BEFORE = {'services': [{'name': 'nginx', 'active': True, 'pids': [12], 'reasons': [], 'confidence': 'cgroup'}],
          'unmanaged': [], 'warnings': []}
AFTER = copy.deepcopy(BEFORE)
AFTER['services'][0]['reasons'] = ['process uses replaced library']


class InteractiveUpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.addCleanup(patch.stopall)
        patch.object(ctl, 'ROOT', self.root).start()
        patch.object(ctl, 'EXTRA', []).start()
        patch.object(ctl, 'verify_admin_access', return_value=True).start()
        patch.object(ctl, 'collect', side_effect=AssertionError('updates must not discover SSH/firewall policy')).start()
        patch.object(update.sys.stdin, 'isatty', return_value=True).start()
        self.events = []
        self.restarted = set()
        self.after = copy.deepcopy(AFTER)
        def remote(controller, host, action, **fields):
            self.events.append((host, action, fields))
            if action == 'plan':
                return copy.deepcopy(CATALOG)
            if action == 'select':
                selected = sorted(fields['packages'])
                changes = [{k: c[k] for k in ('name', 'old', 'new')} for c in CATALOG['candidates'] if c['name'] in selected]
                return dict(CATALOG, selected=selected, changes=sorted(changes, key=lambda c: c['name']))
            if action == 'services':
                return copy.deepcopy(BEFORE if not fields.get('before') or host in self.restarted else self.after)
            if action == 'restart':
                self.restarted.add(host)
                return {'name': fields['service'], 'status': 'restarted'}
            return {'backup_archive': '/var/backups/ccdc-updates/x/backup.tar.gz', 'changes': EXACT['changes']}
        self.remote = patch.object(update, 'remote', side_effect=remote).start()
        for stream in ('stdout', 'stderr'):
            redirect = getattr(contextlib, 'redirect_' + stream)(io.StringIO())
            redirect.__enter__()
            self.addCleanup(redirect.__exit__, None, None, None)

    def saved(self, host='a', **changes):
        document = {'schema': 2, 'host': host, 'ready': True, 'created': time.time(),
                    'remote': copy.deepcopy(EXACT), 'endpoint': update.endpoint(ctl, VARS)}
        document.update(changes)
        ctl.save(self.root / 'reports' / host / 'updates/plan.json', document)
        return document

    def read(self, host='a', file='result.json'):
        return json.loads((self.root / 'reports' / host / 'updates' / file).read_text())

    def apply(self, hosts=('a',), yes=True):
        return update.updates(ctl, 'apply', list(hosts), {host: dict(VARS) for host in hosts}, yes=yes)

    def test_plan_discovers_all_with_no_inventory_config_and_holds_dangerous(self):
        with patch.object(ctl, 'ask', side_effect=['a', 'y']):
            self.assertFalse(update.updates(ctl, 'plan', ['a'], {'a': VARS}))
        plan = self.read(file='plan.json')
        self.assertTrue(plan['ready'])
        self.assertEqual(plan['remote']['selected'], ['libssl3', 'nginx'])
        self.assertNotIn('policy', plan)
        self.assertNotIn('probes', plan)
        self.assertNotIn('security', plan)
        ctl.collect.assert_not_called()
        self.assertEqual((self.root / 'reports/a/updates/plan.json').stat().st_mode & 0o777, 0o600)
        self.assertEqual([e[1] for e in self.events], ['services', 'plan', 'select'])

    def test_per_package_review_holds_declined_package(self):
        with patch.object(ctl, 'ask', side_effect=['r', 'n', 'y', 'y']):
            self.assertFalse(update.updates(ctl, 'plan', ['a'], {'a': VARS}))
        self.assertEqual(self.read(file='plan.json')['remote']['selected'], ['libssl3'])

    def test_skip_and_default_abort_never_approve_plan(self):
        for choices in (['s'], ['a', 'n']):
            self.saved()
            with patch.object(ctl, 'ask', side_effect=choices):
                self.assertFalse(update.updates(ctl, 'plan', ['a'], {'a': VARS}))
            self.assertFalse(self.read(file='plan.json')['ready'])

    def test_failed_or_noninteractive_replan_invalidates_old_approval(self):
        self.saved()
        with patch.object(update.sys.stdin, 'isatty', return_value=False), self.assertRaises(ValueError):
            update.updates(ctl, 'plan', ['a'], {'a': VARS})
        self.assertFalse(self.read(file='plan.json')['ready'])
        self.saved()
        ctl.verify_admin_access.return_value = False
        self.assertTrue(update.updates(ctl, 'plan', ['a'], {'a': VARS}))
        self.assertFalse(self.read(file='plan.json')['ready'])

    def test_unresolvable_selection_can_be_revised_without_broadening(self):
        original = self.remote.side_effect
        attempts = 0
        def fail_once(controller, host, action, **fields):
            nonlocal attempts
            if action == 'select':
                attempts += 1
                if attempts == 1:
                    raise RuntimeError('selected update requires held libc')
            return original(controller, host, action, **fields)
        self.remote.side_effect = fail_once
        with patch.object(ctl, 'ask', side_effect=['a', 'r', 'r', 'n', 'y', 'y']):
            self.assertFalse(update.updates(ctl, 'plan', ['a'], {'a': VARS}))
        self.assertEqual(self.read(file='plan.json')['remote']['selected'], ['libssl3'])

    def test_saved_plans_validated_before_any_mutation(self):
        self.saved()
        with self.assertRaises(OSError):
            self.apply(('a', 'b'))
        self.remote.assert_not_called()
        for changes in ({'schema': 1}, {'created': time.time() - 86401}, {'ready': False}, {'endpoint': 'other'}):
            self.saved(**changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.apply()
        self.remote.assert_not_called()

    def test_apply_never_restarts_without_separate_consent(self):
        self.saved()
        with patch.object(ctl, 'ask', return_value='s') as ask:
            self.assertFalse(self.apply())
        self.assertEqual(ask.call_count, 1)
        self.assertNotIn('restart', [e[1] for e in self.events])
        self.assertEqual(self.read()['deferred_restarts'], ['nginx'])
        self.assertFalse(self.read()['application_health_verified'])
        self.assertFalse(self.read(file='plan.json')['ready'])

    def test_explicit_restart_after_install_and_backup(self):
        self.saved()
        with patch.object(ctl, 'ask', return_value='r'):
            self.assertFalse(self.apply())
        actions = [e[1] for e in self.events]
        self.assertLess(actions.index('apply'), actions.index('restart'))
        restart = next(e for e in self.events if e[1] == 'restart')
        self.assertEqual(restart[2]['service'], 'nginx')
        self.assertEqual(self.read()['deferred_restarts'], [])
        self.assertEqual(ctl.verify_admin_access.call_count, 4)

    def test_noninteractive_yes_installs_but_always_defers_restarts(self):
        self.saved()
        with patch.object(update.sys.stdin, 'isatty', return_value=False), patch.object(ctl, 'ask') as ask:
            self.assertFalse(self.apply())
        ask.assert_not_called()
        self.assertNotIn('restart', [e[1] for e in self.events])
        self.assertEqual(self.read()['deferred_restarts'], ['nginx'])

    def test_apply_abort_no_mutation_or_consumption(self):
        self.saved()
        with patch.object(ctl, 'ask', return_value='n'):
            self.assertFalse(self.apply(yes=False))
        self.assertTrue(self.read(file='plan.json')['ready'])
        self.remote.assert_not_called()

    def test_quit_restart_review_stops_other_hosts(self):
        self.saved('a')
        self.saved('b')
        with patch.object(ctl, 'ask', return_value='q'):
            self.assertTrue(self.apply(('a', 'b')))
        self.assertEqual(self.read()['status'], 'paused')
        self.assertNotIn('b', [e[0] for e in self.events])
        self.assertTrue(self.read('b', 'plan.json')['ready'])

    def test_previously_active_now_stopped_service_stops_rollout_if_deferred(self):
        self.saved('a')
        self.saved('b')
        self.after['services'][0]['active'] = False
        self.after['services'][0]['reasons'] = ['stopped since update']
        with patch.object(ctl, 'ask', return_value='s'):
            self.assertTrue(self.apply(('a', 'b')))
        self.assertIn('now stopped', self.read()['error'])
        self.assertNotIn('b', [e[0] for e in self.events])

    def test_failed_native_update_or_restart_consumes_plan_and_stops_rollout(self):
        original = self.remote.side_effect
        for failing_action in ('apply', 'restart'):
            self.events.clear()
            self.saved('a')
            self.saved('b')
            def fail(controller, host, action, **fields):
                if action == failing_action:
                    raise RuntimeError('native action failed')
                return original(controller, host, action, **fields)
            self.remote.side_effect = fail
            with patch.object(ctl, 'ask', return_value='r'):
                self.assertTrue(self.apply(('a', 'b')))
            self.assertFalse(self.read(file='plan.json')['ready'])
            self.assertNotIn('b', [e[0] for e in self.events])

    def test_unrelated_baselines_and_legacy_policy_snapshot_do_not_block_updates(self):
        firewall = self.root / 'baselines/a/firewall.json'
        ssh = self.root / 'baselines/a/ssh.json'
        ctl.save(firewall, {'backend': 'different'})
        ctl.text_file(ssh, 'invalid baseline JSON\n')
        originals = {path: path.read_bytes() for path in (firewall, ssh)}
        with patch.object(ctl, 'ask', side_effect=['a', 'y']):
            self.assertFalse(update.updates(ctl, 'plan', ['a'], {'a': VARS}))
        self.assertNotIn('security', self.read(file='plan.json'))
        # Existing schema-2 package plans remain usable; obsolete policy data is ignored.
        self.saved(security={'firewall': {'backend': 'old'}, 'ssh': {}})
        with patch.object(ctl, 'ask', return_value='s'):
            self.assertFalse(self.apply())
        for path, original in originals.items():
            self.assertEqual(path.read_bytes(), original)
        ctl.collect.assert_not_called()

    def test_lost_fresh_access_after_install_stops_before_restart_and_next_host(self):
        self.saved('a')
        self.saved('b')
        ctl.verify_admin_access.side_effect = [True, False]
        self.assertTrue(self.apply(('a', 'b')))
        self.assertIn('fresh oski key login/sudo failed', self.read()['error'])
        self.assertIn('transaction', self.read())
        self.assertFalse(self.read(file='plan.json')['ready'])
        self.assertTrue(self.read('b', 'plan.json')['ready'])
        self.assertNotIn('restart', [e[1] for e in self.events])
        self.assertNotIn('b', [e[0] for e in self.events])

    def test_interrupted_restart_prompt_retains_transaction_and_deferred_list(self):
        self.saved()
        with patch.object(ctl, 'ask', side_effect=EOFError), self.assertRaises(EOFError):
            self.apply()
        self.assertEqual(self.read()['status'], 'interrupted')
        self.assertIn('transaction', self.read())
        self.assertEqual(self.read()['deferred_restarts'], ['nginx'])

    def test_transport_has_no_config_keys_and_saves_native_failure_privately(self):
        real = load('interactive_transport', 'update-controller.py')
        def run(args, result_dir=None, result_task=None):
            path = Path(args[args.index('--extra-vars') + 1][1:])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            request = json.loads(path.read_text())['update_request']
            self.assertEqual(request, {'action': 'plan'})
            self.assertEqual(result_task, 'Run guarded update action')
            response = {'stdout': json.dumps({'error': 'native failure', 'native_output': 'private detail'}), 'rc': 1}
            (Path(result_dir) / 'a').write_text(json.dumps(response))
            return subprocess.CompletedProcess(args, 2, '', '')
        with patch.object(ctl, 'run', side_effect=run), self.assertRaisesRegex(RuntimeError, '^native failure$'):
            real.remote(ctl, 'a', 'plan')
        path = self.root / 'reports/a/updates/remote-failure.json'
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertIn('private detail', path.read_text())


@unittest.skipUnless(shutil.which('ansible-playbook'), 'Ansible unavailable')
class UpdatePlaybookTests(unittest.TestCase):
    def test_real_local_ansible_staging_result_selection_and_cleanup(self):
        for action in ('plan', 'services', 'apply'):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'scripts').mkdir()
                (root / 'playbooks').mkdir()
                (root / 'results').mkdir()
                play = (ROOT / 'playbooks/update.yml').read_text().replace('owner: root', f'owner: {os.geteuid()}').replace('group: root', f'group: {os.getegid()}')
                (root / 'playbooks/update.yml').write_text(play)
                (root / 'inventory.json').write_text(json.dumps({'all': {'hosts': {'a': {
                    'ansible_connection': 'local', 'ansible_python_interpreter': sys.executable}}}}))
                (root / 'ansible.cfg').write_text('[defaults]\ninventory = inventory.json\n'
                    f'callback_plugins = {ROOT}/callback_plugins\ncallbacks_enabled = ccdc_results\n')
                # No actual updater/package manager runs in this local fixture.
                for filename in ('update-services.py', 'discover-listeners'):
                    (root / 'scripts' / filename).write_text('pass\n')
                (root / 'scripts/manage-updates').write_text(
                    'import json, pathlib, sys\nrequest = json.load(sys.stdin)\n'
                    'pathlib.Path(request["record_path"]).write_text(sys.argv[0])\n'
                    'print(json.dumps({"schema": 2, "changes": [], "backup_archive": '
                    '"/var/backups/ccdc-updates/" + str(request.get("token")) + "/missing.tar.gz"}))\n')
                request = {'action': action, 'record_path': str(root / 'staged_path')}
                if action == 'apply':
                    request['token'] = 'a' * 32
                env = dict(os.environ, ANSIBLE_CONFIG=str(root / 'ansible.cfg'),
                           CCDC_RESULT_DIR=str(root / 'results'), CCDC_RESULT_TASK='Run guarded update action',
                           ANSIBLE_NOCOLOR='1')
                env.pop('ANSIBLE_INVENTORY', None)
                result = subprocess.run(['ansible-playbook', 'playbooks/update.yml', '--limit', 'a',
                    '--extra-vars', json.dumps({'ansible_become': False, 'update_request': request,
                                               'update_backup_destination': str(root / 'backups')})],
                    cwd=root, env=env, text=True, capture_output=True, timeout=60)
                response = json.loads((root / 'results/a').read_text())
                self.assertTrue((root / 'staged_path').exists(), result.stdout + result.stderr)
                self.assertFalse(Path((root / 'staged_path').read_text()).parent.exists())
                if action == 'apply':
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('msg', response)
                    self.assertNotIn('stdout', response)
                else:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(json.loads(response['stdout'])['changes'], [])


if __name__ == '__main__':
    unittest.main()
