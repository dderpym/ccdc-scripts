"""Credential fallback checks and a fake-chpasswd Ansible test; no real passwords changed."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from test_controller import ctl


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.addCleanup(patch.stopall)
        patch.object(ctl, 'ROOT', self.root).start()
        patch.object(ctl, 'EXTRA', []).start()
        self.output = io.StringIO()
        redirect = contextlib.redirect_stdout(self.output)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)
        self.default = self.root / 'secrets/bootstrap.password'
        ctl.text_file(self.default, 'competition-default\n')
        patch.object(ctl, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')).start()

    def test_secret_permissions_and_invalid_contents(self):
        self.assertEqual(ctl.read_secret(self.default), 'competition-default')
        self.default.chmod(0o644)
        with self.assertRaises(RuntimeError):
            ctl.read_secret(self.default)
        self.default.chmod(0o600)
        link = self.default.parent / 'symlink'
        link.symlink_to(self.default)
        with self.assertRaises(RuntimeError):
            ctl.read_secret(link)
        self.default.write_text('first\nsecond\n')
        with self.assertRaises(RuntimeError):
            ctl.read_secret(self.default)

    def test_vault_source_is_decrypted_without_printing_plaintext(self):
        self.default.write_text('$ANSIBLE_VAULT;1.1;AES256\nciphertext\n')
        with patch.object(ctl, 'run', return_value=subprocess.CompletedProcess([], 0, 'vault-secret\n', '')) as run:
            self.assertEqual(ctl.read_secret(self.default), 'vault-secret')
        self.assertEqual(run.call_args.args[0], ['ansible-vault', 'view', str(self.default)])
        self.assertNotIn('vault-secret', self.output.getvalue())

    def test_save_refuses_to_downgrade_vault_encryption(self):
        encrypted = '$ANSIBLE_VAULT;1.1;AES256\nciphertext\n'
        self.default.write_text(encrypted)
        with patch.object(ctl.getpass, 'getpass') as getpass:
            with self.assertRaises(RuntimeError):
                ctl.initialize(['a'], 'a', save_bootstrap=True)
        getpass.assert_not_called()
        self.assertEqual(self.default.read_text(), encrypted)

    def test_explicit_manual_mode_ignores_saved_defaults(self):
        with patch.object(ctl, 'playbook', return_value=True) as play, patch.object(ctl, 'probe_root') as probe:
            self.assertFalse(ctl.initialize(['a'], 'a', use_saved=False))
        play.assert_called_once_with('init', 'a')
        probe.assert_not_called()

    def test_save_default_uses_hidden_prompt_and_private_file(self):
        self.default.unlink()
        with patch.object(ctl.sys.stdin, 'isatty', return_value=True), \
                patch.object(ctl.getpass, 'getpass', return_value='supplied-default'), \
                patch.object(ctl, 'probe_root', return_value=(True, False, '')), \
                patch.object(ctl, 'playbook', return_value=True):
            self.assertFalse(ctl.initialize(['a'], 'a', save_bootstrap=True))
        self.assertEqual(ctl.read_secret(self.default), 'supplied-default')
        self.assertEqual(stat.S_IMODE(self.default.stat().st_mode), 0o600)
        self.assertNotIn('supplied-default', self.output.getvalue())

    def test_private_vars_file_never_puts_password_in_argv_and_is_removed(self):
        paths = []
        def run(args, capture=True, result_dir=None):
            path = Path(args[args.index('--extra-vars') + 1][1:])
            paths.append(path)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertNotIn('sensitive-password', ' '.join(args))
            self.assertEqual(json.loads(path.read_text())['ansible_password'], 'sensitive-password')
            return subprocess.CompletedProcess(args, 0, '', '')
        with patch.object(ctl, 'run', side_effect=run):
            ctl.run_with_vars(['ansible'], {'ansible_password': 'sensitive-password'})
        self.assertTrue(all(not path.exists() for path in paths))

    def test_probe_classifies_only_authentication_errors_and_redacts_credentials(self):
        def run(args, capture=True, result_dir=None):
            path = Path(args[args.index('--extra-vars') + 1][1:])
            variables = json.loads(path.read_text())
            self.assertEqual(variables['ansible_user'], 'root')
            self.assertFalse(variables['ansible_become'])
            self.assertIn('ControlPath=none', variables['ansible_ssh_args'])
            message = run.message
            (Path(result_dir) / 'a').write_text(json.dumps({'unreachable': True, 'msg': message}))
            return subprocess.CompletedProcess(args, 4, '', '')
        run.message = 'root@host: Permission denied (publickey,password). sensitive-password'
        with patch.object(ctl, 'run', side_effect=run):
            success, authentication, error = ctl.probe_root('a', 'sensitive-password')
            self.assertFalse(success)
            self.assertTrue(authentication)
            self.assertNotIn('sensitive-password', error)
            for message in ('Connection timed out', 'known_hosts: Permission denied. Host key verification failed.'):
                run.message = message
                self.assertFalse(ctl.probe_root('a', 'sensitive-password')[1])

    def test_default_then_one_hidden_prompt_per_host(self):
        with patch.object(ctl, 'probe_root', side_effect=[(False, True, 'authentication failed'), (True, False, '')]) as probe, \
                patch.object(ctl.sys.stdin, 'isatty', return_value=True), \
                patch.object(ctl.getpass, 'getpass', return_value='host-specific-password') as getpass, \
                patch.object(ctl, 'playbook', return_value=True) as play:
            self.assertFalse(ctl.initialize(['a'], 'all'))
        self.assertEqual(probe.call_args_list[0].args, ('a', 'competition-default'))
        self.assertEqual(probe.call_args_list[1].args, ('a', 'host-specific-password'))
        self.assertEqual(getpass.call_count, 1)
        self.assertEqual(play.call_args.args[2]['ansible_password'], 'host-specific-password')
        self.assertNotIn('host-specific-password', self.output.getvalue())
        self.assertNotIn('competition-default', self.output.getvalue())

    def test_network_failure_does_not_prompt_or_prevent_later_hosts(self):
        with patch.object(ctl, 'probe_root', side_effect=[(False, False, 'timeout'), (True, False, '')]), \
                patch.object(ctl.getpass, 'getpass') as getpass, \
                patch.object(ctl, 'playbook', return_value=True) as play:
            self.assertTrue(ctl.initialize(['a', 'b'], 'all'))
        getpass.assert_not_called()
        self.assertEqual(play.call_args.args[1], 'b')
        self.assertIn('a                    FAILED', self.output.getvalue())
        self.assertIn('b                    OK', self.output.getvalue())

    def test_task_failure_is_never_retried_with_another_password(self):
        with patch.object(ctl, 'probe_root', return_value=(True, False, '')) as probe, \
                patch.object(ctl.getpass, 'getpass') as getpass, \
                patch.object(ctl, 'playbook', return_value=False) as play:
            self.assertTrue(ctl.initialize(['a'], 'all'))
        self.assertEqual(probe.call_count, 1)
        self.assertEqual(play.call_count, 1)
        getpass.assert_not_called()

    def test_rerun_prefers_oski_key_access_instead_of_root_ssh(self):
        ctl.text_file(self.root / 'secrets/root/a.password', 'oldRootPW1\n')
        with patch.object(ctl, 'verify_admin_access', return_value=True), \
                patch.object(ctl, 'probe_root') as probe, \
                patch.object(ctl, 'playbook', return_value=True) as play:
            self.assertFalse(ctl.initialize(['a'], 'a'))
        probe.assert_not_called()
        self.assertEqual(play.call_args.args[2]['ansible_user'], 'oski')
        self.assertNotIn('ansible_become', play.call_args.args[2])
        self.assertEqual(play.call_args.args[2]['ansible_become_method'], 'sudo')

    def test_recovery_password_is_used_instead_of_guessing_shared_default_again(self):
        ctl.text_file(self.root / 'secrets/root/a.password', 'oldRootPW1\n')
        with patch.object(ctl, 'verify_admin_access', return_value=False), \
                patch.object(ctl, 'probe_root', return_value=(True, False, '')) as probe, \
                patch.object(ctl, 'playbook', return_value=True):
            self.assertFalse(ctl.initialize(['a'], 'a'))
        self.assertEqual(probe.call_args.args, ('a', 'oldRootPW1'))


@unittest.skipUnless(shutil.which('ansible-playbook') and importlib.util.find_spec('yaml'), 'Ansible/YAML unavailable')
class RootRotationRoleTests(unittest.TestCase):
    def test_save_before_change_backups_no_log_and_failed_preflight(self):
        import yaml
        repo = Path(__file__).resolve().parents[1]
        tasks = yaml.safe_load((repo / 'roles/init/tasks/main.yml').read_text())
        block = copy.deepcopy(tasks[-1])
        self.assertIn('unique root recovery', block['name'])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'playbooks').mkdir()
            capture = root / 'password-input'
            tool = root / 'fake-chpasswd'
            saved = root / 'secrets/root/localhost.password'
            fail_marker = root / 'reject-password'
            tool.write_text('#!/usr/bin/env python3\nimport sys\nfrom pathlib import Path\npayload=sys.stdin.read()\nassert payload.strip() == "root:" + Path(' + repr(str(saved)) + ').read_text().strip()\nPath(' + repr(str(capture)) + ').write_text(payload)\nprint(payload)\nsys.exit(1 if Path(' + repr(str(fail_marker)) + ').exists() else 0)\n')
            tool.chmod(0o700)
            # Only the rotation block runs. SSH proof and password tool are fake;
            # no user/group/sudoers task or real chpasswd can run on the controller.
            block['block'][0]['ansible.builtin.command']['argv'] = ['true']
            locator = next(task for task in block['block'] if 'init_chpasswd' == task.get('register'))
            locator['ansible.builtin.shell'] = 'printf "%s" ' + str(tool)
            locator['become'] = False
            rotation = next(task for task in block['block'] if 'rescue' in task)
            rotation['block'][0]['become'] = False
            # Real play-level escalation, but no controller delegate may sudo.
            # Both fake "remote" commands explicitly remain unprivileged.
            play = [{'hosts': 'localhost', 'connection': 'local', 'gather_facts': False,
                     'become': True, 'tasks': [block]}]
            path = root / 'playbooks/rotate.yml'
            env = dict(os.environ, ANSIBLE_CONFIG=str(repo / 'ansible.cfg'), ANSIBLE_BECOME_EXE='/bin/false')
            def invoke():
                path.write_text(yaml.safe_dump(play))
                return subprocess.run(['ansible-playbook', str(path), '-i', 'localhost,'], env=env,
                                      text=True, capture_output=True, timeout=60)
            result = invoke()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            saved = root / 'secrets/root/localhost.password'
            first = saved.read_text().strip()
            self.assertEqual(len(first), 10)
            self.assertTrue(first.isascii() and first.isalnum())
            self.assertEqual(capture.read_text().strip(), 'root:' + first)
            self.assertNotIn(first, result.stdout + result.stderr)
            self.assertEqual(stat.S_IMODE(saved.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(saved.parent.stat().st_mode), 0o700)
            result = invoke()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            second = saved.read_text().strip()
            self.assertNotEqual(first, second)
            self.assertNotIn(second, result.stdout + result.stderr)
            self.assertTrue(any(p.read_text().strip() == first for p in saved.parent.glob('*.password.*')))
            fail_marker.touch()
            result = invoke()
            self.assertNotEqual(result.returncode, 0)
            candidate = saved.read_text().strip()
            self.assertNotIn(candidate, result.stdout + result.stderr)
            self.assertIn('saved candidate may not be active', result.stdout)
            self.assertTrue(any(p.read_text().strip() == second for p in saved.parent.glob('*.password.*')))
            before = {p.name: p.read_bytes() for p in saved.parent.iterdir()}
            previous_input = capture.read_text()
            block['block'][0]['ansible.builtin.command']['argv'] = ['false']
            result = invoke()
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual({p.name: p.read_bytes() for p in saved.parent.iterdir()}, before)
            self.assertEqual(capture.read_text(), previous_input)


if __name__ == '__main__':
    unittest.main()
