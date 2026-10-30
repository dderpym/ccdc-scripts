"""The shared remote runner: bundle contents, and playbooks/remote.yml over a real local connection."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

from test_controller import ROOT
from test_lse import FIXTURE, passive_fixtures

sys.path.insert(0, str(ROOT))
from controller import remote  # noqa: E402
from host import launcher  # noqa: E402


class BundleTests(unittest.TestCase):
    def test_bundle_is_deterministic_and_contains_code_and_pinned_data(self):
        with tempfile.TemporaryDirectory() as directory:
            first, second = Path(directory) / 'a.pyz', Path(directory) / 'b.pyz'
            remote.build_bundle(first)
            remote.build_bundle(second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertTrue(first.read_bytes().startswith(b'#!/usr/bin/env python3\n'))
            self.assertTrue(os.access(first, os.X_OK))
            names = set(zipfile.ZipFile(first).namelist())
        self.assertLessEqual({'__main__.py', 'host/launcher.py', 'host/data/lse.sh', 'host/data/LSE-LICENSE'}, names)
        self.assertLessEqual({'host/' + entry + '.py' for entry in launcher.ENTRIES}, names)

    def test_launcher_refuses_unknown_entries(self):
        for argv in ([], ['os'], ['../etc/passwd'], ['launcher']):
            self.assertEqual(launcher.main(argv), 2)

    def test_request_quotes_nothing_itself_and_stringifies_arguments(self):
        document = json.loads(remote.request('discover_firewall', ['--apply', '{"tcp":[22]}', 5], connection=True))
        self.assertEqual(document['ccdc_remote']['args'], ['--apply', '{"tcp":[22]}', '5'])
        self.assertTrue(document['ccdc_remote']['connection'])
        self.assertTrue(Path(document['ccdc_remote']['bundle']).is_file())


@unittest.skipUnless(shutil.which('ansible-playbook'), 'Ansible unavailable')
class RemotePlaybookTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        passive_fixtures(self.root)
        # A tiny stand-in entry proves delivery of args, payload, and environment.
        (self.root / 'host/manage_updates.py').write_text(
            'import json, os, sys\nprint(json.dumps({"args": sys.argv[1:], "stdin": sys.stdin.read(),\n'
            '    "connection": os.environ.get("SSH_CONNECTION"), "payload_var": "CCDC_PAYLOAD" in os.environ,\n'
            '    "cwd_has_bundle": any(p.endswith(".pyz") for p in sys.path)}))\n')
        shutil.copyfile(ROOT / 'host/launcher.py', self.root / 'host/launcher.py')
        (self.root / 'vendor').mkdir()
        (self.root / 'vendor/lse.sh').write_text('#!/bin/sh\ncat <<\'OUTPUT\'\n' + FIXTURE + 'OUTPUT\n')
        shutil.copyfile(ROOT / 'vendor/LSE-LICENSE', self.root / 'vendor/LSE-LICENSE')
        self.bundle = self.root / 'bundle.pyz'
        remote.build_bundle(self.bundle, root=self.root)

    def play(self, entry, args=(), connection=False, payload=None, extra=None):
        results = self.root / 'results'
        shutil.rmtree(results, ignore_errors=True)
        results.mkdir(mode=0o700)
        config = self.root / 'ansible.cfg'
        config.write_text(f'[defaults]\ncallback_plugins = {ROOT}/callback_plugins\ncallbacks_enabled = ccdc_results\n')
        request = {'ccdc_remote': {'bundle': str(self.bundle), 'entry': entry, 'args': list(args), 'become': False,
                                  'connection': connection, 'payload': str(payload or '')}}
        env = dict(os.environ, ANSIBLE_CONFIG=str(config), CCDC_RESULT_DIR=str(results),
                   CCDC_RESULT_TASK=remote.TASK, ANSIBLE_NOCOLOR='1')
        command = ['ansible-playbook', str(ROOT / 'playbooks/remote.yml'), '-i', 'fixture,', '-c', 'local',
                   '-e', json.dumps(dict(request, ansible_python_interpreter=sys.executable, ansible_become=False))]
        run = subprocess.run(command, env=env, capture_output=True, text=True, timeout=90)
        return run, results / 'fixture'

    def test_arguments_with_spaces_and_json_arrive_intact(self):
        run, result = self.play('manage_updates', ['--apply', '{"tcp": [22], "udp": []}', 'two words'])
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertEqual(json.loads(json.loads(result.read_text())['stdout'])['args'],
                         ['--apply', '{"tcp": [22], "udp": []}', 'two words'])
        self.assertEqual(result.stat().st_mode & 0o777, 0o600)

    def test_payload_becomes_stdin_and_is_removed(self):
        payload = self.root / 'request.json'
        payload.write_text('{"action": "plan"}')
        run, result = self.play('manage_updates', payload=payload)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        document = json.loads(json.loads(result.read_text())['stdout'])
        self.assertEqual(document['stdin'], '{"action": "plan"}')
        self.assertFalse(document['payload_var'])
        self.assertIn('Remove the request payload', run.stdout)

    def test_connection_is_forwarded_only_when_requested(self):
        os.environ.pop('SSH_CONNECTION', None)
        run, result = self.play('manage_updates')
        self.assertIsNone(json.loads(json.loads(result.read_text())['stdout'])['connection'])
        run, result = self.play('manage_updates', connection=True)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertEqual(json.loads(json.loads(result.read_text())['stdout'])['connection'], '')

    def test_bundled_pinned_lse_runs_and_unknown_entries_fail(self):
        run, result = self.play('discover_lse')
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        state = json.loads(json.loads(result.read_text())['stdout'])
        self.assertIn('fst030', {finding['id'] for finding in state['findings']})
        run, result = self.play('not_an_entry')
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(json.loads(result.read_text())['rc'], 2)


if __name__ == '__main__':
    unittest.main()
