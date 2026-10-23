"""Exercise Bash completion offline with a fake inventory CLI; no SSH."""
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/ccdcctl-completion.bash'


@unittest.skipUnless(shutil.which('bash'), 'Bash unavailable')
class CompletionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.log = self.root / 'calls'
        inventory = {'ungrouped': {'hosts': ['beta', 'alpha']}, '_meta': {
            'hostvars': {'alpha': {'ansible_password': 'must-not-complete'}}}}
        fake = self.root / 'ansible-inventory'
        fake.write_text('#!/bin/sh\n'
                        'printf "%s|%s|%s|%s\\n" "$ANSIBLE_INVENTORY" "$ANSIBLE_CONFIG" "$*" "$PWD" >> "$CALL_LOG"\n'
                        "printf '%s\\n' '" + json.dumps(inventory) + "'\n")
        fake.chmod(0o700)
        self.env = dict(os.environ, PATH=str(self.root) + os.pathsep + os.environ['PATH'],
                        ANSIBLE_INVENTORY='selected.yml', CALL_LOG=str(self.log))

    def complete(self, *words, invoked='ccdcctl'):
        line = shlex.join([invoked, *words[:-1]]) + ' '
        if words[-1]:
            line += shlex.quote(words[-1])
        return self.complete_line(line, words[-1], words[-2] if len(words) > 1 else invoked,
                                  invoked=invoked)

    def complete_line(self, line, current, previous, point=None, invoked='ccdcctl'):
        env = dict(self.env, COMP_LINE=line, COMP_POINT=str(len(line.encode()) if point is None else point))
        result = subprocess.run([str(ROOT / 'scripts/ccdcctl'), 'complete', invoked, current, previous],
            cwd=self.root, env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        return result.stdout.splitlines()

    def test_commands_actions_and_context_specific_flags(self):
        cases = [
            (('',), 'init'),
            (('firewall', 'r'), 'rollback'),
            (('ssh', 'c'), 'configure'),
            (('--verbose', 'ssh', 'c'), 'configure'),
            (('ssh', 'status', '--j'), '--json'),
            (('firewall', 'configure', '--v'), '--verbose'),
            (('init', '--replace'), '--replace-host-keys'),
            (('init', 'alpha', '--save'), '--save-bootstrap-password'),
            (('integrity', '--d'), '--deep'),
            (('lse', '--d'), '--deep'),
            (('monitor', 'i'), 'integrity'),
            (('monitor', '--o'), '--once'),
        ]
        for words, expected in cases:
            with self.subTest(words=words):
                self.assertIn(expected, self.complete(*words))
        self.assertEqual(self.complete('ssh', '--replace'), [])
        self.assertEqual(self.complete('monitor', '--interval', ''), [])
        self.assertFalse(self.log.exists(), 'Command/flag completion must not read inventory')

    def test_hosts_come_from_selected_inventory_without_secret_variables(self):
        for words in [('ping', 'a'), ('--verbose', 'ssh', 'status', 'a'), ('init', '--replace-host-keys', 'b'),
                      ('firewall', 'status', 'a'), ('lse', 'status', 'b'),
                      ('monitor', '--host', 'a')]:
            with self.subTest(words=words):
                matches = self.complete(*words)
                self.assertEqual(matches, ['all', 'alpha'] if words[-1] == 'a' else ['beta'])
        self.assertEqual(self.complete('ping', 'alpha', 'b'), [])
        matches = self.complete('listeners', '')
        self.assertNotIn('$(unsafe)', matches)
        self.assertNotIn('must-not-complete', matches)
        for line in self.log.read_text().splitlines():
            self.assertEqual(line, f'selected.yml|{ROOT}/ansible.cfg|--list|{ROOT}')

    def test_lab_and_monitor_commands(self):
        for tool in ('docker', 'ssh-keygen'):
            fake = self.root / tool
            fake.write_text('#!/bin/sh\nprintf "%s\\n" "$0 $*" >> "$CALL_LOG"\nexit 99\n')
            fake.chmod(0o700)
        cases = [
            ('./lab/manage', ('u',), ['up']),
            ('lab/manage', ('d',), ['down']),
            (str(ROOT / 'lab/manage'), ('up', '--p'), ['--password-file']),
            ('./lab/manage', ('down', '--p'), []),
            ('./lab/manage', ('_',), []),
            ('./lab/manage', ('up', '--password-file', 'password'), []),
            ('./scripts/check-lab', ('--i',), ['--inventory']),
            ('check-lab', ('--p',), ['--password-file']),
            ('./scripts/check-lab', ('--inventory', 'selected.yml', '--p'), ['--password-file']),
            ('./scripts/check-lab', ('--inventory', 'selected'), []),
            ('./monitor/ssh-monitor', ('--o',), ['--once']),
            ('firewall-monitor', ('--i',), ['--interval']),
            ('./monitor/firewall-monitor', ('--interval', '10', '--h'), ['--help', '--host']),
            ('./monitor/ssh-monitor', ('i',), []),
        ]
        for invoked, words, expected in cases:
            with self.subTest(invoked=invoked, words=words):
                self.assertEqual(self.complete(*words, invoked=invoked), expected)
        self.assertNotIn('_forward', self.complete('', invoked='./lab/manage'))
        self.assertFalse(self.log.exists(), 'Lab/flag completion must not run inventory')
        for invoked in ('./monitor/ssh-monitor', './monitor/firewall-monitor'):
            self.assertEqual(self.complete('--host', 'a', invoked=invoked), ['all', 'alpha'])

    def test_bash_registration_and_native_filename_fallback(self):
        result = subprocess.run(['bash', '--noprofile', '--norc', '-c',
            'source "$1"; complete -p ccdcctl ./scripts/ccdcctl ./lab/manage '
            './scripts/check-lab ./monitor/ssh-monitor ./monitor/firewall-monitor', 'bash', str(SCRIPT)],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('-o default', result.stdout)
        self.assertIn(' complete', result.stdout)
        self.assertIn('-C ', result.stdout)
        self.assertEqual(len(result.stdout.splitlines()), 6)
        self.assertEqual(self.complete('init', '--bootstrap-password-file', 'password'), [])
        self.assertFalse(self.log.exists())

    def test_setup_activates_venv_and_registers_all_commands(self):
        checkout = self.root / 'checkout with spaces'
        checkout.mkdir()
        shutil.copy2(ROOT / 'setup', checkout / 'setup')
        (checkout / 'scripts').mkdir()
        shutil.copy2(SCRIPT, checkout / 'scripts/ccdcctl-completion.bash')
        subprocess.run([shutil.which('python3'), '-m', 'venv', '--without-pip', str(checkout / '.venv')],
                       check=True, capture_output=True, text=True, timeout=30)
        result = subprocess.run(['bash', '--noprofile', '--norc', '-c',
            'source "$1" || exit; [[ "$VIRTUAL_ENV" == "$2/.venv" ]] || exit 2; '
            '[[ "$(command -v python)" == "$2/.venv/bin/python" ]] || exit 3; '
            '[[ ! -v _ccdc_setup_root ]] || exit 4; '
            'complete -p ccdcctl ./lab/manage ./scripts/check-lab '
            './monitor/ssh-monitor ./monitor/firewall-monitor',
            'bash', str(checkout / 'setup'), str(checkout)],
            cwd=self.root, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(result.stdout.splitlines()), 5)
        self.assertEqual(result.stderr, '')

    def test_setup_explains_missing_venv_and_direct_execution(self):
        setup = self.root / 'setup'
        shutil.copy2(ROOT / 'setup', setup)
        for args, message in [
            (['bash', str(setup)], 'source'),
            (['bash', '--noprofile', '--norc', '-c', 'source "$1"', 'bash', str(setup)], 'uv sync'),
        ]:
            with self.subTest(args=args):
                result = subprocess.run(args, cwd=self.root, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 1)
                self.assertIn(message, result.stderr)

    def test_incomplete_quotes_and_cursor_in_middle(self):
        self.assertEqual(self.complete_line('ccdcctl monitor --host "a', 'a', '--host'), ['all', 'alpha'])
        self.assertIn('--once', self.complete_line('ccdcctl monitor --o ignored', '--o', 'monitor',
                                                  len('ccdcctl monitor --o')))
        self.assertEqual(self.complete_line('ccdcctl init --bootstrap-password-file "password with ',
                                            'password with ', '--bootstrap-password-file'), [])

    def test_inventory_failure(self):
        fake = self.root / 'ansible-inventory'
        fake.write_text('#!/bin/sh\nexit 1\n')
        self.assertIn('all', self.complete('init', ''))
        self.assertIn('--replace-host-keys', self.complete('init', '--replace'))


if __name__ == '__main__':
    unittest.main()
