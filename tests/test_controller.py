"""Offline safety/UX checks: never connects to or changes a host."""
import contextlib
import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    loader = importlib.machinery.SourceFileLoader(name.replace('-', '_'), str(ROOT / 'scripts' / name))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


ctl = load('ccdcctl')
VERIFY_ADMIN = ctl.verify_admin_access
SSH = {'effective': {'permitrootlogin': ['no'], 'passwordauthentication': ['no'],
                     'kbdinteractiveauthentication': ['no'], 'pubkeyauthentication': ['yes'], 'port': ['22']}}
LISTENER = {'protocol': 'tcp', 'port': 3000, 'address': '0.0.0.0', 'family': 'IPv4',
            'external': True, 'loopback_only': False, 'pid': 10, 'process': 'gitea',
            'executable': '/usr/bin/gitea', 'user': 'git', 'service': 'gitea', 'service_confidence': 'cgroup'}


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.addCleanup(patch.stopall)
        patch.object(ctl, 'ROOT', self.root).start()
        patch.object(ctl, 'verify_admin_access', return_value=True).start()
        self.output = io.StringIO()
        self.redirect = contextlib.redirect_stdout(self.output)
        self.redirect.__enter__()
        self.addCleanup(self.redirect.__exit__, None, None, None)

    def test_inventory_enumerates_ansible_not_second_list(self):
        data = {'all': {'children': ['ungrouped']}, 'ungrouped': {'hosts': ['beta', 'alpha']},
                '_meta': {'hostvars': {'alpha': {'ansible_host': '192.0.2.1'}, 'beta': {}}}}
        result = subprocess.CompletedProcess([], 0, json.dumps(data), '')
        with patch.object(ctl, 'run', return_value=result) as run:
            self.assertEqual(ctl.select()[0], ['alpha', 'beta'])
            self.assertEqual(ctl.select('beta')[0], ['beta'])
            with self.assertRaises(RuntimeError):
                ctl.select('not-a-host')
            self.assertEqual(run.call_args.args[0][0:2], ['ansible-inventory', '--list'])

    def test_reject_unsafe_inventory_names(self):
        result = subprocess.CompletedProcess([], 0, json.dumps({'ungrouped': {'hosts': ['../escape']}}), '')
        with patch.object(ctl, 'run', return_value=result), self.assertRaises(RuntimeError):
            ctl.inventory()

    def test_batch_keeps_success_when_host_unreachable(self):
        def fake_run(args, result_dir=None):
            directory = Path(result_dir)
            (directory / 'a').write_text(json.dumps({'stdout': json.dumps(SSH), 'rc': 0}))
            (directory / 'b').write_text(json.dumps({'unreachable': True, 'msg': 'authentication failed'}))
            return subprocess.CompletedProcess(args, 4, '', '')
        with patch.object(ctl, 'run', side_effect=fake_run):
            states, errors = ctl.collect('ssh', ['a', 'b'])
        self.assertEqual(states, {'a': SSH})
        self.assertIn('authentication failed', errors['b'])

    def test_admin_preflight_disables_connection_reuse_and_passwords(self):
        response = subprocess.CompletedProcess([], 0, '', '')
        with patch.object(ctl, 'run', return_value=response) as run:
            self.assertTrue(VERIFY_ADMIN('a'))
        args = run.call_args.args[0]
        variables = json.loads(args[args.index('--extra-vars') + 1])
        self.assertEqual(variables['ansible_user'], 'oski')
        self.assertTrue(variables['ansible_become'])
        self.assertIn('ControlPath=none', variables['ansible_ssh_args'])
        self.assertIn('PasswordAuthentication=no', variables['ansible_ssh_args'])

    def test_ssh_apply_is_sequential_and_verified(self):
        calls = []
        def collect(kind, hosts, args=()):
            calls.append(('discover', hosts[0]))
            return {hosts[0]: SSH}, {}
        def play(name, host, variables):
            calls.append(('apply', host))
            self.assertFalse(variables['password_auth'])
            return True
        with patch.object(ctl, 'collect', side_effect=collect), patch.object(ctl, 'playbook', side_effect=play), \
                patch.object(ctl, 'ask', side_effect=['a', 'y', 'reuse', 'y']):
            self.assertFalse(ctl.configure_ssh(['a', 'b']))
        self.assertEqual(calls, [('discover', 'a'), ('apply', 'a'), ('discover', 'a'),
                                 ('discover', 'b'), ('apply', 'b'), ('discover', 'b')])

    def test_firewall_aggregate_review_precedes_all_applies(self):
        events = []
        def collect(kind, hosts, args=()):
            events.append((kind, tuple(hosts), tuple(args)))
            state = [LISTENER] if kind == 'listeners' else SSH if kind == 'ssh' else {'backend': 'nftables'}
            return {host: state for host in hosts}, {}
        choices = iter(['a', 'y', 'reuse', 'y', 'y'])
        def ask(prompt, options, default):
            answer = next(choices)
            if '[y] apply all' in prompt:
                events.append(('aggregate-confirmed',))
            return answer
        def apply(name, host, variables):
            self.assertIn(('aggregate-confirmed',), events)
            self.assertTrue((self.root / 'reports/rollback' / host / 'firewall.json').is_file())
            self.assertEqual(variables['firewall_tcp_ports'], [22, 3000])
            events.append(('apply', host))
            return True
        with patch.object(ctl, 'collect', side_effect=collect), patch.object(ctl, 'ask', side_effect=ask), \
                patch.object(ctl, 'playbook', side_effect=apply):
            self.assertFalse(ctl.configure_firewall(['a', 'b']))
        self.assertEqual([event for event in events if event[0] == 'apply'], [('apply', 'a'), ('apply', 'b')])

    def test_firewall_abort_never_snapshots_or_applies(self):
        def collect(kind, hosts, args=()):
            self.assertFalse(args)
            return {host: [] if kind == 'listeners' else {'backend': 'nftables'} for host in hosts}, {}
        with patch.object(ctl, 'collect', side_effect=collect), patch.object(ctl, 'ask', side_effect=['y', 'n']), \
                patch.object(ctl, 'playbook') as play:
            self.assertFalse(ctl.configure_firewall(['a']))
        play.assert_not_called()

    def test_firewall_refuses_to_close_nonstandard_ssh_port(self):
        def collect(kind, hosts, args=()):
            state = [] if kind == 'listeners' else {'effective': {'port': ['2222']}} if kind == 'ssh' else {}
            return {'a': state}, {}
        with patch.object(ctl, 'collect', side_effect=collect), patch.object(ctl, 'ask', side_effect=['y', 'y']), \
                patch.object(ctl, 'playbook') as play:
            self.assertTrue(ctl.configure_firewall(['a']))
        play.assert_not_called()

    def test_listener_reports_cover_every_host_and_failure(self):
        with patch.object(ctl, 'collect', return_value=({'a': [LISTENER]}, {'b': 'unreachable'})):
            self.assertTrue(ctl.listeners(['a', 'b'], {'a': {'ansible_host': '192.0.2.1'}}))
        text = (self.root / 'reports/listeners.txt').read_text()
        structured = json.loads((self.root / 'reports/listeners.json').read_text())
        self.assertIn('a - 192.0.2.1', text)
        self.assertIn('gitea', text)
        self.assertIn('b - b', text)
        self.assertEqual(structured['hosts']['b']['error'], 'unreachable')
        self.assertEqual(structured['hosts']['a']['listeners'][0]['port'], 3000)

    def test_monitor_never_accepts_drift_and_is_quiet_when_healthy(self):
        path = self.root / 'baselines/a/ssh.json'
        ctl.save(path, SSH)
        original = path.read_bytes()
        with patch.object(ctl, 'select', return_value=(['a'], {})), \
                patch.object(ctl, 'collect', return_value=({'a': SSH}, {})):
            self.assertFalse(ctl.monitor(['ssh'], 'all', 5, True))
        self.assertNotIn('CRITICAL', self.output.getvalue())
        changed = {'effective': dict(SSH['effective'], passwordauthentication=['yes'])}
        with patch.object(ctl, 'select', return_value=(['a'], {})), \
                patch.object(ctl, 'collect', return_value=({'a': changed}, {})):
            self.assertTrue(ctl.monitor(['ssh'], 'all', 5, True))
        self.assertIn('CRITICAL', self.output.getvalue())
        self.assertEqual(path.read_bytes(), original)

    def test_failed_baseline_leaves_previous_trust_intact(self):
        path = self.root / 'baselines/a/ssh.json'
        ctl.save(path, SSH)
        original = path.read_bytes()
        with patch.object(ctl, 'collect', return_value=({}, {'a': 'unreachable'})):
            self.assertTrue(ctl.baseline('ssh', ['a']))
        self.assertEqual(path.read_bytes(), original)

    def test_bulk_identity_does_not_equate_unrelated_same_ports(self):
        other = dict(LISTENER, process='malware', service=None, executable='/tmp/listener')
        self.assertEqual(len(ctl.groups([LISTENER, other])), 2)
        unknown = dict(LISTENER, process=None, service=None, executable=None)
        self.assertEqual(len(ctl.groups([unknown, dict(unknown, port=4000)])), 2)


if __name__ == '__main__':
    unittest.main()
