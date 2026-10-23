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
        patch.object(ctl, 'VERBOSE', False).start()
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

    def test_remote_script_failure_reports_json_error_not_ssh_close_notice(self):
        error = 'unsupported xtables compat expression, use iptables-nft with this ruleset'
        for stream in ('stdout', 'stderr'):
            def fake_run(args, result_dir=None):
                response = {'rc': 1, 'failed': True, 'msg': 'non-zero return code',
                            'stdout': '', 'stderr': 'Shared connection to 127.0.0.1 closed.\r\n'}
                response[stream] = json.dumps({'error': error}) + '\r\n'
                (Path(result_dir) / 'a').write_text(json.dumps(response))
                return subprocess.CompletedProcess(args, 2, '', '')
            with self.subTest(stream=stream), patch.object(ctl, 'run', side_effect=fake_run):
                states, errors = ctl.collect('firewall', ['a'], ['--snapshot'])
                self.assertFalse(states)
                self.assertEqual(errors, {'a': error})

    def test_remote_script_failure_retains_non_json_diagnostics(self):
        def fake_run(args, result_dir=None):
            response = {'rc': 1, 'stdout': 'sudo: permission denied\r\n',
                        'stderr': 'Shared connection to 127.0.0.1 closed.\r\n'}
            (Path(result_dir) / 'a').write_text(json.dumps(response))
            return subprocess.CompletedProcess(args, 2, '', '')
        with patch.object(ctl, 'run', side_effect=fake_run):
            states, errors = ctl.collect('firewall', ['a'])
        self.assertFalse(states)
        self.assertIn('sudo: permission denied', errors['a'])

    def test_ssh_status_is_readable_and_keeps_scope_and_socket_warnings(self):
        state = dict(SSH, sources={'/etc/ssh/sshd_config': 'not-for-the-summary'},
                     context=None, match_rules=[{'directive': 'match', 'arguments': ['User', 'root']}],
                     socket_listeners={'ssh.socket': '2222 (Stream)'},
                     caveats=['\x1b[31mUnexpected vendor setting\x1b[0m'])
        with patch.object(ctl, 'collect', return_value=({'a': state}, {})):
            self.assertFalse(ctl.status('ssh', ['a']))
        text = self.output.getvalue()
        self.assertIn('Root login: no', text)
        self.assertIn('Password: no', text)
        self.assertIn('Interactive: no', text)
        self.assertIn('Public key: yes', text)
        self.assertIn('global defaults', text)
        self.assertIn('Match rules may differ', text)
        self.assertIn('conditional Match/Include', text)
        self.assertIn('2222 (Stream)', text)
        self.assertIn('Unexpected vendor setting', text)
        self.assertNotIn('\x1b', text)
        self.assertNotIn('not-for-the-summary', text)
        self.assertNotIn('"effective"', text)

    def test_firewall_summary_does_not_confuse_unknown_with_closed_ports(self):
        state = {'backend': 'nftables', 'default_inbound': None, 'allowed_tcp': None,
                 'allowed_udp': None, 'ssh22': None,
                 'explicit_inbound_accepts': [{'protocol': 'tcp', 'ports': [443]}],
                 'input_policies': [{'family': 'inet', 'table': 'filter', 'chain': 'input', 'policy': 'drop'}],
                 'source_rules': [{'rule': 'source-conditional'}], 'rules': {'managers': ['firewalld']}}
        text = ctl.firewall_text(state)
        for phrase in ('Allowed TCP: unknown', 'Allowed UDP: unknown', 'TCP/22: unknown',
                       'NOT reachability', 'conditions/order may deny', 'tcp/443',
                       'inet/filter/input: drop', 'restrictions are NOT retained', 'firewalld'):
            self.assertIn(phrase, text)
        text = ctl.firewall_text(dict(state, allowed_tcp=[22, 443], allowed_udp=[], ssh22=True, default_inbound='drop'))
        self.assertIn('Allowed TCP: 22, 443', text)
        self.assertIn('Allowed UDP: none', text)
        self.assertIn('TCP/22: allowed', text)
        self.assertNotIn('ACCEPT candidates', text)

    def test_status_json_keeps_full_documents_and_partial_failures(self):
        stderr = io.StringIO()
        with patch.object(ctl, 'collect', return_value=({'a': SSH}, {'b': 'unreachable'})), \
                contextlib.redirect_stderr(stderr):
            self.assertTrue(ctl.status('ssh', ['a', 'b'], json_output=True))
        self.assertEqual(json.loads(self.output.getvalue()), {'hosts': {'a': SSH}, 'errors': {'b': 'unreachable'}})
        self.assertEqual(stderr.getvalue(), '')

    def test_verbose_retains_discovery_details(self):
        with patch.object(ctl, 'VERBOSE', True):
            ctl.show_state('ssh', SSH, 'Current SSH')
        self.assertIn('"effective"', self.output.getvalue())

    def test_output_flags_can_follow_command_or_precede_it(self):
        parser = ctl.argument_parser()
        for words in (['--verbose', 'ssh', 'status', 'a'], ['ssh', 'status', 'a', '--verbose']):
            self.assertTrue(parser.parse_args(words).verbose)
        self.assertTrue(parser.parse_args(['firewall', 'status', '--json']).json)
        self.assertFalse(parser.parse_args(['ssh', 'status']).verbose)

    def test_json_cannot_be_used_to_hide_configuration_review(self):
        with patch.object(ctl.sys, 'argv', ['ccdcctl', 'firewall', 'configure', '--json']), \
                patch.object(ctl, 'select') as select, contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(SystemExit) as raised:
            ctl.main()
        self.assertEqual(raised.exception.code, 2)
        select.assert_not_called()

    def test_visible_ansible_uses_progress_but_capture_and_verbose_do_not(self):
        response = subprocess.CompletedProcess([], 0, '', '')
        with patch.object(ctl.subprocess, 'run', return_value=response) as run:
            ctl.run(['ansible-playbook', 'playbooks/ssh.yml'], capture=False)
            env = run.call_args.kwargs['env']
            self.assertEqual(env['ANSIBLE_STDOUT_CALLBACK'], 'ccdc_progress')
            self.assertEqual(env['ANSIBLE_LOAD_CALLBACK_PLUGINS'], '1')
            self.assertNotIn('ccdc_summary', env['ANSIBLE_CALLBACKS_ENABLED'])
            with patch.dict(ctl.os.environ, {}, clear=True):
                ctl.run(['ansible-inventory', '--list'])
                self.assertNotIn('ANSIBLE_STDOUT_CALLBACK', run.call_args.kwargs['env'])
                with patch.object(ctl, 'VERBOSE', True):
                    ctl.run(['ansible-playbook', 'playbooks/ssh.yml'], capture=False)
                self.assertNotIn('ANSIBLE_STDOUT_CALLBACK', run.call_args.kwargs['env'])

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
            if variables.get('firewall_action') == 'prepare':
                self.assertFalse(events)
                events.append(('prepare', host))
                return True
            self.assertIn(('aggregate-confirmed',), events)
            self.assertTrue((self.root / 'reports/rollback' / host / 'firewall.json').is_file())
            self.assertEqual(variables['firewall_tcp_ports'], [22, 3000])
            events.append(('apply', host))
            return True
        with patch.object(ctl, 'collect', side_effect=collect), patch.object(ctl, 'ask', side_effect=ask), \
                patch.object(ctl, 'playbook', side_effect=apply):
            self.assertFalse(ctl.configure_firewall(['a', 'b']))
        self.assertEqual(events[0], ('prepare', 'a:b'))
        self.assertEqual([event for event in events if event[0] == 'apply'], [('apply', 'a'), ('apply', 'b')])

    def test_firewall_abort_never_snapshots_or_applies(self):
        def collect(kind, hosts, args=()):
            self.assertFalse(args)
            return {host: [] if kind == 'listeners' else {'backend': 'nftables'} for host in hosts}, {}
        with patch.object(ctl, 'collect', side_effect=collect), patch.object(ctl, 'ask', side_effect=['y', 'n']), \
                patch.object(ctl, 'playbook') as play:
            self.assertFalse(ctl.configure_firewall(['a']))
        play.assert_called_once_with('firewall', 'a', {'firewall_action': 'prepare'})

    def test_firewall_preparation_failure_stops_before_discovery(self):
        with patch.object(ctl, 'playbook', return_value=False) as play, patch.object(ctl, 'collect') as collect:
            self.assertTrue(ctl.configure_firewall(['a']))
        play.assert_called_once_with('firewall', 'a', {'firewall_action': 'prepare'})
        collect.assert_not_called()

    def test_firewall_refuses_to_close_nonstandard_ssh_port(self):
        def collect(kind, hosts, args=()):
            state = [] if kind == 'listeners' else {'effective': {'port': ['2222']}} if kind == 'ssh' else {}
            return {'a': state}, {}
        with patch.object(ctl, 'collect', side_effect=collect), patch.object(ctl, 'ask', side_effect=['y', 'y']), \
                patch.object(ctl, 'playbook') as play:
            self.assertTrue(ctl.configure_firewall(['a']))
        play.assert_called_once_with('firewall', 'a', {'firewall_action': 'prepare'})

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

    def test_ssh_baseline_and_monitor_compare_settings_not_hashes(self):
        observed = dict(SSH, sources={'/etc/ssh/sshd_config': 'old'},
                        dropins={'/etc/ssh/sshd_config.d/vendor.conf': 'old'},
                        context=None, socket_listeners={}, caveats=['old'], sshd='/old/sshd')
        path = self.root / 'baselines/a/ssh.json'
        with patch.object(ctl, 'collect', return_value=({'a': observed}, {})):
            self.assertFalse(ctl.baseline('ssh', ['a']))
        saved = json.loads(path.read_text())
        self.assertNotIn('sources', saved)
        self.assertNotIn('dropins', saved)
        self.assertEqual(saved['effective'], SSH['effective'])
        # Old full-discovery baselines also work without reaccepting host state.
        ctl.save(path, observed)
        trusted = path.read_bytes()
        changed = dict(observed, sources={'/etc/ssh/sshd_config': 'new'}, dropins={},
                       caveats=['new'], sshd='/new/sshd')
        previous = {}
        self.assertEqual(ctl.monitor_events(previous, 'ssh', ['a'], {'a': changed}, {}), [])
        changed['effective'] = dict(SSH['effective'], passwordauthentication=['yes'])
        events = ctl.monitor_events(previous, 'ssh', ['a'], {'a': changed}, {})
        self.assertEqual(events[0][0], 'CRITICAL')
        self.assertIn('passwordauthentication', events[0][-1])
        self.assertNotIn('sources', events[0][-1])
        self.assertEqual(ctl.monitor_events(previous, 'ssh', ['a'], {'a': observed}, {})[0][0], 'RESOLVED')
        self.assertEqual(path.read_bytes(), trusted)
        for field, new in [('socket_listeners', {'ssh.socket': '2222 (Stream)'}),
                           ('context', 'user=root,addr=192.0.2.1'),
                           ('match_rules', [{'directive': 'match', 'arguments': ['User', 'root']},
                                            {'directive': 'permitrootlogin', 'arguments': ['yes']}])]:
            events = ctl.monitor_events({}, 'ssh', ['a'], {'a': dict(observed, **{field: new})}, {})
            self.assertEqual(events[0][0], 'CRITICAL')

    def test_invalid_ssh_baseline_preserves_trust_and_alerts(self):
        path = self.root / 'baselines/a/ssh.json'
        ctl.save(path, SSH)
        original = path.read_bytes()
        with patch.object(ctl, 'collect', return_value=({'a': {}}, {})), contextlib.redirect_stderr(io.StringIO()):
            self.assertTrue(ctl.baseline('ssh', ['a']))
        self.assertEqual(path.read_bytes(), original)
        for invalid in ({}, [], None):
            ctl.save(path, invalid)
            events = ctl.monitor_events({}, 'ssh', ['a'], {'a': SSH}, {})
            self.assertEqual(events[0][0], 'WARNING')

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
