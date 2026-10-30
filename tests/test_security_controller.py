"""Security scans remain current findings, not accepted initial baselines."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from test_controller import ctl, load

FINDING = {'id': 'sshd:content', 'path': '/usr/sbin/sshd',
           'severity': 'critical', 'summary': 'packaged contents modified'}
STATE = {'findings': [FINDING], 'raw': 'U /usr/sbin/sshd\n', 'errors': []}


class SecurityControllerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.addCleanup(patch.stopall)
        patch.object(ctl, 'ROOT', self.root).start()
        self.output = io.StringIO()
        redirect = contextlib.redirect_stdout(self.output)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)

    def test_status_always_reports_existing_findings_and_replaces_reports(self):
        with patch.object(ctl, 'collect', return_value=({'a': STATE}, {})):
            for _ in range(2):
                self.assertTrue(ctl.security_status('integrity', ['a']))
        self.assertEqual(self.output.getvalue().count('packaged contents modified'), 2)
        self.assertFalse((self.root / 'baselines').exists())
        report = self.root / 'reports/a/integrity/report.json'
        self.assertEqual(json.loads(report.read_text())['findings'], [FINDING])
        self.assertEqual((report.parent / 'raw.txt').read_text(), STATE['raw'])
        with patch.object(ctl, 'collect', return_value=({'a': {'findings': [], 'errors': [], 'raw': ''}}, {})):
            self.assertFalse(ctl.security_status('integrity', ['a']))
        self.assertFalse(json.loads(report.read_text())['findings'])

    def test_new_unchanged_changed_and_resolved_runtime_alerts(self):
        for kind in ('integrity', 'lse'):
            previous = {}
            events = ctl.monitor_events(previous, kind, ['a'], {'a': STATE}, {})
            self.assertEqual(len(events), 1)
            self.assertIn('NEW:', events[0][-1])
            self.assertEqual(ctl.monitor_events(previous, kind, ['a'], {'a': STATE}, {}), [])
            changed = dict(STATE, findings=[dict(FINDING, summary='contents and mode changed')])
            events = ctl.monitor_events(previous, kind, ['a'], {'a': changed}, {})
            self.assertIn('CHANGED:', events[0][-1])
            events = ctl.monitor_events(previous, kind, ['a'], {'a': {'findings': []}}, {})
            self.assertEqual(events[0][0], 'RESOLVED')
            self.assertEqual(ctl.monitor_events(previous, kind, ['a'], {'a': {'findings': []}}, {}), [])
            # Restart has no saved alert acceptance.
            self.assertIn('NEW:', ctl.monitor_events({}, kind, ['a'], {'a': STATE}, {})[0][-1])

    def test_resolving_one_condition_does_not_claim_the_whole_path_is_clean(self):
        previous = {}
        mode = dict(FINDING, id='mode', summary='mode changed')
        content = dict(FINDING, id='content', summary='contents modified')
        ctl.monitor_events(previous, 'integrity', ['a'], {'a': {'findings': [mode, content]}}, {})
        events = ctl.monitor_events(previous, 'integrity', ['a'], {'a': {'findings': [content]}}, {})
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][0], 'RESOLVED')
        self.assertIn('mode changed', events[0][-1])
        self.assertNotIn('matches expected state', events[0][-1])

    def test_incomplete_scan_cannot_resolve_active_findings(self):
        previous = {}
        ctl.monitor_events(previous, 'integrity', ['a'], {'a': STATE}, {})
        events = ctl.monitor_events(previous, 'integrity', ['a'], {}, {'a': 'unreachable'})
        self.assertEqual([e[0] for e in events], ['WARNING'])
        self.assertTrue(previous[('a', 'integrity')]['findings'])
        self.assertEqual(ctl.monitor_events(previous, 'integrity', ['a'], {}, {'a': 'unreachable'}), [])
        events = ctl.monitor_events(previous, 'integrity', ['a'], {'a': {'findings': [], 'errors': ['verifier failed']}}, {})
        self.assertNotIn('RESOLVED', [e[0] for e in events])
        events = ctl.monitor_events(previous, 'integrity', ['a'], {'a': {'findings': []}}, {})
        self.assertEqual([e[0] for e in events], ['RESOLVED', 'RESOLVED'])

    def test_real_scanners_share_controller_contract_including_warnings(self):
        integrity = load('discover-integrity')
        lse = load('discover-lse')
        state = integrity.document()
        integrity.parse_apk(state, 'U usr/sbin/sshd\ne etc/private\n')
        self.assertIs(ctl.scanner_state(state), state)
        lse_state = lse.parse('User ID: 1000\n[!] sud000 Sudo without password....... yes!\n---\nuid=0(root)\n---\n')
        self.assertIs(ctl.scanner_state(lse_state), lse_state)
        self.assertEqual(lse_state['findings'][0]['severity'], 'critical')
        with patch.object(ctl, 'collect', return_value=({'a': state}, {})):
            states, errors = ctl.scan('integrity', ['a'])
        self.assertEqual(states['a'], state)
        self.assertFalse(errors)

    def test_scoped_coverage_gap_does_not_block_unrelated_resolution(self):
        previous = {}
        state = {'findings': [dict(FINDING, id='fst160'), dict(FINDING, id='sud000')], 'errors': []}
        ctl.monitor_events(previous, 'lse', ['a'], {'a': state}, {})
        limited = {'findings': [], 'errors': [], 'incomplete_ids': ['fst160']}
        events = ctl.monitor_events(previous, 'lse', ['a'], {'a': limited}, {})
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][0], 'RESOLVED')
        self.assertEqual(len(previous[('a', 'lse')]['findings']), 1)
        self.assertEqual(next(iter(previous[('a', 'lse')]['findings'].values()))['id'], 'fst160')
        fixed = {'findings': [], 'errors': []}
        self.assertEqual(ctl.monitor_events(previous, 'lse', ['a'], {'a': fixed}, {})[0][0], 'RESOLVED')

    def test_passive_capability_failures_and_kernel_rc_do_not_resolve_prior_findings(self):
        extras = load('lse_extras.py')
        kernel = load('kernel_risks.py')
        previous = {}
        caps = dict(FINDING, id='extra-capabilities')
        pipe = dict(FINDING, id='kernel:CVE-2022-0847')
        ctl.monitor_events(previous, 'lse', ['a'], {'a': {'findings': [caps, pipe], 'errors': []}}, {})
        with patch.object(extras.os, 'geteuid', return_value=1000):
            failed = extras.inspect_capabilities('[!] sec010 Capabilities nope\n', 1)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'proc').mkdir()
            (root / 'proc/version').write_text('fixture')
            rc = kernel.inspect_kernel(root=root, release='5.17-rc1')
        partial = {'findings': failed['findings'] + rc['findings'], 'errors': [],
                   'incomplete_ids': failed['incomplete_ids'] + rc['incomplete_ids']}
        events = ctl.monitor_events(previous, 'lse', ['a'], {'a': partial}, {})
        self.assertNotIn('RESOLVED', [event[0] for event in events])
        with patch.object(extras.os, 'geteuid', return_value=1000):
            empty = extras.inspect_capabilities('[!] sec010 Capabilities nope\n', 0)
        empty['incomplete_ids'] = [kernel.DIRTY_PIPE]
        events = ctl.monitor_events(previous, 'lse', ['a'], {'a': empty}, {})
        resolutions = [event[-1] for event in events if event[0] == 'RESOLVED']
        self.assertTrue(any('extra-capabilities' in event for event in resolutions))
        self.assertFalse(any('kernel:CVE-2022-0847' in event for event in resolutions))

    def test_lse_context_changes_are_changes_not_false_resolutions(self):
        previous = {}
        old = dict(STATE, findings=[dict(FINDING, context=['/path/old'])])
        new = dict(STATE, findings=[dict(FINDING, context=['/path/new'])])
        ctl.monitor_events(previous, 'lse', ['a'], {'a': old}, {})
        events = ctl.monitor_events(previous, 'lse', ['a'], {'a': new}, {})
        self.assertEqual(len(events), 1)
        self.assertIn('CHANGED:', events[0][-1])

    def test_bad_host_result_does_not_discard_other_hosts(self):
        with patch.object(ctl, 'collect', return_value=({'a': STATE, 'b': {'bad': 'json'}}, {'c': 'unreachable'})):
            states, errors = ctl.scan('integrity', ['a', 'b', 'c'])
        self.assertEqual(list(states), ['a'])
        self.assertEqual(set(errors), {'b', 'c'})
        self.assertTrue(json.loads((self.root / 'reports/c/integrity/report.json').read_text())['incomplete'])

    def test_untrusted_malformed_fields_are_host_local_errors(self):
        for field, value in [('severity', []), ('path', {}), ('id', ''), ('summary', 42)]:
            bad = dict(STATE, findings=[dict(FINDING, **{field: value})])
            with patch.object(ctl, 'collect', return_value=({'a': STATE, 'b': bad}, {})):
                states, errors = ctl.scan('lse', ['a', 'b'])
            self.assertEqual(set(states), {'a'})
            self.assertEqual(set(errors), {'b'})

    def test_large_status_is_summarized_but_report_is_complete(self):
        findings = [dict(FINDING, id=f'file:{i}', path=f'/usr/bin/example{i}') for i in range(55)]
        with patch.object(ctl, 'collect', return_value=({'a': dict(STATE, findings=findings)}, {})):
            ctl.security_status('integrity', ['a'])
        self.assertEqual(self.output.getvalue().count('packaged contents modified'), 40)
        self.assertIn('15 additional findings', self.output.getvalue())
        self.assertEqual(len(json.loads((self.root / 'reports/a/integrity/report.json').read_text())['findings']), 55)

    def test_no_scanner_baseline_entry_point(self):
        for kind in ('integrity', 'lse'):
            with self.assertRaises(RuntimeError):
                ctl.baseline(kind, ['a'])
            with patch('sys.argv', ['ccdcctl', kind, 'baseline']), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    ctl.main()
                self.assertEqual(error.exception.code, 2)

    def test_cli_default_host_status_and_deep(self):
        for kind in ('integrity', 'lse'):
            for words, host, deep in [([], 'all', False), (['a'], 'a', False),
                                      (['status'], 'all', False), (['status', 'a', '--deep'], 'a', True),
                                      (['--deep'], 'all', True), (['a', '--deep'], 'a', True)]:
                with patch('sys.argv', ['ccdcctl', kind, *words]), \
                        patch.object(ctl, 'select', return_value=([host], {})) as select, \
                        patch.object(ctl, 'security_status', return_value=False) as status:
                    self.assertFalse(ctl.main())
                    select.assert_called_once_with(host)
                    status.assert_called_once_with(kind, [host], deep)

    def test_intervals_use_inventory_and_independent_defaults(self):
        result = ctl.polling_intervals(list(ctl.POLL_INTERVALS), ['a', 'b'], {'a': {'lse_poll_interval': 240}})
        self.assertEqual(result[('a', 'lse')], 240)
        self.assertEqual(result[('b', 'lse')], 180)
        self.assertEqual(result[('b', 'ssh')], 10)
        self.assertEqual(result[('b', 'integrity')], 60)
        with self.assertRaises(ValueError):
            ctl.polling_intervals(['integrity'], ['a'], {'a': {'integrity_poll_interval': 'nan'}})

    def test_slow_lse_does_not_block_recurring_ssh_poll(self):
        two_ssh_polls = threading.Event()
        count = 0
        clean = {'findings': [], 'errors': [], 'raw': ''}
        def collect(kind, hosts, args=()):
            nonlocal count
            if kind == 'lse':
                if not two_ssh_polls.wait(2):
                    raise AssertionError('LSE blocked SSH polling')
                return {'a': clean}, {}
            count += 1
            if count >= 2:
                two_ssh_polls.set()
            return {'a': {}}, {}
        original = ctl.monitor_events
        def events(previous, kind, hosts, states, errors):
            if kind == 'lse':
                raise KeyboardInterrupt
            return original(previous, kind, hosts, states, errors)
        with patch.object(ctl, 'select', return_value=(['a'], {})), \
                patch.object(ctl, 'collect', side_effect=collect), \
                patch.object(ctl, 'polling_intervals', return_value={('a', 'ssh'): .02, ('a', 'lse'): .02}), \
                patch.object(ctl, 'monitor_events', side_effect=events):
            with self.assertRaises(KeyboardInterrupt):
                ctl.monitor(['lse', 'ssh'], 'all')
        self.assertGreaterEqual(count, 2)

    def test_monitor_once_and_failure_isolation(self):
        with patch.object(ctl, 'select', return_value=(['a', 'b'], {})), \
                patch.object(ctl, 'collect', return_value=({'a': STATE}, {'b': 'unreachable'})):
            self.assertTrue(ctl.monitor(['integrity', 'lse'], 'all', once=True))
        output = self.output.getvalue()
        self.assertIn('CRITICAL a INTEGRITY', output)
        self.assertIn('CRITICAL a LSE', output)
        self.assertIn('WARNING b', output)
        self.assertNotIn(' OK', output)
        self.assertFalse((self.root / 'baselines').exists())

    def test_combined_cli_selects_exactly_four_modules(self):
        with patch('sys.argv', ['ccdcctl', 'monitor']), patch.object(ctl, 'monitor', return_value=False) as monitor:
            self.assertFalse(ctl.main())
        monitor.assert_called_once_with(['ssh', 'firewall', 'integrity', 'lse'], 'all', None, False)

    def test_monitor_emission_is_ranked_capped_and_keeps_failure_notices(self):
        events = [('REVIEW', 'a', 'integrity', f'NEW: config{i}') for i in range(50)]
        events += [('CRITICAL', 'a', 'integrity', 'NEW: /usr/sbin/sshd modified'),
                   ('WARNING', 'a', 'integrity', 'scanner/connectivity failure: verifier failed'),
                   ('RESOLVED', 'a', 'integrity', '/bin/sh now matches')]
        ctl.emit_monitor_events(events)
        output = self.output.getvalue()
        self.assertIn('/usr/sbin/sshd modified', output)
        self.assertIn('verifier failed', output)
        self.assertIn('/bin/sh now matches', output)
        self.assertIn('11 additional finding events', output)
        self.assertEqual(output.count('NEW:'), 40)

    def test_lse_transport_uses_the_shared_runner_and_normal_mode(self):
        def run(args, result_dir=None, result_task=None):
            self.assertEqual(result_task, 'Run host script')
            self.assertEqual(args[:2], ['ansible-playbook', 'playbooks/remote.yml'])
            request = json.loads(args[args.index('--extra-vars') + 1])['ccdc_remote']
            self.assertEqual((request['entry'], request['args'], request['become']), ('discover_lse', [], True))
            (Path(result_dir) / 'a').write_text(json.dumps({'stdout': json.dumps(STATE), 'rc': 0}))
            return subprocess.CompletedProcess(args, 0, '', '')
        with patch.object(ctl, 'run', side_effect=run):
            states, errors = ctl.collect('lse', ['a'])
        self.assertFalse(errors)
        self.assertEqual(states['a'], STATE)

    def test_console_does_not_execute_remote_controls(self):
        self.assertEqual(ctl.terminal('\x1b[31mcritical\x1b[0m\x07\r'), 'critical??')


if __name__ == '__main__':
    unittest.main()
