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
                    status.assert_called_once_with(kind, [host], deep, None)

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


class FixOfferTests(SecurityControllerTests):
    def state(self, tier='simple', uid=0):
        fix = {'path': '/etc/x', 'mode': 0o644, 'uid': uid, 'gid': 0, 'tier': tier,
               'was': {'mode': 0o666, 'uid': 5 if uid == 0 and tier == 'all' else 0, 'gid': 0}}
        return {'findings': [dict(FINDING, fix=fix)], 'raw': '', 'errors': []}

    def offer(self, state, auto=None, tty=False, answers=()):
        with patch.object(ctl.sys.stdin, 'isatty', return_value=tty), \
                patch.object(ctl, 'ask', side_effect=list(answers)), \
                patch.object(ctl, 'act', return_value=True) as act:
            ctl.offer_fixes('a', state, auto)
        return act

    def test_non_interactive_without_flag_never_mutates(self):
        self.assertFalse(self.offer(self.state()).called)

    def test_prompt_applies_only_on_yes(self):
        self.assertFalse(self.offer(self.state(), tty=True, answers=['n']).called)
        act = self.offer(self.state(), tty=True, answers=['y'])
        self.assertEqual(act.call_args.args[:2], ('a', 'apply_fixes'))

    def test_auto_apply_simple_skips_ownership_changes_without_a_tty(self):
        self.assertTrue(self.offer(self.state('simple'), auto='simple').called)
        self.assertFalse(self.offer(self.state('all'), auto='simple').called)
        self.assertTrue(self.offer(self.state('all'), auto='all').called)

    def test_malformed_fixes_are_ignored(self):
        state = self.state()
        state['findings'][0]['fix']['path'] = 'relative'
        self.assertFalse(self.offer(state, auto='all').called)
        state['findings'][0]['fix'] = {'tier': 'all', 'path': '/x'}
        self.assertFalse(self.offer(state, auto='all').called)


class SysctlFixPlanTests(unittest.TestCase):
    def test_sysctl_and_multi_fix_findings_are_planned_and_validated(self):
        good = {'kind': 'sysctl', 'tier': 'all', 'settings': {'user.max_user_namespaces': '0'},
                'was': {'user.max_user_namespaces': '15000'}}
        perm = {'path': '/a', 'mode': 0o644, 'uid': 0, 'gid': 0, 'tier': 'simple',
                'was': {'mode': 0o666, 'uid': 0, 'gid': 0}}
        bad = dict(good, settings={'kernel.randomize_va_space': '0'})
        plan = ctl.fix_plan({'findings': [{'fixes': [good, perm, perm, bad, 'junk']}]})
        self.assertEqual([p[1].get('kind', 'perm') for p in plan], ['sysctl', 'perm'])
        self.assertIn('15000 -> 0', plan[0][2])
