"""Offline fixtures only: never query the host manager or read secret contents."""
import importlib.util
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

SPEC = importlib.util.spec_from_file_location('lse_host_risks', Path(__file__).resolve().parents[1] / 'scripts/lse_host_risks.py')
host = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(host)


def native(**values):
    properties = dict.fromkeys(host.PROPERTIES, '')
    properties['DynamicUser'] = 'no'
    properties.update(values)
    return '\n'.join(key + '=' + value for key, value in properties.items())


def executable(path):
    return '{ path=' + str(path) + ' ; argv[]=' + str(path) + ' ignored-argument ; ignore_errors=no ; pid=0 ; status=0/0 }'


def evidence(result, test_id):
    return [c['evidence'][0] for f in result['findings'] if f['id'] == test_id for c in f['context']]


class HostFixtures(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.uid = self.enterContext(patch.object(host.os, 'geteuid', return_value=1001))
        self.access = self.enterContext(patch.object(host, '_access', return_value=False))
        self.enterContext(patch.object(host.subprocess, 'Popen', side_effect=AssertionError('No host commands in tests')))
        self.owners = {}
        original = host._metadata

        def metadata(path, gaps, follow=True, **kwargs):
            result = original(path, gaps, follow, **kwargs)
            return SimpleNamespace(st_mode=result.st_mode, st_uid=self.owners.get(str(path), 0)) if result else None
        self.enterContext(patch.object(host, '_metadata', side_effect=metadata))

    def file(self, name, contents='fixture', mode=0o600):
        path = self.base / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
        path.chmod(mode)
        return path

    def writable(self, *paths):
        self.access.side_effect = lambda path, mode: str(path) in set(map(str, paths)) and bool(mode & os.W_OK)

    def account(self, uid, home):
        return SimpleNamespace(pw_uid=uid, pw_dir=str(home))

    def test_root_suppression_all_checks(self):
        self.uid.return_value = 0
        for name, check in [('services', lambda: host.inspect_services(properties={})),
                            ('root-processes', host.inspect_root_processes),
                            ('credentials', host.inspect_credentials), ('agent-sockets', host.inspect_agent_sockets)]:
            result = check()
            self.assertEqual(result['incomplete_ids'], ['extra-' + name])
            self.assertFalse(evidence(result, 'extra-' + name))
        self.access.assert_not_called()

    def test_actual_access_over_mode_bits_and_no_root_ownership_inference(self):
        path = self.file('program', mode=0o777)
        result = host.inspect_services(properties={'x.service': native(User='other', ExecStart=executable(path))})
        self.assertEqual(result['findings'], [])  # root-owned doesn't establish service UID
        result = host.inspect_services(properties={'x.service': native(ExecStart=executable(path))})
        self.assertEqual(result['findings'], [])  # ACL-like access denial despite mode
        path.chmod(0o400)
        self.writable(path)
        result = host.inspect_services(properties={'x.service': native(User='0', ExecStart=executable(path))})
        self.assertIn(str(path), evidence(result, 'extra-services'))  # ACL-like grant

    def test_active_effective_config_all_exec_paths_and_spaces(self):
        program = self.file('bin/my program')
        fragment = self.file('unit.service')
        dropin = self.file('drop ins/override.conf')
        values = dict(ExecStart=executable(program), FragmentPath=str(fragment),
                      DropInPaths=str(dropin).replace(' ', r'\x20'))
        for key in host.EXEC[1:]:
            values[key] = executable(str(program).replace(' ', r'\x20'))
        self.writable(program, fragment, dropin)
        result = host.inspect_services(properties={'x.service': native(**values)})
        self.assertNotIn('incomplete_ids', result)
        self.assertEqual(set(evidence(result, 'extra-services')), {str(program), str(fragment), str(dropin)})
        # Missing User is intentionally root; never infer UID from file owner.
        text = native(**values).replace('User=\n', '', 1)
        self.assertIn(str(program), evidence(host.inspect_services(properties={'x.service': text}), 'extra-services'))

    def test_nonroot_dynamic_and_chroot_service_scoping(self):
        program = self.file('program')
        self.writable(program)
        properties = {name + '.service': native(ExecStart=executable(program), **values) for name, values in
                      [('other', {'User': '1002'}), ('dynamic', {'DynamicUser': 'yes'}),
                       ('chroot', {'RootDirectory': '/isolated'}), ('image', {'RootImage': '/disk.img'})]}
        result = host.inspect_services(properties=properties)
        self.assertFalse(evidence(result, 'extra-services'))
        self.assertEqual(result['incomplete_ids'], ['extra-services'])
        details = str(result['findings'])
        self.assertIn('chroot.service', details)
        self.assertNotIn('other.service', details)
        self.assertNotIn('dynamic.service', details)

    def test_unknown_exec_and_property_syntax_not_clean(self):
        for text in (native(ExecStart='/bin/foo --arg'), native(ExecStart='{ path=/bin/foo ; argv[]={} ; }'),
                     native(ExecStart=executable(r'/bin/bad\q')), native(ExecStart=executable('relative')),
                     native(DynamicUser='maybe'), native() + '\nUser=root',
                     native().replace('RootImage=\n', ''), 'User='):
            with self.subTest(text=text):
                result = host.inspect_services(properties={'x.service': text})
                self.assertEqual(result['incomplete_ids'], ['extra-services'])

    def test_sticky_parent_respects_entry_and_directory_ownership(self):
        path = self.file('sticky/root-program')
        parent = path.parent
        parent.chmod(0o1777)
        self.writable(parent)
        for owner, directory_owner, expected in [(0, 0, False), (1001, 0, True), (0, 1001, True)]:
            self.owners[str(path)], self.owners[str(parent)] = owner, directory_owner
            result = host.inspect_services(properties={'x.service': native(ExecStart=executable(path))})
            self.assertEqual(str(parent) in evidence(result, 'extra-services'), expected)
        self.owners[str(path)] = self.owners[str(parent)] = 0
        parent.chmod(0o0777)
        self.assertIn(str(parent), evidence(host.inspect_services(properties={'x.service': native(ExecStart=executable(path))}), 'extra-services'))
        self.access.side_effect = lambda path, mode: str(path) == str(parent) and mode == os.W_OK
        self.assertEqual(host.inspect_services(properties={'x.service': native(ExecStart=executable(path))})['findings'], [])

    def test_symlink_dotdot_kernel_semantics_and_target_parents(self):
        target = self.file('b/secret')
        (self.base / 'b/inner').mkdir()
        (self.base / 'a').mkdir()
        (self.base / 'a/link').symlink_to(self.base / 'b/inner', target_is_directory=True)
        path = str(self.base / 'a/link') + '/../secret'
        self.assertEqual(os.path.realpath(path), str(target))
        self.writable(target.parent)
        result = host.inspect_services(properties={'x.service': native(ExecStart=executable(path))})
        self.assertIn(str(target.parent), evidence(result, 'extra-services'))
        self.assertNotIn('incomplete_ids', result)

    def test_no_manager_and_trusted_binary_gap(self):
        runner = lambda argv: self.fail('No manager must not invoke runner')
        self.assertEqual(host.inspect_services(manager=str(self.base / 'absent'), runner=runner)['findings'], [])
        with patch.object(host, '_trusted_systemctl', return_value=None):
            result = host.inspect_services(manager=str(self.base), runner=runner)
        self.assertEqual(result['incomplete_ids'], ['extra-services'])

    def test_runner_readonly_commands_errors_limits_and_incremental_show(self):
        program = self.file('program')
        self.writable(program)
        calls = []

        def runner(argv):
            calls.append(argv)
            if argv[1] == 'list-units':
                return 'ok.service loaded active running OK\nbad.service loaded active exited Bad\n'
            if argv[-1] == 'bad.service':
                raise subprocess.TimeoutExpired(argv, 2)
            return native(ExecStart=executable(program))
        with patch.object(host, '_trusted_systemctl', return_value='/usr/bin/systemctl'):
            result = host.inspect_services(manager=str(self.base), runner=runner)
            self.assertIn(str(program), evidence(result, 'extra-services'))
            self.assertEqual(result['incomplete_ids'], ['extra-services'])
            self.assertIn('--state=active', calls[0])
            self.assertIn('--no-pager', calls[0])
            self.assertEqual([c[1] for c in calls], ['list-units', 'show', 'show'])
            self.assertIn('ExecStopPost', calls[1][3])
            for failure in (TimeoutError(), OSError(), ValueError()):
                with self.subTest(failure=failure):
                    with patch.object(host, '_trusted_systemctl', return_value='/usr/bin/systemctl'):
                        result = host.inspect_services(manager=str(self.base), runner=lambda argv: (_ for _ in ()).throw(failure))
                    self.assertEqual(result['incomplete_ids'], ['extra-services'])
            result = host.inspect_services(manager=str(self.base), runner=runner, max_services=1)
            self.assertIn('incomplete_ids', result)
            result = host.inspect_services(manager=str(self.base), runner=lambda argv: 'x' * (host.OUTPUT_LIMIT + 1))
            self.assertIn('incomplete_ids', result)

    def test_systemctl_pipe_runner_limits_and_kills_without_executing(self):
        for chunks, clock, error in (([b'fixture', b''], None, None),
                                      ([b'x' * 8192] * 16 + [b'x'], None, ValueError),
                                      ([], [0, 3], TimeoutError)):
            process, selector = MagicMock(), MagicMock()
            process.__enter__.return_value = process
            process.returncode = 0
            process.poll.return_value = None if error else 0
            selector.__enter__.return_value = selector
            key = SimpleNamespace(fd=123, fileobj=process.stdout)
            registered = {123: key}
            selector.get_map.side_effect = lambda: registered
            selector.select.side_effect = lambda timeout: [(key, 1)]
            selector.unregister.side_effect = lambda file: registered.clear()
            with patch.object(host.subprocess, 'Popen', return_value=process) as popen, \
                    patch.object(host.selectors, 'DefaultSelector', return_value=selector), \
                    patch.object(host.os, 'read', side_effect=chunks), \
                    patch.object(host.time, 'monotonic', side_effect=clock) if clock else patch.object(host.time, 'monotonic', return_value=0):
                if error:
                    with self.assertRaises(error):
                        host._run(['/fixture/systemctl', 'show'])
                    process.kill.assert_called_once_with()
                else:
                    self.assertEqual(host._run(['/fixture/systemctl', 'show']), 'fixture')
                    process.kill.assert_not_called()
                self.assertNotIn('shell', popen.call_args.kwargs)
                self.assertEqual(popen.call_args.kwargs['stdin'], subprocess.DEVNULL)
                self.assertNotIn('LD_PRELOAD', popen.call_args.kwargs['env'])

    def test_systemctl_trust_rejects_nonroot_or_writable_native_binary(self):
        self.access.side_effect = lambda path, mode: mode == os.X_OK
        for owner, mode, expected in ((0, 0o755, '/usr/bin/systemctl'), (1002, 0o755, None), (0, 0o775, None)):
            def metadata(path):
                return SimpleNamespace(st_uid=owner, st_mode=(stat.S_IFREG if str(path).endswith('systemctl') else stat.S_IFDIR) | mode)
            with patch.object(host.os.path, 'realpath', side_effect=lambda path: path), \
                    patch.object(host.os, 'stat', side_effect=metadata):
                self.assertEqual(host._trusted_systemctl(), expected)

    def test_native_multiple_paths_trailing_spaces_utf8_and_ambiguous_dropins(self):
        first = self.file('first ')
        second = self.file('second')
        self.writable(first, second)
        result = host.inspect_services(properties={'x.service': native(ExecStart=executable(first) + ' ' + executable(second))})
        self.assertEqual(set(evidence(result, 'extra-services')), {str(first), str(second)})
        self.assertEqual(host._unescape(r'/file\xc3\xa9'), '/fileé')
        result = host.inspect_services(properties={'x.service': native(DropInPaths=str(first) + 'broken')})
        self.assertEqual(evidence(result, 'extra-services'), [])
        self.assertIn('incomplete_ids', result)

    def process(self, pid, effective, target=None, real=1002):
        status = self.file('proc/%s/status' % pid, 'Name:\tfixture\nUid:\t%d\t%d\t%d\t%d\n' % (real, effective, effective, effective))
        if target:
            status.with_name('exe').symlink_to(target)
        return status.parent

    def test_effective_root_processes_deduplicated_no_arguments(self):
        target = self.file('root-binary')
        other = self.file('other-binary')
        self.process(1, 0, target)
        self.process(2, 0, target)
        self.process(3, 1002, other, real=0)
        self.writable(target, other)
        with patch.object(host, 'read_regular', wraps=host.read_regular) as reader:
            result = host.inspect_root_processes(proc=str(self.base / 'proc'))
        self.assertEqual(evidence(result, 'extra-root-processes'), [str(target)])
        self.assertNotIn('incomplete_ids', result)
        self.assertTrue(all(str(c.args[0]).endswith('/status') for c in reader.call_args_list))
        self.assertNotIn('/proc/1', str(result['findings']))

    def test_process_hidepid_and_exe_denial_grouped_without_pids(self):
        target = self.file('root-binary')
        for pid in (10, 11, 12):
            self.process(pid, 0, target)
        original = os.readlink
        with patch.object(host.os, 'readlink', side_effect=lambda path, **kw: (_ for _ in ()).throw(PermissionError()) if str(path).endswith('/exe') else original(path, **kw)):
            result = host.inspect_root_processes(proc=str(self.base / 'proc'))
        self.assertEqual(result['incomplete_ids'], ['extra-root-processes'])
        self.assertEqual(len(result['findings'][0]['context'][0]['evidence']), 1)
        self.assertNotIn('/10/', str(result))
        with patch.object(host, 'read_regular', side_effect=PermissionError()):
            self.assertIn('incomplete_ids', host.inspect_root_processes(proc=str(self.base / 'proc')))

    def test_process_vanished_pid_kernel_thread_bounds_and_nonregular_status(self):
        self.process(1, 0)
        (self.base / 'proc/1/status').write_text('Uid:\t0\t0\t0\t0\nKthread:\t1\n')
        (self.base / 'proc/2').mkdir()
        original = host.read_regular

        def read(path):
            if str(path).endswith('/2/status'):
                (self.base / 'proc/2').rmdir()
                raise FileNotFoundError()
            return original(path)
        with patch.object(host, 'read_regular', side_effect=read):
            self.assertEqual(host.inspect_root_processes(proc=str(self.base / 'proc'))['findings'], [])
        self.assertIn('incomplete_ids', host.inspect_root_processes(proc=str(self.base / 'proc'), max_entries=0))
        os.mkfifo(self.base / 'proc/1/status-fifo')
        with self.assertRaises(OSError):
            host.read_regular(self.base / 'proc/1/status-fifo')
        (self.base / 'proc/1/status').write_text('x' * (1024 * 1024 + 1))
        self.assertIn('incomplete_ids', host.inspect_root_processes(proc=str(self.base / 'proc')))

    def test_credentials_metadata_only_cross_account_and_private_key_filter(self):
        secret = 'DO_NOT_DISCLOSE_ROOT_SECRET'
        key = self.file('other/.ssh/id_ed25519', secret)
        public = self.file('other/.ssh/id_ed25519.pub', secret)
        self.file('other/.ssh/authorized_keys', secret)
        self.file('other/.ssh/known_hosts', secret)
        aws = self.file('other/.aws/credentials', secret)
        root_key = self.file('host_key', secret)
        own = self.file('own/.ssh/id_rsa', secret)
        self.owners[str(own)] = 1001
        accounts = [self.account(0, key.parents[1]), self.account(1001, own.parents[1])]
        self.access.side_effect = lambda path, mode: mode == os.R_OK
        with patch.object(host, 'read_regular', side_effect=AssertionError('Never read credentials')):
            result = host.inspect_credentials(paths=[root_key, self.base / 'absent'], accounts=accounts, environ={}, tmp=str(self.base))
        self.assertEqual(set(evidence(result, 'extra-credentials')), {str(root_key), str(key), str(aws)})
        self.assertNotIn(str(public), str(result))
        self.assertNotIn(secret, str(result))
        self.assertNotIn('incomplete_ids', result)

    def test_credentials_own_injected_projected_tokens_and_symlink_targets(self):
        own = self.file('own-token', 'SECRET')
        cross = self.file('other-token', 'SECRET')
        link = self.base / 'token-link'
        link.symlink_to(cross)
        self.owners[str(own)] = 1001
        self.access.side_effect = lambda path, mode: mode == os.R_OK
        result = host.inspect_credentials(paths=[], accounts=[], tmp=str(self.base),
                                         environ=dict(zip(host.TOKEN_VARS, [str(own), str(link), '/run/secrets/kubernetes.io/serviceaccount/token'])))
        self.assertEqual(evidence(result, 'extra-credentials'), [str(link)])
        self.assertNotIn('SECRET', str(result))

    def test_credentials_access_errors_limits_no_directory_links_and_caches(self):
        key = self.file('other/.ssh/id_rsa')
        cache = self.file('krb5cc_1002')
        accounts = [self.account(1002, key.parents[1])]
        self.access.side_effect = lambda path, mode: mode == os.R_OK
        self.assertIn(str(cache), evidence(host.inspect_credentials(paths=[], accounts=accounts, environ={}, tmp=str(self.base)), 'extra-credentials'))
        for bounds in ({'max_accounts': 0}, {'max_entries': 0}):
            self.assertIn('incomplete_ids', host.inspect_credentials(paths=[], accounts=accounts, environ={}, tmp=str(self.base), **bounds))
        (self.base / 'alias').symlink_to(key.parents[1], target_is_directory=True)
        result = host.inspect_credentials(paths=[], accounts=[self.account(1002, self.base / 'alias')], environ={}, tmp=str(self.base / 'missing'))
        self.assertEqual(result['findings'], [])
        real_stat = os.stat
        with patch.object(host.os, 'stat', side_effect=lambda path, **kw: (_ for _ in ()).throw(PermissionError()) if str(path) == str(key) else real_stat(path, **kw)):
            self.assertIn('incomplete_ids', host.inspect_credentials(paths=[key], accounts=[], environ={}))

    def test_other_account_agent_sockets_metadata_only_and_bounds(self):
        directory = self.base / 'ssh-fixture'
        directory.mkdir()
        agent = directory / 'agent.1'
        own = directory / 'agent.2'
        for path in (agent, own):
            connection = socket.socket(socket.AF_UNIX)
            self.addCleanup(connection.close)
            connection.bind(str(path))
        self.owners[str(own)] = 1001
        self.writable(agent, own)
        (self.base / 'ssh-link').symlink_to(directory, target_is_directory=True)
        with patch.object(host.socket if hasattr(host, 'socket') else socket, 'socket', side_effect=AssertionError('No connections')):
            result = host.inspect_agent_sockets(accounts=[], tmp=str(self.base), run=str(self.base / 'run'))
        self.assertEqual(evidence(result, 'extra-agent-sockets'), [str(agent)])
        self.assertNotIn('incomplete_ids', result)
        self.assertIn('incomplete_ids', host.inspect_agent_sockets(accounts=[], tmp=str(self.base), max_entries=0))

    def test_per_account_gpg_gcr_agents_and_directory_links(self):
        home = self.base / 'other'
        sockets = [home / '.gnupg/S.gpg-agent', self.base / 'run/1002/gcr/ssh', self.base / 'run/1002/gnupg/S.gpg-agent.extra']
        for path in sockets:
            path.parent.mkdir(parents=True, exist_ok=True)
            connection = socket.socket(socket.AF_UNIX)
            self.addCleanup(connection.close)
            connection.bind(str(path))
        self.writable(*sockets)
        result = host.inspect_agent_sockets(accounts=[self.account(1002, home)], tmp=str(self.base / 'absent'), run=str(self.base / 'run'))
        self.assertEqual(set(evidence(result, 'extra-agent-sockets')), set(map(str, sockets)))
        sockets[0].with_name('S.gpg-agent.link').symlink_to(sockets[0])
        result = host.inspect_agent_sockets(accounts=[self.account(1002, home)], tmp=str(self.base / 'absent'), run=str(self.base / 'run'))
        self.assertNotIn(str(sockets[0]) + '.link', evidence(result, 'extra-agent-sockets'))

    def test_scan_isolates_failures_keeps_prior_findings_and_deep_only_agents(self):
        part = host._result('services', [(str(self.base), 'candidate')])
        with patch.object(host, 'inspect_services', return_value=part), \
                patch.object(host, 'inspect_root_processes', side_effect=RuntimeError('secret exception text')), \
                patch.object(host, 'inspect_credentials', return_value=host._result('credentials')), \
                patch.object(host, 'inspect_agent_sockets', return_value=host._result('agent-sockets')) as agent:
            result = host.scan()
            self.assertTrue(evidence(result, 'extra-services'))
            self.assertEqual(result['incomplete_ids'], ['extra-root-processes'])
            self.assertNotIn('secret exception text', str(result))
            agent.assert_not_called()
            host.scan(deep=True)
            agent.assert_called_once_with()

    def test_original_access_uses_effective_ids(self):
        # The imported function retains lse_extras globals; os is the same stdlib module.
        original = host.runpy.run_path(str(host._HERE / 'lse_extras.py'))['_access']
        with patch.object(os, 'access', return_value=True) as access:
            self.assertTrue(original('/fixture', os.R_OK))
        access.assert_called_once_with('/fixture', os.R_OK, effective_ids=True)


if __name__ == '__main__':
    unittest.main()
