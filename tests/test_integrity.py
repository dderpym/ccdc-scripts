"""Offline native-format/safety fixtures; never verify or repair the real host."""
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from test_controller import load

integrity = load('discover-integrity')


class ParserTests(unittest.TestCase):
    def test_apk_upstream_reasons_relative_paths_and_unknown(self):
        result = integrity.document()
        integrity.parse_apk(result, 'U usr/bin/sudo\nM etc/shadow\nm etc/sudoers.d/\n'
                            'X usr/bin/missing tool\nx usr/lib/libc.so\nA etc/local\n'
                            'd opt/new/\nD opt/opaque/\ne etc/private\nnew format!\n', include_added=True)
        rows = {r.get('code'): r for r in result['findings'] if 'code' in r}
        self.assertEqual(set(rows), set('UMmXxAdDe'))
        self.assertEqual(rows['U']['path'], '/usr/bin/sudo')
        self.assertEqual(rows['U']['severity'], 'critical')
        self.assertEqual(rows['X']['path'], '/usr/bin/missing tool')
        self.assertEqual(rows['A']['severity'], 'review')
        self.assertEqual(rows['e']['severity'], 'warning')
        self.assertTrue(result['errors'])

    def test_normal_apk_ignores_added_files_but_keeps_security_configs(self):
        result = integrity.document()
        integrity.parse_apk(result, 'A etc/new\nd opt/new\nD opt/other\n'
                            'U etc/ssh/sshd_config\nU etc/nginx/nginx.conf\n')
        self.assertEqual(len(result['findings']), 2)
        by_path = {f['path']: f for f in result['findings']}
        self.assertEqual(by_path['/etc/ssh/sshd_config']['severity'], 'warning')
        self.assertEqual(by_path['/etc/nginx/nginx.conf']['severity'], 'review')
        self.assertEqual(result['errors'], [])

    def test_rpm_nine_flags_configuration_and_missing(self):
        result = integrity.document()
        fixture = ('SM5DLUGTP    /usr/bin/sudo\n..5....T.  c /etc/ssh/sshd_config\n'
                   '.......T.    /usr/bin/time-only\nmissing     /usr/bin/gone\n'
                   '.M.......  c /etc/shadow\n..?......    /usr/bin/unreadable\n'
                   'Unsatisfied dependencies for package example\n')
        integrity.parse_rpm(result, fixture)
        rows = {r['path']: r for r in result['findings'] if 'checks' in r}
        self.assertEqual(len(rows['/usr/bin/sudo']['checks']), 9)
        self.assertEqual(rows['/usr/bin/sudo']['severity'], 'critical')
        self.assertEqual(rows['/etc/ssh/sshd_config']['severity'], 'warning')
        self.assertEqual(rows['/usr/bin/time-only']['severity'], 'review')
        self.assertEqual(rows['/usr/bin/gone']['checks'], ['missing'])
        self.assertEqual(rows['/etc/shadow']['severity'], 'critical')
        self.assertEqual(len(result['errors']), 2)

    def test_dpkg_unsupported_flags_are_not_false_errors(self):
        result = integrity.document()
        integrity.parse_rpm(result, '??5??????   /usr/bin/tool with spaces\n'
                            '??5?????? c /etc/example\n?M???????   /usr/bin/wrong-type\n'
                            'missing   c /etc/gone (No such file or directory)\n', 'dpkg')
        self.assertEqual(result['errors'], [])
        rows = {r['path']: r for r in result['findings']}
        self.assertEqual(rows['/usr/bin/tool with spaces']['severity'], 'critical')
        self.assertEqual(rows['/etc/example']['severity'], 'review')
        self.assertEqual(rows['/usr/bin/wrong-type']['checks'], ['mode/type'])
        self.assertIn('/etc/gone', rows)

    def test_xbps_real_file_symlink_and_error_formats(self):
        result = integrity.document()
        integrity.parse_xbps(result, 'ERROR: sudo: hash mismatch for /usr/bin/sudo.\n'
                             'ERROR: shell: unexistent file /bin/missing.\n'
                             'ERROR: cfg: unexistent file /etc/example\n'
                             'ERROR: shell: broken symlink /bin/sh (target: /bin/dash)\n'
                             'WARNING: shell: modified symlink /bin/link points to /bad (shall be /good)\n'
                             "ERROR: secret: can't check `/etc/private' (Permission denied)\n"
                             'ERROR: sudo: files check FAILED.\n'
                             'ERROR: cfg: conf files check FAILED.\n'
                             'ERROR: sudo: metadata file has been modified!\n')
        rows = {r['path']: r for r in result['findings'] if r['path']}
        self.assertEqual(rows['/usr/bin/sudo']['severity'], 'critical')
        self.assertIn('/bin/missing', rows)
        self.assertIn('/etc/example', rows)
        self.assertIn('/bin/sh', rows)
        self.assertIn('/bin/link', rows)
        self.assertEqual(rows['/etc/private']['severity'], 'warning')
        self.assertEqual(len(result['errors']), 2)

    def test_stable_unique_finding_ids(self):
        result = integrity.document()
        for _ in range(2):
            integrity.parse_apk(result, 'U usr/bin/sudo\n')
        self.assertEqual(len(result['findings']), 1)
        other = integrity.document()
        integrity.parse_apk(other, 'U usr/bin/sudo\n')
        self.assertEqual(other['findings'][0]['id'], result['findings'][0]['id'])

    def test_apk_installed_acl_records_defaults_and_package_boundaries(self):
        fixture = ('P:base\nF:etc\nM:0:0:755\nR:shadow\na:0:42:640\n'
                   'R:passwd\nF:usr/bin\nR:tool\na:0:0:4755:Q1xattrs\n\n'
                   'P:next\nF:etc\nR:unrelated\na:12:13:600\n')
        rows = integrity.parse_apk_database(fixture, {'/etc', '/etc/shadow', '/etc/passwd', '/usr/bin/tool'})
        self.assertEqual(rows['/etc/shadow']['gid'], 42)
        self.assertEqual(rows['/etc/shadow']['mode'], 0o640)
        self.assertEqual(rows['/etc/passwd']['mode'], 0o644)
        self.assertEqual(rows['/usr/bin/tool']['mode'], 0o4755)
        self.assertEqual(rows['/usr/bin/tool']['package'], 'base')
        self.assertNotIn('/etc/unrelated', rows)

    def test_changed_observation_keeps_the_same_condition_identity(self):
        first, second = integrity.document(), integrity.document()
        integrity.parse_rpm(first, '.M.......    /usr/bin/sudo\n')
        integrity.parse_rpm(second, 'SM5......    /usr/bin/sudo\n')
        self.assertEqual(first['findings'][0]['id'], second['findings'][0]['id'])
        self.assertNotEqual(first['findings'][0], second['findings'][0])
        self.assertEqual(integrity.numeric('root', {'root': 1000}), 0)

    def test_numeric_rpm_and_dpkg_metadata(self):
        users, groups = {'root': 0}, {'root': 0, 'shadow': 42}
        rpm = integrity.parse_rpm_metadata('/etc/shadow\t33184\troot\tshadow\t\n'
                                           '/bin/sh\t41471\troot\troot\tdash\n',
                                           {'/etc/shadow', '/bin/sh'}, users, groups)
        self.assertEqual(rpm['/etc/shadow']['mode'], 0o640)
        self.assertEqual(rpm['/bin/sh']['type'], stat.S_IFLNK)
        self.assertEqual(rpm['/bin/sh']['symlink'], 'dash')
        dpkg = integrity.parse_overrides('root shadow 640 /etc/shadow\n'
                                        '#7 #8 600 /etc/path with spaces\n',
                                        {'/etc/shadow', '/etc/path with spaces'}, users, groups)
        self.assertEqual(dpkg['/etc/shadow']['gid'], 42)
        self.assertEqual(dpkg['/etc/path with spaces']['uid'], 7)


class MetadataTests(unittest.TestCase):
    def test_lstat_numeric_metadata_and_symlink_referent_security(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'target'
            target.write_text('not hashed')
            target.chmod(0o666)
            link = Path(tmp) / 'link'
            link.symlink_to('target')
            result = integrity.document()
            integrity.collect_metadata(result, {str(link)})
            rows = {r['path']: r for r in result['metadata']}
            self.assertEqual(rows[str(link)]['symlink'], 'target')
            self.assertEqual(rows[str(link)]['type'], stat.S_IFLNK)
            self.assertEqual(rows[str(target)]['mode'], 0o666)
            for key in ('uid', 'gid', 'mode', 'type'):
                self.assertIsInstance(rows[str(target)][key], int)
            for row in result['metadata']:
                if row.get('exists'):
                    integrity.security_checks(result, row)
            self.assertTrue(any(r['path'] == str(target) and r['severity'] == 'critical'
                                for r in result['findings']))
            self.assertFalse(any(r['path'] == str(link) and 'writable' in r['summary']
                                 for r in result['findings']))

    def test_shadow_group_read_is_legitimate_world_read_is_not(self):
        result = integrity.document()
        row = {'path': '/etc/shadow', 'uid': 0, 'gid': 42, 'mode': 0o640,
               'type': stat.S_IFREG, 'symlink': None}
        integrity.security_checks(result, row, secret=True)
        self.assertEqual(result['findings'], [])
        row['mode'] = 0o644
        integrity.security_checks(result, row, secret=True)
        self.assertEqual(result['findings'][0]['severity'], 'critical')
        self.assertNotIn('gid', result['findings'][0]['checks'])

    def test_fallback_type_policy_and_dynamic_init_content_severity(self):
        result = integrity.document()
        row = {'path': '/etc/shadow', 'uid': 0, 'gid': 42, 'mode': 0o700,
               'type': stat.S_IFDIR, 'symlink': None}
        integrity.security_checks(result, row, secret=True)
        self.assertIn('unexpected critical path type', result['findings'][0]['checks'])
        result['metadata'].append({'path': '/opt/init/daemon'})
        integrity.parse_rpm(result, '..5......    /opt/init/daemon\n')
        self.assertEqual(result['findings'][-1]['severity'], 'critical')

    def test_expected_distro_mode_owner_and_link_are_compared(self):
        result = integrity.document()
        row = {'path': '/bin/tool', 'uid': 7, 'gid': 8, 'mode': 0o755,
               'type': stat.S_IFREG, 'symlink': None}
        expected = dict(row, uid=0, gid=0, mode=0o4755, type=stat.S_IFLNK, symlink='other')
        integrity.security_checks(result, row, expected)
        self.assertEqual(result['findings'][0]['checks'], ['uid', 'gid', 'mode', 'type', 'symlink'])
        self.assertEqual(row['expected'], expected)
        self.assertEqual(result['findings'][0]['expected']['mode'], '4755')
        self.assertEqual(result['findings'][0]['observed']['mode'], '0755')

    def test_missing_referent_cycles_and_permission_failure_are_structured(self):
        with tempfile.TemporaryDirectory() as tmp:
            link = Path(tmp) / 'missing-link'
            link.symlink_to('missing')
            cycle = Path(tmp) / 'cycle'
            cycle.symlink_to('cycle')
            result = integrity.document()
            integrity.collect_metadata(result, {str(link), str(cycle)})
            self.assertTrue(any('Missing required critical path' in r['summary'] for r in result['findings']))
            self.assertTrue(any('cycle' in e for e in result['errors']))
        result = integrity.document()
        with patch.object(integrity, 'file_metadata', side_effect=PermissionError('denied')):
            integrity.collect_metadata(result, {'/etc/shadow'})
        self.assertTrue(result['errors'])

    def test_symlink_chain_is_bounded_without_unbounded_realpath(self):
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(40):
                (Path(tmp) / str(i)).symlink_to(str(i + 1))
            result = integrity.document()
            integrity.collect_metadata(result, {str(Path(tmp) / '0')})
            self.assertTrue(any('chain limit' in e for e in result['errors']))
            self.assertLess(len(result['metadata']), 40)

    def test_metadata_limit_and_fifo_read_refusal(self):
        result = integrity.document()
        with patch.object(integrity, 'MAX_METADATA', 1):
            integrity.collect_metadata(result, {'/etc/passwd', '/etc/group'})
        self.assertEqual(len(result['metadata']), 1)
        self.assertTrue(result['errors'])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'fifo'
            os.mkfifo(path)
            with self.assertRaises(ValueError):
                integrity.read_metadata(path)

    def test_active_init_and_package_executables_without_systemd(self):
        result = integrity.document()
        with patch.object(integrity, 'CRITICAL', ()), \
                patch.object(integrity.os, 'readlink', return_value='/sbin/openrc-init'), \
                patch.object(integrity.shutil, 'which', side_effect=lambda name: '/sbin/apk' if name == 'apk' else None):
            self.assertEqual(integrity.critical_paths(result), {'/sbin/openrc-init', '/sbin/apk'})


class CommandTests(unittest.TestCase):
    def test_native_commands_no_repairs_and_apk_normal_flags(self):
        for backend, helptext in (('apk', '--system --backup --check-permissions --full --details'),
                                  ('rpm', ''), ('dpkg', '')):
            with self.subTest(backend=backend):
                result = integrity.document()
                with patch.object(integrity, 'run', return_value=(helptext if backend == 'apk' else '', '', 0)) as run:
                    integrity.verify(result, backend, backend, False)
                calls = [c.args[1] for c in run.call_args_list]
                forbidden = {'fix', '--restore', '--setperms', '--setugids', '--update', '--mode', '--full', '--details'}
                self.assertFalse(any(forbidden.intersection(argv) for argv in calls))
                if backend == 'apk':
                    self.assertEqual(calls[1], ['apk', 'audit', '--system', '--check-permissions'])
                    self.assertEqual(calls[-1], ['apk', 'audit', '--backup', '--check-permissions', '/etc'])
                elif backend == 'rpm':
                    self.assertEqual(calls[-1], ['rpm', '--verify', '--all', '--noscripts'])
                else:
                    self.assertEqual(calls[-1], ['dpkg', '--verify', '--verify-format=rpm'])
                self.assertEqual(run.call_args_list[-1].args[2], 300)

    def test_apk_usage_exit_one_still_discovers_supported_flags(self):
        result = integrity.document()
        helptext = '--system --backup --full --check-permissions'
        with patch.object(integrity.subprocess, 'run', side_effect=[
                subprocess.CompletedProcess([], 1, helptext, ''),
                subprocess.CompletedProcess([], 0, 'U usr/bin/ssh\nX usr/bin/scp\n', ''),
                subprocess.CompletedProcess([], 0, '', '')]):
            integrity.verify(result, 'apk', 'apk', False)
        self.assertEqual(result['errors'], [])
        self.assertEqual({f['path'] for f in result['findings']}, {'/usr/bin/ssh', '/usr/bin/scp'})

    def test_missing_documentation_is_review_not_binary_severity(self):
        result = integrity.document()
        integrity.parse_rpm(result, 'missing /usr/share/doc/example/README\nmissing /usr/bin/scp\n', 'dpkg')
        by_path = {f['path']: f for f in result['findings']}
        self.assertEqual(by_path['/usr/share/doc/example/README']['severity'], 'review')
        self.assertEqual(by_path['/usr/bin/scp']['severity'], 'critical')

    def test_deep_apk_adds_full_scan_only_on_request(self):
        with patch.object(integrity, 'run', return_value=('--system --backup --full --check-permissions', '', 0)) as run:
            integrity.verify(integrity.document(), 'apk', 'apk', True)
        self.assertEqual(run.call_args_list[-1].args[1], ['apk', 'audit', '--full', '--check-permissions'])
        self.assertEqual(run.call_count, 4)
        self.assertFalse(any('--details' in call.args[1] for call in run.call_args_list))

    def test_option_detection_refuses_unsafe_fallback(self):
        for backend, helptext in (('apk', '--system'), ('xbps', '--all --update --mode')):
            result = integrity.document()
            with patch.object(integrity, 'run', return_value=(helptext, '', 0)) as run:
                integrity.verify(result, backend, backend, False)
            self.assertEqual(run.call_count, 1)
            self.assertTrue(result['errors'])

    def test_xbps_only_file_checks_with_private_database_root(self):
        result = integrity.document()
        prepare = Mock()
        with patch.object(integrity, 'copy_xbps_metadata') as copy, \
                patch.object(integrity, 'xbps_namespace', return_value=prepare) as namespace, \
                patch.object(integrity, 'run', side_effect=[('--checks --all', '', 0), ('', 'ERROR: pkg: hash mismatch for /usr/bin/tool.\n', 1)]) as run:
            integrity.verify(result, 'xbps', '/usr/bin/xbps-pkgdb', False)
        argv = run.call_args_list[-1].args[1]
        self.assertEqual(argv[1:], ['--rootdir', '/', '--all', '--checks', 'files'])
        namespace.assert_called_once_with(copy.call_args.args[0])
        self.assertEqual(run.call_args.kwargs['preexec_fn'], prepare)
        self.assertEqual(result['findings'][0]['path'], '/usr/bin/tool')

    def test_xbps_copy_is_not_a_host_metadata_link_and_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as host, tempfile.TemporaryDirectory() as root:
            host = Path(host)
            db = host / 'var/db/xbps'
            db.mkdir(parents=True)
            (host / 'usr').mkdir()
            (db / 'pkgdb-0.38.plist').write_text('metadata')
            (db / '.shell-files.plist').write_text('files')
            integrity.copy_xbps_metadata(root, db)
            copied = Path(root) / 'pkgdb-0.38.plist'
            self.assertFalse(copied.is_symlink())
            copied.write_text('native verifier may flush here')
            self.assertEqual((db / 'pkgdb-0.38.plist').read_text(), 'metadata')
        with tempfile.TemporaryDirectory() as host, tempfile.TemporaryDirectory() as root:
            db = Path(host) / 'var/db/xbps'
            db.mkdir(parents=True)
            (db / 'bad.plist').symlink_to('/etc/passwd')
            with self.assertRaises(OSError):
                integrity.copy_xbps_metadata(root, db)

    def test_xbps_namespace_is_private_before_database_bind_and_fails_closed(self):
        libc = Mock()
        libc.unshare.return_value = 0
        libc.mount.return_value = 0
        with patch.object(integrity.ctypes, 'CDLL', return_value=libc):
            integrity.xbps_namespace('/private/db')()
        libc.unshare.assert_called_once_with(0x20000)
        self.assertEqual(libc.mount.call_args_list[0].args, (None, b'/', None, (1 << 18) | 16384, None))
        self.assertEqual(libc.mount.call_args_list[1].args, (b'/private/db', b'/var/db/xbps', None, 4096, None))
        libc.reset_mock()
        libc.unshare.return_value = -1
        with patch.object(integrity.ctypes, 'CDLL', return_value=libc), self.assertRaises(OSError):
            integrity.xbps_namespace('/private/db')()
        libc.mount.assert_not_called()

    def test_subprocess_namespace_failure_is_structured(self):
        result = integrity.document()
        with patch.object(integrity.subprocess, 'run', side_effect=subprocess.SubprocessError('preexec failed')):
            out, err, code = integrity.run(result, ['xbps-pkgdb'], preexec_fn=Mock())
        self.assertIsNone(code)
        self.assertTrue(result['errors'])
        self.assertIn('preexec failed', result['raw'])

    def test_timeout_retains_partial_native_findings_and_raw(self):
        result = integrity.document()
        exc = subprocess.TimeoutExpired(['rpm'], 300, output=b'..5......    /usr/bin/partial\n', stderr=b'diagnostic')
        with patch.object(integrity.subprocess, 'run', side_effect=exc):
            integrity.verify(result, 'rpm', 'rpm', False)
        self.assertTrue(any(r['path'] == '/usr/bin/partial' for r in result['findings']))
        self.assertIn('diagnostic', result['raw'])
        self.assertIn('partial', result['raw'])
        self.assertTrue(result['errors'])

    def test_nonzero_missing_tool_and_locale(self):
        result = integrity.document()
        completed = subprocess.CompletedProcess([], 2, '..5......    /usr/bin/partial\n', 'db corrupt')
        with patch.object(integrity.subprocess, 'run', return_value=completed) as run:
            integrity.verify(result, 'rpm', 'rpm', False)
        self.assertEqual(run.call_args.kwargs['env']['LC_ALL'], 'C')
        self.assertTrue(any(r['path'] == '/usr/bin/partial' for r in result['findings']))
        with patch.object(integrity.subprocess, 'run', side_effect=FileNotFoundError('gone')):
            integrity.verify(result, 'dpkg', 'dpkg', False)
        self.assertTrue(result['errors'])
        self.assertIn('db corrupt', result['raw'])

    def test_discovery_selects_database_and_continues_after_verifier_failure(self):
        def verify(result, backend, binary, deep):
            if backend == 'apk':
                raise OSError('broken')
            integrity.parse_rpm(result, '..5......    /usr/bin/sudo\n')
        with patch.object(integrity.os.path, 'exists', return_value=True), \
                patch.object(integrity.shutil, 'which', side_effect=lambda n: '/usr/bin/' + n), \
                patch.object(integrity, 'critical_paths', return_value=set()), \
                patch.object(integrity, 'collect_metadata', return_value=set()), \
                patch.object(integrity, 'distro_metadata', return_value={}), \
                patch.object(integrity, 'verify', side_effect=verify) as verifier:
            result = integrity.discover()
        self.assertEqual(verifier.call_count, 4)  # Deduplicate RPM DB locations.
        self.assertTrue(any(r['path'] == '/usr/bin/sudo' for r in result['findings']))
        self.assertTrue(result['errors'])
        self.assertEqual(set(result), {'findings', 'raw', 'metadata', 'errors'})

    def test_rpm_metadata_queries_unique_owners_and_ignores_unowned_paths(self):
        result = integrity.document()
        with patch.object(integrity, 'accounts', return_value=({'root': 0}, {'root': 0})), \
                patch.object(integrity, 'run', side_effect=[
                    ('bash\nbash\nfile /opt/custom is not owned by any package\n', '', 1),
                    ('/bin/bash\t33261\troot\troot\t\n', '', 0)]) as run:
            expected = integrity.distro_metadata(result, [('rpm', 'rpm')], {'/bin/bash', '/opt/custom'})
        self.assertEqual(expected['/bin/bash']['mode'], 0o755)
        self.assertEqual(result['errors'], [])
        self.assertEqual(run.call_args.args[1][:3], ['rpm', '--query', 'bash'])
        self.assertEqual(run.call_count, 2)

    def test_verifier_mismatch_exit_is_not_a_scanner_failure(self):
        result = integrity.document()
        completed = subprocess.CompletedProcess([], 1, '..5......    /usr/bin/sudo\n', '')
        with patch.object(integrity.subprocess, 'run', return_value=completed):
            integrity.verify(result, 'rpm', 'rpm', False)
        self.assertEqual(result['errors'], [])
        self.assertEqual(result['findings'][0]['severity'], 'critical')

    def test_all_required_critical_binaries_and_active_tools_are_collected(self):
        for path in ('/bin/sh', '/bin/bash', '/bin/dash', '/bin/ash', '/usr/bin/sudo',
                     '/usr/bin/doas', '/usr/bin/su', '/usr/sbin/sshd', '/usr/bin/ssh',
                     '/usr/bin/python', '/usr/bin/python3'):
            self.assertIn(path, integrity.CRITICAL)
        for name in ('apk', 'dpkg', 'apt', 'rpm', 'dnf', 'yum', 'xbps-install',
                     'xbps-pkgdb', 'systemctl', 'systemd', 'rc-service', 'rc-status', 'sv', 'runsv'):
            self.assertIn(name, integrity.PACKAGE_TOOLS)

    def test_stdout_is_one_json_document_even_when_no_verifier(self):
        with patch.object(integrity.os.path, 'exists', return_value=False), \
                patch.object(integrity, 'critical_paths', return_value=set()), \
                patch.object(integrity, 'collect_metadata', return_value=set()), \
                patch.object(integrity, 'distro_metadata', return_value={}), \
                patch('sys.argv', ['discover-integrity']), contextlib.redirect_stdout(io.StringIO()) as out:
            integrity.main()
        result = json.loads(out.getvalue())
        self.assertTrue(result['errors'])
        self.assertEqual(result['findings'][0]['severity'], 'warning')


if __name__ == '__main__':
    unittest.main()
