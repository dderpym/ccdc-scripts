"""Fixture-only package triage tests; never query the development host."""
import errno
import importlib.util
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('package_risks', Path(__file__).resolve().parents[1] / 'scripts/package_risks.py')
risks = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(risks)
NATIVE_RUN = risks.native_run


def completed(code=0, out='', err=''):
    return subprocess.CompletedProcess([], code, out, err)


class PackageRisksTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.rows, self.comparisons, self.calls = {}, {}, []
        self.release('ubuntu', '22.04')
        self.file('etc/needrestart/needrestart.conf', '$nrconf{interpscan} = 1;\n')
        self.file('usr/share/dbus-1/system-services/org.freedesktop.PackageKit.service', '[D-BUS Service]\n')
        for name in ('sudo', 'pkexec'):
            self.file('usr/bin/' + name, 'never execute me', 0o4755)
        self.real_lstat = os.lstat

        def root_owned(path, *args, **kwargs):
            metadata = self.real_lstat(path, *args, **kwargs)
            if str(path).startswith(str(self.root)):
                fields = list(metadata)
                fields[4] = 0  # Fixture root ownership, without chown or elevated tests.
                metadata = os.stat_result(fields)
            return metadata

        self.addCleanup(patch.stopall)
        patch.object(risks.os, 'lstat', side_effect=root_owned).start()
        patch.object(risks, 'native_run', side_effect=AssertionError('real host queries forbidden')).start()

    def file(self, name, text, mode=0o644):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        path.chmod(mode)
        return path

    def release(self, vendor, version):
        self.file('etc/os-release', 'NAME="Fixture userspace"\nID=%s\nVERSION_ID="%s"\n' % (vendor, version))

    def installed(self, name, installed_version, source=None, **changes):
        record = dict(package=name, state='install ok installed', version=installed_version,
                      source=source or name, source_version=installed_version, origin='',
                      maintainer='Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>')
        record.update(changes)
        self.rows[name] = record
        return record

    def runner(self, args):
        self.calls.append(args)
        if args[0] == '/usr/bin/dpkg':
            self.assertEqual(args[1], '--compare-versions')
            self.assertEqual(args[3], 'lt')
            self.assertIn((args[2], args[4]), self.comparisons, 'unplanned fixture version comparison')
            return completed(self.comparisons[args[2], args[4]])
        self.assertIn(args[0], ('/usr/bin/dpkg-query', '/usr/bin/rpm'))
        names = risks.DEB_NAMES if args[0].endswith('dpkg-query') else risks.RPM_NAMES
        output, absent = [], []
        for name in names:
            if name not in self.rows:
                absent.append(name)
                continue
            row = self.rows[name]
            output.append('\t'.join(row[key] for key in ('package', 'state', 'version', 'source', 'source_version', 'origin', 'maintainer')))
        if args[0].endswith('dpkg-query'):
            errors = ''.join('dpkg-query: no packages found matching %s\n' % name for name in absent)
        else:
            output.extend('package %s is not installed' % name for name in absent)
            errors = ''
        return completed(int(bool(absent)), '\n'.join(output) + ('\n' if output else ''), errors)

    def scan(self, **kwargs):
        return risks.scan(root=self.root, runner=self.runner, **kwargs)

    def cves(self, result):
        return [row for row in result['findings'] if row['id'].startswith('package:')]

    def test_every_verified_boundary_uses_full_native_versions(self):
        for cve, vendors in risks.FIXES.items():
            for vendor, releases in vendors.items():
                for release, fixed in releases.items():
                    with self.subTest(cve=cve, vendor=vendor, release=release):
                        source, packages = risks.RULES[cve]
                        record = self.installed(packages[0], fixed, source=source,
                                                maintainer='Vendor <security@%s.org>' % vendor if vendor == 'debian' else 'Ubuntu <security@ubuntu.com>')
                        record['manager'] = 'dpkg'
                        self.assertTrue(risks.vendor_build(record, vendor, fixed))
                        # These orders are fixture facts from Debian version semantics;
                        # the implementation must pass the complete strings to dpkg.
                        for version, code in ((fixed, 1), ('0:' + fixed, 1),
                                              (fixed + '~rc1', 0), ('1:' + fixed + '~rc1', 1),
                                              (fixed + '+local1', 1)):
                            self.comparisons[version, fixed] = code
                            self.assertEqual(risks.version_status(version, fixed, self.runner),
                                             'affected' if code == 0 else 'installed-fixed')
                            self.assertEqual(self.calls[-1][2], version)
                        self.assertFalse(risks.vendor_build(dict(record, version='1:' + fixed, source_version='1:' + fixed), vendor, fixed))
                        self.assertFalse(risks.vendor_build(dict(record, version=fixed + '~bpo1', source_version=fixed + '~bpo1'), vendor, fixed))

    def test_required_affected_rules_and_root_scan(self):
        examples = [('CVE-2024-48990', 'needrestart', '3.5-5ubuntu2.1', '22.04'),
                    ('CVE-2026-41651', 'packagekit', '1.2.5-2ubuntu3', '22.04'),
                    ('CVE-2021-4034', 'policykit-1', '0.105-26ubuntu1.1', '20.04'),
                    ('CVE-2021-3156', 'sudo', '1.8.31-1ubuntu1.1', '20.04')]
        for cve, package, version, release in examples:
            with self.subTest(cve=cve):
                self.rows.clear()
                self.release('ubuntu', release)
                self.installed(package, version)
                fixed = risks.FIXES[cve]['ubuntu'][release]
                self.comparisons[version, fixed] = 0
                with patch.object(risks.os, 'geteuid', return_value=0):
                    result = self.scan()
                finding, = self.cves(result)
                self.assertEqual(finding['id'], 'package:' + cve)
                self.assertEqual(finding['severity'], 'warning')
                self.assertIn('not prove', finding['context']['limitation'])
                self.assertNotIn('incomplete_ids', result)

    def test_installed_fix_not_live_daemon_patch_proof(self):
        version = risks.FIXES['CVE-2026-41651']['ubuntu']['22.04']
        self.installed('packagekit', version)
        self.comparisons[version, version] = 1
        result = self.scan()
        self.assertFalse(self.cves(result))
        self.assertEqual(result['incomplete_ids'], ['package:CVE-2026-41651'])
        self.assertIn('restart/replacement unknown', result['raw'])

    def test_unverified_builds_deep_only(self):
        for changes in ({'origin': 'Acme'}, {'maintainer': 'Acme <security@notubuntu.com>'},
                        {'source': 'thirdparty'}, {'version': '3.5-5ubuntu2.2+ppa1', 'source_version': '3.5-5ubuntu2.2+ppa1'},
                        {'version': '1:3.5-5ubuntu2.2', 'source_version': '1:3.5-5ubuntu2.2'},
                        {'version': '3.5-5ubuntu2.2~bpo1', 'source_version': '3.5-5ubuntu2.2~bpo1'},
                        {'source_version': '3.5-5ubuntu2.1'}):
            with self.subTest(changes=changes):
                self.installed('needrestart', '3.5-5ubuntu2.2', **changes)
                normal, deep = self.scan(), self.scan(deep=True)
                self.assertFalse(self.cves(normal))
                self.assertEqual(normal['incomplete_ids'], ['package:CVE-2024-48990'])
                finding, = self.cves(deep)
                self.assertEqual(finding['severity'], 'review')
                self.assertIn('heuristic', finding['context']['certainty'])
        self.rows.clear()
        self.release('debian', '11')
        self.installed('needrestart', '3.5-5ubuntu2.2', maintainer='Debian <security@debian.org>')
        self.assertFalse(self.cves(self.scan()))
        self.assertIn('package:CVE-2024-48990', self.scan()['incomplete_ids'])

    def test_absent_and_residual_are_normal_but_invalid_installed_state_is_gap(self):
        self.assertEqual(self.scan()['findings'], [])
        self.installed('needrestart', '', state='deinstall ok config-files', source_version='')
        self.assertEqual(self.scan()['findings'], [])
        for changes in ({'state': 'install reinstreq installed'}, {'source_version': ''}, {'version': ''}):
            self.installed('needrestart', '3.5-5ubuntu2.1', **changes)
            self.assertEqual(self.scan()['incomplete_ids'], ['package:CVE-2024-48990'])

    def test_failure_truncation_and_unrecognized_absence_never_clear(self):
        for reply in (completed(2, ''), completed(1, '', 'database unreadable\n'), completed(),
                      completed(0, 'X' * (risks.LIMIT + 1)), completed(1, '', 'dpkg-query: no packages found matching sudo\nerror\n')):
            with self.subTest(reply=reply):
                result = risks.scan(root=self.root, runner=lambda args: reply)
                self.assertEqual(set(result['incomplete_ids']), {'package:' + c for c in risks.RULES})
                self.assertFalse(self.cves(result))
        for failure in (OSError('failed'), subprocess.TimeoutExpired('fixture', 8)):
            with patch.object(self, 'runner', side_effect=failure):
                self.assertEqual(len(self.scan()['incomplete_ids']), 4)

    def test_rule_isolation_and_single_combined_query(self):
        self.installed('needrestart', '3.5-5ubuntu2.1', source_version='')
        self.release('ubuntu', '20.04')
        self.installed('sudo', '1.8.31-1ubuntu1.1')
        self.comparisons['1.8.31-1ubuntu1.1', '1.8.31-1ubuntu1.2'] = 0
        result = self.scan()
        self.assertEqual(result['incomplete_ids'], ['package:CVE-2024-48990'])
        self.assertEqual(self.cves(result)[0]['id'], 'package:CVE-2021-3156')
        queries = [args for args in self.calls if args[0].endswith('dpkg-query')]
        self.assertEqual(len(queries), 1)
        self.assertEqual(tuple(queries[0][-6:]), risks.DEB_NAMES)
        self.assertIn('--admindir=' + str(self.root / 'var/lib/dpkg'), queries[0])

    def test_needrestart_literal_mitigation_not_includes_or_dynamic_perl(self):
        self.installed('needrestart', '3.5-5ubuntu2.1')
        self.comparisons['3.5-5ubuntu2.1', '3.5-5ubuntu2.2'] = 0
        self.file('etc/needrestart/needrestart.conf', '# static mitigation\n$nrconf{interpscan} = 0;\n')
        self.assertFalse(self.cves(self.scan()))
        self.assertNotIn('incomplete_ids', self.scan())
        for line in ('do "/other.conf";', '$nrconf{interpscan} = $value;', "$nrconf{'interpscan\"} = 0;", 'bad Perl'):
            self.file('etc/needrestart/needrestart.conf', '$nrconf{interpscan} = 0;\n' + line)
            self.assertEqual(self.scan()['incomplete_ids'], ['package:CVE-2024-48990'])
        self.file('etc/needrestart/needrestart.conf', '$nrconf{interpscan} = 0;\n')
        self.file('etc/needrestart/conf.d/99-enable.conf', '$nrconf{interpscan} = 1;\n')
        self.assertEqual(len(self.cves(self.scan())), 1)

    def test_unreadable_fifo_and_oversized_config(self):
        self.installed('needrestart', '3.5-5ubuntu2.1')
        self.comparisons['3.5-5ubuntu2.1', '3.5-5ubuntu2.2'] = 0
        path = self.root / 'etc/needrestart/needrestart.conf'
        real_read = risks.read_regular
        with patch.object(risks, 'read_regular', side_effect=lambda p: (_ for _ in ()).throw(PermissionError('fixture')) if p == path else real_read(p)):
            self.assertEqual(self.scan()['incomplete_ids'], ['package:CVE-2024-48990'])
        path.unlink()
        os.mkfifo(path)
        self.assertEqual(self.scan()['incomplete_ids'], ['package:CVE-2024-48990'])
        path.unlink()
        self.file('etc/needrestart/needrestart.conf', '#' * (risks.LIMIT + 1))
        self.assertEqual(self.scan()['incomplete_ids'], ['package:CVE-2024-48990'])

    def test_suid_privilege_metadata_and_unknown_capabilities(self):
        self.release('ubuntu', '20.04')
        for cve, package, executable, version in (('CVE-2021-4034', 'policykit-1', 'pkexec', '0.105-26ubuntu1.1'),
                                                 ('CVE-2021-3156', 'sudo', 'sudo', '1.8.31-1ubuntu1.1')):
            self.rows.clear()
            self.installed(package, version)
            self.comparisons[version, risks.FIXES[cve]['ubuntu']['20.04']] = 0
            self.assertEqual(len(self.cves(self.scan())), 1)
            path = self.root / ('usr/bin/' + executable)
            path.chmod(0o755)
            with patch.object(risks.os, 'getxattr', side_effect=OSError(errno.ENODATA, 'no caps')):
                self.assertFalse(self.cves(self.scan()))
            if executable == 'sudo':
                with patch.object(risks.os, 'getxattr', return_value=b'unknown capabilities'):
                    self.assertEqual(self.scan()['incomplete_ids'], ['package:' + cve])
            path.unlink()
            os.mkfifo(path)
            self.assertEqual(self.scan()['incomplete_ids'], ['package:' + cve])

    def test_unknown_activation_metadata_scoped(self):
        self.installed('packagekit', '1.2.5-2ubuntu3')
        self.comparisons['1.2.5-2ubuntu3', '1.2.5-2ubuntu3.1'] = 0
        (self.root / 'usr/share/dbus-1/system-services/org.freedesktop.PackageKit.service').unlink()
        self.assertEqual(self.scan()['incomplete_ids'], ['package:CVE-2026-41651'])
        self.assertFalse(self.cves(self.scan()))

    def test_unsupported_distribution_is_not_applicable_not_rpm(self):
        self.release('alpine', '3.22.7')
        result = self.scan()
        self.assertNotIn('incomplete_ids', result)
        self.assertFalse(self.cves(result))
        self.assertFalse(self.calls)

    def test_rpm_keeps_epoch_revision_source_and_vendor_without_vendor_verdict(self):
        self.release('fedora', '43')
        self.installed('PackageKit', '2:1.3.4-3.fc43', state='installed', source='PackageKit-1.3.4-3.fc43.src.rpm',
                       source_version='', origin='Fedora Project', maintainer='Fedora')
        result = self.scan(deep=True)
        finding, = self.cves(result)
        self.assertEqual(finding['context']['version'], '2:1.3.4-3.fc43')
        self.assertTrue(finding['context']['source'].endswith('.src.rpm'))
        self.assertEqual(finding['severity'], 'review')
        self.assertEqual(result['incomplete_ids'], ['package:CVE-2026-41651'])
        self.assertTrue(all(args[0] == '/usr/bin/rpm' for args in self.calls))

    def test_os_release_is_data_and_container_userspace_not_kernel(self):
        self.file('etc/os-release', 'ID=ubuntu\nVERSION_ID="$(touch /never)"\n')
        self.assertEqual(risks.os_release(self.root), ('ubuntu', '$(touch /never)'))
        self.installed('needrestart', '3.5-5ubuntu2.1')
        self.assertEqual(self.scan()['incomplete_ids'], ['package:CVE-2024-48990'])
        self.file('etc/os-release', 'ID=ubuntu\nID=debian\n')
        with self.assertRaises(ValueError):
            risks.os_release(self.root)

    def test_native_runner_is_fixed_environment_bounded_and_no_input(self):
        root_binary = os.stat_result((stat.S_IFREG | 0o755, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        with patch.object(risks.os, 'stat', return_value=root_binary), patch.object(subprocess, 'run', return_value=completed()) as run:
            NATIVE_RUN(['/usr/bin/dpkg', '--compare-versions', '1:1.0~rc1-2', 'lt', '1:1.0-2'])
            options = run.call_args.kwargs
            self.assertEqual(options['stdin'], subprocess.DEVNULL)
            self.assertEqual(options['env']['LC_ALL'], 'C')
            self.assertEqual(options['timeout'], 8)
            self.assertNotIn('shell', options)
            with self.assertRaises(ValueError):
                NATIVE_RUN(['/tmp/discovered-pkexec', '--version'])
            run.return_value = completed(0, 'X' * (risks.LIMIT + 1))
            with self.assertRaises(OSError):
                NATIVE_RUN(['/usr/bin/dpkg-query', '-W'])


if __name__ == '__main__':
    unittest.main()
