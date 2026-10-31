"""Canned running-kernel metadata only; no host scans or vulnerability probes."""
from pathlib import Path
import gzip
import os
import tempfile
import unittest
from unittest.mock import patch

from test_controller import load

kernel = load('kernel_risks.py')
NETWORK_IDS = {kernel.NFTABLES, kernel.NET_SCHED, kernel.ESP}
NETWORK_CONFIG = ('CONFIG_NF_TABLES=y\nCONFIG_NET_CLS_ACT=y\n'
                  'CONFIG_INET_ESP=y\nCONFIG_XFRM=y\n')


class KernelRiskTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def put(self, path, text):
        dest = self.root / path.lstrip('/')
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text)

    def scan(self, release, deep=False, banner='', signature='', config='CONFIG_CRYPTO_USER_API_AEAD=y\n'):
        self.put('/proc/version', banner)
        self.put('/proc/version_signature', signature)
        self.put('/boot/config-' + release, config)
        with patch.object(kernel.os, 'uname', side_effect=AssertionError('must use fixture release')):
            return kernel.inspect_kernel(deep, self.root, release)

    def ids(self, result):
        return {f['id'] for f in result['findings']}

    def test_copy_fail_stable_branch_boundaries(self):
        for series, fixed in kernel.COPY_FIXED.items():
            with self.subTest(series=series):
                prefix = '%s.%s.' % series
                self.assertIn(kernel.COPY_FAIL, self.ids(self.scan(prefix + str(fixed - 1))))
                self.assertNotIn(kernel.COPY_FAIL, self.ids(self.scan(prefix + str(fixed))))
        self.assertNotIn(kernel.COPY_FAIL, self.ids(self.scan('4.13.16')))
        self.assertNotIn(kernel.COPY_FAIL, self.ids(self.scan('7.0')))
        self.assertIn(kernel.COPY_FAIL, self.ids(self.scan('6.14.11')))

    def test_ubuntu_generic_running_build_and_hwe_not_installed_packages(self):
        for base, boundary in kernel.UBUNTU_COPY_FIXED.items():
            major, minor, _, abi, revision = boundary
            release = f'{major}.{minor}.0-{abi}-generic'
            for number, affected in ((revision - 1, True), (revision, False)):
                signature = f'Ubuntu {major}.{minor}.0-{abi}.{number}~22.04.1-generic {major}.{minor}.12'
                state = self.scan(release, signature=signature)
                self.assertEqual(kernel.COPY_FAIL in self.ids(state), affected)
                if affected:
                    row = next(f for f in state['findings'] if f['id'] == kernel.COPY_FAIL)
                    self.assertEqual(row['context']['vendor'], 'ubuntu')
                    self.assertEqual(row['severity'], 'warning')
        # Other flavours have different vendor fixes; do not apply generic tables.
        state = self.scan('6.8.0-117-azure', signature='Ubuntu 6.8.0-117.117-azure 6.8.12')
        self.assertIn(kernel.COPY_FAIL, state['incomplete_ids'])
        # A signature from a different ABI must not assert the running build is patched.
        for release in ('6.8.0-116-generic', '6.8.0-117-azure', '6.8.0-117-generic-custom'):
            state = self.scan(release, signature='Ubuntu 6.8.0-117.117-generic 6.8.12')
            self.assertNotIn(kernel.COPY_FAIL, self.ids(state))
            self.assertIn(kernel.COPY_FAIL, state['incomplete_ids'])

    def test_debian_source_revision_and_backport_boundaries(self):
        for base, fixed in kernel.DEBIAN_COPY_FIXED.items():
            a, b, patchlevel, revision = fixed
            release = f'{a}.{b}.0-20-amd64'
            for number, affected in ((revision - 1, True), (revision, False)):
                banner = f'Linux version {release} (builder) #1 SMP Debian {a}.{b}.{patchlevel}-{number}~deb11u1 (date)'
                state = self.scan(release, banner=banner)
                self.assertEqual(kernel.COPY_FAIL in self.ids(state), affected)
        # A distro userspace doesn't establish who built the kernel.
        self.put('/etc/os-release', 'ID=debian\nVERSION_CODENAME=bookworm\n')
        state = self.scan('5.15.100-host-custom')
        self.assertIn(kernel.COPY_FAIL, state['incomplete_ids'])
        self.assertNotIn(kernel.COPY_FAIL, self.ids(state))

    def test_dirty_pipe_all_fix_branches_and_vendor_unknown(self):
        for release in ('5.8.0', '5.9.16', '5.10.101', '5.15.24', '5.16.10'):
            self.assertIn(kernel.DIRTY_PIPE, self.ids(self.scan(release)), release)
        for release in ('5.7.19', '5.10.102', '5.15.25', '5.16.11', '5.17.0', '6.1.0'):
            self.assertNotIn(kernel.DIRTY_PIPE, self.ids(self.scan(release)), release)
        state = self.scan('5.15.0-25-generic', signature='Ubuntu 5.15.0-25.25-generic 5.15.12')
        self.assertNotIn(kernel.DIRTY_PIPE, self.ids(state))
        self.assertIn(kernel.DIRTY_PIPE, state['incomplete_ids'])

    def test_unknown_rc_and_local_versions_not_silently_fixed(self):
        for release in ('not-a-version', '7.0-rc6', '6.1.170-custom', '6.8.0-101-generic'):
            state = self.scan(release)
            self.assertEqual(set(state['incomplete_ids']), set(kernel.IDS))
            self.assertIn('scanner-extra-kernel', self.ids(state))
            self.assertIn(kernel.COPY_FAIL, state['incomplete_ids'])
            self.assertNotIn(kernel.COPY_FAIL, self.ids(state))
        for release in ('5.17-rc1', '5.8-rc1', '5.16.11-rc1'):
            state = self.scan(release)
            self.assertIn(kernel.DIRTY_PIPE, state['incomplete_ids'])
        state = self.scan('6.8.0-101-custom', deep=True)
        row = next(f for f in state['findings'] if f['id'] == kernel.COPY_FAIL)
        self.assertEqual(row['severity'], 'review')
        self.assertIn('backports unknown', row['summary'])
        self.assertIn(kernel.COPY_FAIL, state['incomplete_ids'])

    def test_network_upstream_fixed_boundaries(self):
        # Literal expectations keep accidental changes to the curated tables visible.
        tables = {
            kernel.NFTABLES: {'5.15': 200, '6.1': 163, '6.6': 124, '6.12': 70, '6.18': 10},
            kernel.NET_SCHED: {'5.10': 259, '5.15': 210, '6.1': 176, '6.6': 143,
                               '6.12': 94, '6.18': 36, '7.0': 13},
            kernel.ESP: {'5.10': 255, '5.15': 206, '6.1': 172, '6.6': 138,
                         '6.12': 87, '6.18': 28, '7.0': 5},
        }
        for test_id, table in tables.items():
            for prefix, fixed in table.items():
                for patchlevel, affected in ((fixed - 1, True), (fixed, False), (fixed + 1, False)):
                    with self.subTest(test_id=test_id, prefix=prefix, patchlevel=patchlevel):
                        state = self.scan(f'{prefix}.{patchlevel}', config=NETWORK_CONFIG)
                        self.assertEqual(test_id in self.ids(state), affected)
                        self.assertNotIn(test_id, state.get('incomplete_ids', []))
        for release, fixed_ids in (('6.19', {kernel.NFTABLES}), ('7.0', {kernel.NFTABLES}),
                                   ('7.1', NETWORK_IDS), ('7.2.1', NETWORK_IDS)):
            state = self.scan(release, config=NETWORK_CONFIG)
            self.assertTrue(fixed_ids.isdisjoint(self.ids(state)))
            self.assertTrue(fixed_ids.isdisjoint(state.get('incomplete_ids', [])))

    def test_nftables_backport_introductions_and_series_gaps(self):
        for prefix, intro in {'4.19': 316, '5.4': 262, '5.10': 188,
                              '5.15': 121, '6.1': 36, '6.3': 10}.items():
            for patchlevel, affected in ((intro - 1, False), (intro, True), (intro + 1, True)):
                with self.subTest(prefix=prefix, patchlevel=patchlevel):
                    state = self.scan(f'{prefix}.{patchlevel}', config=NETWORK_CONFIG)
                    self.assertEqual(kernel.NFTABLES in self.ids(state), affected)
                    self.assertNotIn(kernel.NFTABLES, state.get('incomplete_ids', []))
        for release in ('4.18.999', '4.20.1', '5.0', '5.9.999', '5.11.99', '5.16.99', '6.0.99', '6.2.99'):
            self.assertNotIn(kernel.NFTABLES, self.ids(self.scan(release, config=NETWORK_CONFIG)), release)
        for release in ('6.4', '6.5.99', '6.14.11'):
            self.assertIn(kernel.NFTABLES, self.ids(self.scan(release, config=NETWORK_CONFIG)), release)

    def test_sched_and_esp_introduction_without_exploit_specific_gates(self):
        for test_id, before, intro in ((kernel.NET_SCHED, '4.13.99', '4.14'),
                                      (kernel.ESP, '4.10.99', '4.11')):
            self.assertNotIn(test_id, self.ids(self.scan(before, config=NETWORK_CONFIG)))
            state = self.scan(intro, config=NETWORK_CONFIG + '# CONFIG_NET_CLS_FLOWER is not set\n# CONFIG_NET_ACT_GACT is not set\n')
            self.assertIn(test_id, self.ids(state))
        for esp_symbol in ('CONFIG_INET_ESP', 'CONFIG_INET6_ESP'):
            state = self.scan('6.1.100', config=esp_symbol + '=m\nCONFIG_XFRM=y\n')
            row = next(f for f in state['findings'] if f['id'] == kernel.ESP)
            self.assertEqual(row['context']['surface'], 'module-configured')
            self.assertEqual(row['context']['xfrm_surface'], 'builtin')
        for config in ('CONFIG_XFRM=y\nCONFIG_XFRM_USER=y\n',
                       'CONFIG_INET_ESP=y\n', 'CONFIG_INET6_ESP=m\n'):
            state = self.scan('6.1.100', config=config)
            self.assertNotIn(kernel.ESP, self.ids(state))
            self.assertIn(kernel.ESP, state['incomplete_ids'])

    def test_network_vendor_and_custom_never_inherit_upstream_verdicts(self):
        cases = (
            ('6.1.0-20-amd64', '', 'Linux version x #1 Debian 6.1.176-1 (date)'),
            ('5.15.0-179-generic', 'Ubuntu 5.15.0-179.189-generic 5.15.210', ''),
            ('6.1.176-custom', '', ''), ('4.10.99-custom', '', ''), ('7.1-custom', '', ''),
            ('6.1.100-custom', '', ''),
        )
        self.put('/etc/os-release', 'ID=ubuntu\nVERSION_ID=26.04\n')
        self.put('/var/lib/dpkg/status', 'Package: linux-image\nVersion: 7.1\n')
        for release, signature, banner in cases:
            with self.subTest(release=release):
                state = self.scan(release, signature=signature, banner=banner, config=NETWORK_CONFIG)
                self.assertTrue(NETWORK_IDS.issubset(state['incomplete_ids']))
                self.assertTrue(NETWORK_IDS.isdisjoint(self.ids(state)))
                deep = self.scan(release, deep=True, signature=signature, banner=banner, config=NETWORK_CONFIG)
                self.assertTrue(NETWORK_IDS.issubset(deep['incomplete_ids']))
                for row in deep['findings']:
                    if row['id'] in NETWORK_IDS:
                        self.assertEqual(row['severity'], 'review')
                        self.assertIn('unverified upstream-version', row['summary'])
                        self.assertEqual(row['context']['version_status'], 'unknown')
        for release in ('6.1.100-custom', '6.1.0-20-amd64'):
            deep = self.scan(release, deep=True, banner='Debian 6.1.100-1 (date)', config=NETWORK_CONFIG)
            self.assertTrue(NETWORK_IDS.issubset(self.ids(deep)))

    def test_network_rc_stays_unknown_even_in_deep_mode(self):
        for release in ('6.19-rc1', '6.18.10-rc1', '7.1-rc6', '7.0.13-rc1', '6.1.100-rc1', '6.4.rc1'):
            for deep in (False, True):
                state = self.scan(release, deep=deep, config=NETWORK_CONFIG)
                self.assertTrue(NETWORK_IDS.issubset(state['incomplete_ids']), release)
                self.assertTrue(NETWORK_IDS.isdisjoint(self.ids(state)), release)

    def test_network_missing_surfaces_are_scoped_incomplete(self):
        state = self.scan('6.1.100', config='CONFIG_CRYPTO_USER_API_AEAD=y\n')
        self.assertEqual(set(state['incomplete_ids']), NETWORK_IDS)
        self.assertTrue(NETWORK_IDS.isdisjoint(self.ids(state)))
        self.assertIn(kernel.COPY_FAIL, self.ids(state))
        state = self.scan('6.1.100', config='CONFIG_CRYPTO_USER_API_AEAD=y\nCONFIG_NF_TABLES=y\n')
        self.assertEqual(set(state['incomplete_ids']), {kernel.NET_SCHED, kernel.ESP})
        self.assertIn(kernel.NFTABLES, self.ids(state))
        row = next(f for f in state['findings'] if f['id'] == 'scanner-extra-kernel')
        self.assertEqual(set(row['context']['checks']), {kernel.NET_SCHED, kernel.ESP})
        deep = self.scan('6.1.100-custom', deep=True, config='')
        self.assertTrue(NETWORK_IDS.issubset(deep['incomplete_ids']))
        for row in deep['findings']:
            if row['id'] in NETWORK_IDS:
                self.assertEqual(row['context']['surface'], 'unknown')
                self.assertIn('unverified', row['summary'])
        for test_id, symbol in ((kernel.NFTABLES, 'CONFIG_NF_TABLES'),
                                (kernel.NET_SCHED, 'CONFIG_NET_CLS_ACT')):
            state = self.scan('6.1.100', config=symbol + '=m\n')
            row = next(f for f in state['findings'] if f['id'] == test_id)
            self.assertEqual(row['context']['surface'], 'module-configured')

    def test_network_compiled_out_requires_running_config_and_modules_override(self):
        disabled = ('# CONFIG_NF_TABLES is not set\n# CONFIG_NET_CLS_ACT is not set\n'
                    '# CONFIG_INET_ESP is not set\n# CONFIG_INET6_ESP is not set\n'
                    '# CONFIG_XFRM is not set\n')
        state = self.scan('6.1.100', config=disabled)
        self.assertTrue(NETWORK_IDS.issubset(state['incomplete_ids']))
        self.assertIn('indicative disk config', state['raw'])
        embedded = self.root / 'proc/config.gz'
        embedded.write_bytes(gzip.compress(disabled.encode()))
        state = self.scan('6.1.100', config=NETWORK_CONFIG)
        self.assertTrue(NETWORK_IDS.isdisjoint(state.get('incomplete_ids', [])))
        self.assertTrue(NETWORK_IDS.isdisjoint(self.ids(state)))
        # Even definitive surface evidence doesn't turn an unknown vendor build into a fix verdict.
        state = self.scan('6.1.100-custom', deep=True, config=NETWORK_CONFIG)
        self.assertTrue(NETWORK_IDS.issubset(state['incomplete_ids']))
        self.assertTrue(NETWORK_IDS.isdisjoint(self.ids(state)))
        for module in ('nf_tables', 'act_mirred', 'esp6'):
            (self.root / 'sys/module' / module).mkdir(parents=True)
        state = self.scan('6.1.100', config=disabled)
        self.assertTrue(NETWORK_IDS.issubset(self.ids(state)))
        for row in state['findings']:
            if row['id'] in NETWORK_IDS:
                self.assertEqual(row['context']['surface'], 'loaded')
        # Without loaded ESP, only one disabled address family is insufficient.
        (self.root / 'sys/module/esp6').rmdir()
        embedded.write_bytes(gzip.compress(b'# CONFIG_INET_ESP is not set\nCONFIG_XFRM=y\n'))
        self.assertIn(kernel.ESP, self.scan('6.1.100')['incomplete_ids'])
        embedded.write_bytes(gzip.compress(b'CONFIG_INET6_ESP=y\n# CONFIG_XFRM is not set\n'))
        self.assertNotIn(kernel.ESP, self.ids(self.scan('6.1.100')))

    def test_network_privilege_evidence_is_separate_and_never_suppresses(self):
        for cap, expected in (('0000000000001000', 'present'), ('0000000000000000', 'absent'),
                              ('malformed', 'unknown')):
            self.put('/proc/self/status', 'Name: fixture\nCapEff:\t' + cap + '\n')
            self.put('/proc/sys/kernel/unprivileged_userns_clone', '0\n')
            self.put('/proc/sys/user/max_user_namespaces', '0\n')
            state = self.scan('6.1.100', config=NETWORK_CONFIG + '# CONFIG_USER_NS is not set\n')
            self.assertTrue(NETWORK_IDS.issubset(self.ids(state)))
            for row in state['findings']:
                if row['id'] in NETWORK_IDS:
                    context = row['context']
                    self.assertEqual(context['version_status'], 'affected')
                    self.assertEqual(context['surface'], 'builtin')
                    self.assertEqual(context['privilege_path']['self_cap_net_admin'], expected)
                    self.assertEqual(set(context['privilege_path']['namespace_sysctls'].values()), {'0'})
                    self.assertIn('not verified', context['privilege_path']['certainty'])
        (self.root / 'proc/self/status').unlink()
        self.put('/proc/sys/user/max_user_namespaces', 'invalid\n')
        state = self.scan('6.1.100', config=NETWORK_CONFIG)
        row = next(f for f in state['findings'] if f['id'] == kernel.NFTABLES)
        self.assertEqual(row['context']['privilege_path']['self_cap_net_admin'], 'unknown')
        self.assertEqual(row['context']['privilege_path']['namespace_sysctls']['/proc/sys/user/max_user_namespaces'], 'unknown')
        self.assertTrue(NETWORK_IDS.isdisjoint(state.get('incomplete_ids', [])))
        (self.root / 'proc/config.gz').write_bytes(gzip.compress(
            (NETWORK_CONFIG + '# CONFIG_USER_NS is not set\n').encode()))
        for module in ('esp4', 'esp6'):
            (self.root / 'sys/module' / module).mkdir(parents=True)
            state = self.scan('6.1.100', config='')
            self.assertTrue(NETWORK_IDS.issubset(self.ids(state)))
            row = next(f for f in state['findings'] if f['id'] == kernel.ESP)
            self.assertEqual(row['context']['surface'], 'loaded')
            self.assertEqual(row['context']['privilege_path']['user_ns_config'], 'disabled')
            (self.root / 'sys/module' / module).rmdir()

    def test_disabled_api_loaded_module_and_unknown_exposure(self):
        disabled = '# CONFIG_CRYPTO_USER_API_AEAD is not set\n'
        # An on-disk config is not definitive evidence about the running kernel.
        self.assertIn(kernel.COPY_FAIL, self.scan('6.1.100', config=disabled)['incomplete_ids'])
        self.put('/proc/config.gz', '')
        (self.root / 'proc/config.gz').write_bytes(gzip.compress(disabled.encode()))
        self.assertNotIn(kernel.COPY_FAIL, self.ids(self.scan('6.1.100', config=disabled)))
        (self.root / 'proc/config.gz').unlink()
        self.assertIn(kernel.COPY_FAIL, self.scan('6.1.100', config='')['incomplete_ids'])
        # Loaded code wins over an inconsistent config or a future-load blacklist.
        (self.root / 'proc/config.gz').write_bytes(gzip.compress(disabled.encode()))
        (self.root / 'sys/module/algif_aead').mkdir(parents=True)
        self.put('/etc/modprobe.d/block.conf', 'install algif_aead /bin/false\n')
        state = self.scan('6.1.100', config=disabled)
        self.assertIn(kernel.COPY_FAIL, self.ids(state))
        self.assertIn('loaded', state['raw'])

    def test_module_config_does_not_claim_reachability_or_mitigation(self):
        self.put('/etc/modprobe.d/block.conf', 'blacklist algif_aead\n')
        state = self.scan('6.1.100', config='CONFIG_CRYPTO_USER_API_AEAD=m\n')
        row = next(f for f in state['findings'] if f['id'] == kernel.COPY_FAIL)
        self.assertEqual(row['context']['surface'], 'module-configured')
        self.assertIn('not proof', row['context']['certainty'])
        self.assertIn('autoload policy', state['raw'])

    def test_bounded_reads_gzip_missing_config_fifo_and_root_scan(self):
        self.put('/proc/version', '')
        self.put('/proc/config.gz', '')
        (self.root / 'proc/config.gz').write_bytes(gzip.compress(b'CONFIG_CRYPTO_USER_API_AEAD=y\n'))
        with patch.object(kernel.os, 'geteuid', return_value=0):
            state = kernel.inspect_kernel(root=self.root, release='6.1.100')
        self.assertIn(kernel.COPY_FAIL, self.ids(state))
        fifo = self.root / 'fifo'
        os.mkfifo(fifo)
        with self.assertRaisesRegex(OSError, 'not a regular'):
            kernel.read_regular(fifo)
        (self.root / 'large').write_bytes(b'x' * (kernel.LIMIT + 1))
        with self.assertRaisesRegex(OSError, 'limit exceeded'):
            kernel.read_regular(self.root / 'large')
        (self.root / 'proc/config.gz').write_bytes(b'not-gzip')
        state = kernel.inspect_kernel(root=self.root, release='6.1.100')
        self.assertIn(kernel.COPY_FAIL, state['incomplete_ids'])
        self.assertIn('config.gz', state['raw'])
        # The actual running config must win over a stale disk config.
        (self.root / 'proc/config.gz').write_bytes(gzip.compress(b'CONFIG_CRYPTO_USER_API_AEAD=y\n'))
        self.put('/boot/config-6.1.100', '# CONFIG_CRYPTO_USER_API_AEAD is not set\n')
        self.assertIn(kernel.COPY_FAIL, self.ids(kernel.inspect_kernel(root=self.root, release='6.1.100')))

    def test_malformed_compressed_payload_input_budget_and_huge_numbers(self):
        self.put('/proc/version', 'Debian 6.1.170-' + '9' * 5000 + ' (date)')
        self.put('/proc/config.gz', '')
        compressed = self.root / 'proc/config.gz'
        # Valid gzip framing followed by an invalid DEFLATE block (zlib.error).
        compressed.write_bytes(bytes.fromhex('1f8b0800000000000003') + b'\xff' * 20)
        state = kernel.inspect_kernel(root=self.root, release='6.1.0-20-amd64')
        self.assertIn(kernel.COPY_FAIL, state['incomplete_ids'])
        self.assertIn('config.gz', state['raw'])
        self.assertIsNone(kernel.version('9' * 5000 + '.1.1'))
        # Many empty members can have huge compressed input and zero output.
        with patch.object(kernel, 'LIMIT', 100):
            compressed.write_bytes(gzip.compress(b'') * 20)
            with self.assertRaisesRegex(OSError, 'input read limit'):
                kernel.read_regular(compressed, compressed=True)
            compressed.write_bytes(gzip.compress(b'x' * 101))
            with self.assertRaisesRegex(OSError, 'read limit'):
                kernel.read_regular(compressed, compressed=True)

    def test_repeat_is_stable_and_no_host_actions(self):
        first = self.scan('6.1.100')
        second = self.scan('6.1.100')
        self.assertEqual(first, second)
        source = Path(kernel.__file__).read_text()
        for prohibited in ('subprocess', 'socket.socket', 'os.splice', 'ctypes', 'eval(', 'exec('):
            self.assertNotIn(prohibited, source)


if __name__ == '__main__':
    unittest.main()


class UsernsFindingTests(unittest.TestCase):
    P = '/proc/sys/kernel/unprivileged_userns_clone'
    M = '/proc/sys/user/max_user_namespaces'

    def test_enabled_sysctls_produce_a_sysctl_fix(self):
        row = kernel.userns_finding({self.P: '1', self.M: '15000'})
        fix, = row['fixes']
        self.assertEqual(fix['settings'], {'kernel.unprivileged_userns_clone': '0', 'user.max_user_namespaces': '0'})
        self.assertEqual(fix['was']['user.max_user_namespaces'], '15000')

    def test_only_enabled_knobs_are_listed_and_disabled_or_unknown_is_clean(self):
        row = kernel.userns_finding({self.P: '0', self.M: '15000'})
        self.assertEqual(set(row['fixes'][0]['settings']), {'user.max_user_namespaces'})
        self.assertIsNone(kernel.userns_finding({self.P: '0', self.M: '0'}))
        self.assertIsNone(kernel.userns_finding({self.P: 'unknown', self.M: 'unknown'}))
