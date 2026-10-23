import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from test_controller import load

ssh = load('apply-ssh')
discovery = load('discover-ssh')
POLICY = {'permitrootlogin': 'no', 'passwordauthentication': 'no',
          'kbdinteractiveauthentication': 'no', 'pubkeyauthentication': 'yes'}
CONTEXT = 'user=oski,host=192.0.2.1,addr=192.0.2.1,laddr=192.0.2.2,lport=22'
ALPINE = '''#!/sbin/openrc-run
command="${SSHD_BINARY:-"/usr/sbin/sshd"}"
command_args="${command_args:-${SSHD_OPTS:-}}"
checkconfig() {
    command_args="$command_args -f $cfgfile"
}
update_command() {
    command="${SSHD_BINARY:-"/usr/sbin/sshd.pam"}"
}
'''


class SSHTests(unittest.TestCase):
    def test_owned_layer_removes_controlled_directives_and_has_no_include_dependency(self):
        original = ('Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\n'
                    '  pUbKeYaUtHeNtIcAtIoN=no # manual change\n'
                    'Match User root\n  PermitRootLogin yes\n'
                    '  ChallengeResponseAuthentication yes\nAllowUsers oski\n')
        managed = ssh.policy_config(original, POLICY)
        self.assertNotIn('PermitRootLogin yes', managed)
        self.assertNotIn('PasswordAuthentication yes', managed)
        self.assertNotIn('pUbKeYaUtHeNtIcAtIoN', managed)
        self.assertNotIn('ChallengeResponseAuthentication yes', managed)
        self.assertTrue(managed.endswith('Port 22\nMatch User root\nAllowUsers oski\n'))
        self.assertIn('ChallengeResponseAuthentication no', managed)
        self.assertNotIn('Include', managed)
        self.assertEqual(ssh.policy_config(managed, POLICY), managed)
        with self.assertRaises(RuntimeError):
            ssh.policy_config(original + ssh.BEGIN, POLICY)

    def test_conflicting_match_and_conditional_include_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'sshd_config'
            for text in ('Match User root\nPermitRootLogin yes\n', 'Match all\nInclude /some/file\n'):
                config.write_text(text)
                with self.assertRaises(RuntimeError):
                    ssh.inspect(str(config), POLICY)

    def test_stock_alpine_openrc_nested_defaults_and_diagnostic_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            conf = Path(directory) / 'sshd'
            conf.write_text('# default options\n')
            with patch.object(ssh, 'daemon', return_value='/usr/sbin/sshd'):
                self.assertEqual(ssh.openrc_options(ALPINE, str(conf)), ['/usr/sbin/sshd'])
                conf.write_text('SSHD_OPTS="-D"\n')
                self.assertEqual(ssh.openrc_options(ALPINE, str(conf)), ['/usr/sbin/sshd', '-D'])
                conf.write_text('cfgfile="/tmp/other"\n')
                with self.assertRaises(RuntimeError):
                    ssh.openrc_options(ALPINE, str(conf))

    def test_rhel_crypto_policy_options_allowed_but_auth_overrides_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            conf = Path(directory) / 'opensshserver.config'
            conf.write_text('CRYPTO_POLICY="-oCiphers=aes256-gcm@openssh.com -oMACs=hmac-sha2-256"\n')
            with patch.object(ssh, 'daemon', return_value='/usr/sbin/sshd'):
                args = ssh.expand_args('/usr/sbin/sshd -D $CRYPTO_POLICY', '', [str(conf)])
                self.assertIn('-oMACs=hmac-sha2-256', args)
                for bad in ('-oPermitRootLogin=yes', '-f /tmp/config', '-p 2222'):
                    with self.assertRaises(RuntimeError):
                        ssh.expand_args('/usr/sbin/sshd ' + bad, '', [])

    def test_systemd_socket_activated_authentication_only_reload(self):
        output = ('ActiveState=active\nId=ssh.service\n'
                  'ExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D ; }\n'
                  'TriggeredBy=ssh.socket\n')
        with patch.object(ssh.shutil, 'which', return_value='/bin/systemctl'), \
                patch.object(ssh.os.path, 'isdir', return_value=True), \
                patch.object(ssh, 'daemon', return_value='/usr/sbin/sshd'), \
                patch.object(ssh, 'run', return_value=subprocess.CompletedProcess([], 0, output, '')):
            name, reload, status = ssh.service()
        self.assertEqual(name, 'ssh.service')
        self.assertEqual(reload, ['/bin/systemctl', 'reload', 'ssh.service'])
        self.assertEqual(status[-1], 'ssh.service')

    def test_openrc_and_runit_selection_do_not_require_systemd(self):
        def tools(name):
            return {'systemctl': '/bin/systemctl', 'rc-service': '/sbin/rc-service', 'sv': '/usr/bin/sv'}.get(name)
        def rc_run(argv, check=True):
            return subprocess.CompletedProcess(argv, 0 if argv[1] == 'sshd' else 1, '', '')
        with patch.object(ssh.shutil, 'which', side_effect=tools), \
                patch.object(ssh.os.path, 'isdir', return_value=False), \
                patch.object(ssh.os.path, 'exists', side_effect=lambda path: path == '/run/openrc'), \
                patch.object(ssh.Path, 'read_text', return_value=ALPINE), \
                patch.object(ssh, 'daemon', return_value='/usr/sbin/sshd'), \
                patch.object(ssh, 'run', side_effect=rc_run):
            self.assertEqual(ssh.service()[1], ['/sbin/rc-service', 'sshd', 'reload'])
        void = '#!/bin/sh\nexec 2>&1\n[ -r conf ] && . ./conf\nexec /usr/bin/sshd -D $OPTS\n'
        with patch.object(ssh.shutil, 'which', side_effect=lambda name: '/usr/bin/sv' if name == 'sv' else None), \
                patch.object(ssh.os.path, 'exists', side_effect=lambda path: path == '/var/service/sshd'), \
                patch.object(ssh.Path, 'read_text', return_value=void), \
                patch.object(ssh, 'daemon', return_value='/usr/bin/sshd'), \
                patch.object(ssh, 'run', return_value=subprocess.CompletedProcess([], 0, 'run: sshd: (pid 42) 1s', '')):
            self.assertEqual(ssh.service()[1], ['/usr/bin/sv', 'hup', '/var/service/sshd'])

    def test_void_literal_conf_expansion(self):
        with tempfile.TemporaryDirectory() as directory:
            conf = Path(directory) / 'conf'
            conf.write_text('OPTS="-e"\n')
            with patch.object(ssh, 'daemon', return_value='/usr/bin/sshd'):
                ssh.check_shell_options(str(conf))
                self.assertEqual(ssh.expand_args('/usr/bin/sshd -D $OPTS', '', [str(conf)]),
                                 ['/usr/bin/sshd', '-D', '-e'])
            conf.write_text('OPTS="$(touch /tmp/bad)"\n')
            with self.assertRaises(RuntimeError):
                ssh.check_shell_options(str(conf))

    def test_effective_output_keeps_repeated_ports_and_all_access_directives(self):
        result = discovery.effective('port 22\nport 2222\npermitrootlogin no\n')
        self.assertEqual(result['port'], ['22', '2222'])
        self.assertIn('allowusers', result)
        self.assertIn('denygroups', result)

    def test_discovery_tracks_match_semantics_without_hash_or_formatting_noise(self):
        for text, expected in [
                (r'User nobo\dy # comment', ['User', r'nobo\dy']),
                ('User nobody#suffix # comment', ['User', 'nobody#suffix']),
                ('User "no"body', ['User', 'nobody']),
                ('"/path with space#hash" # comment', ['/path with space#hash']),
                (r'"echo \"yes\""', ['echo "yes"'])]:
            self.assertEqual(ssh.arguments(text), expected)
            self.assertEqual(discovery.arguments(text), expected)
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'sshd_config'
            config.write_text('PermitRootLogin no\nMatch User root\nPermitRootLogin yes\n')
            hashes, _, rules = discovery.sources(str(config))
            self.assertEqual(rules, [{'directive': 'match', 'arguments': ['User', 'root']},
                                     {'directive': 'permitrootlogin', 'arguments': ['yes']}])
            config.write_text('# changed comment\nPermitRootLogin no\n  Match   User root # comment\n'
                              '  permitrootlogin=yes\n')
            new_hashes, _, new_rules = discovery.sources(str(config))
            self.assertNotEqual(hashes, new_hashes)
            self.assertEqual(rules, new_rules)
            config.write_text('PermitRootLogin no\nMatch User root\nPermitRootLogin no\n')
            self.assertNotEqual(rules, discovery.sources(str(config))[2])

    @unittest.skipUnless(shutil.which('sshd') and shutil.which('ssh-keygen'), 'OpenSSH tools unavailable')
    def test_monitor_preserves_include_scope_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = root / 'hostkey'
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
            config, first, second = (root / name for name in ('config', 'first', 'second'))
            config.write_text(f'HostKey {key}\nPasswordAuthentication no\nInclude "{first}" "{second}"\n')
            first.write_text('Match User root\nPermitRootLogin no\n')
            second.write_text('PasswordAuthentication yes\n')
            command = [shutil.which('sshd'), '-T', '-f', str(config), '-C', CONTEXT.replace('user=oski,', 'user=root,')]
            before = discovery.effective(ssh.run(command).stdout)
            # Match scope in the first Include must not leak into the second.
            self.assertEqual(set(ssh.inspect(str(config), POLICY)), {str(config), str(first), str(second)})
            rules = discovery.sources(str(config))[2]
            first.write_text('Match User root\nPermitRootLogin no\nPasswordAuthentication yes\n')
            second.write_text('')
            after = discovery.effective(ssh.run(command).stdout)
            self.assertEqual(before['passwordauthentication'], ['no'])
            self.assertEqual(after['passwordauthentication'], ['yes'])
            self.assertNotEqual(rules, discovery.sources(str(config))[2])

    @unittest.skipUnless(shutil.which('sshd') and shutil.which('ssh-keygen'), 'OpenSSH tools unavailable')
    def test_quoted_keywords_cannot_bypass_enforcement_or_monitoring(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = root / 'hostkey'
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
            config = root / 'config'
            command = [shutil.which('sshd'), '-T', '-f', str(config), '-C', CONTEXT.replace('user=oski,', 'user=nobody,')]
            for match, password in [('"Match"', '"PasswordAuthentication"'),
                                    ('Ma"tch"', 'Pass"wordAuthentication"')]:
                original = f'HostKey {key}\n{match} User nobody\n{password} yes\n'
                config.write_text(ssh.policy_config(original, POLICY))
                self.assertEqual(discovery.effective(ssh.run(command).stdout)['passwordauthentication'], ['no'])
                config.write_text('PasswordAuthentication no\n')
                rules = discovery.sources(str(config))[2]
                config.write_text(f'PasswordAuthentication no\n{match} User nobody\n{password} yes\n')
                self.assertNotEqual(rules, discovery.sources(str(config))[2])
                with self.assertRaises(RuntimeError):
                    ssh.inspect(str(config), POLICY)
            # SSH arguments are not shell arguments: unknown escapes and an
            # embedded # are literal, not shell escapes/comments.
            for user in (r'nobo\dy', 'nobody#suffix'):
                config.write_text(f'HostKey {key}\nPasswordAuthentication no\nMatch User {user}\nPasswordAuthentication yes\n')
                self.assertEqual(discovery.effective(ssh.run(command).stdout)['passwordauthentication'], ['no'])
                rules = discovery.sources(str(config))[2]
                config.write_text(f'HostKey {key}\nPasswordAuthentication no\nMatch User nobody\nPasswordAuthentication yes\n')
                self.assertEqual(discovery.effective(ssh.run(command).stdout)['passwordauthentication'], ['yes'])
                self.assertNotEqual(rules, discovery.sources(str(config))[2])
            # Native glob handles escaped metacharacters differently from Python.
            included = root / 'name?.conf'
            included.write_text('Match User nobody\nPasswordAuthentication yes\n')
            pattern = str(included).replace('?', r'\?')
            config.write_text(f'HostKey {key}\nPasswordAuthentication no\nInclude {pattern}\n')
            self.assertEqual(discovery.effective(ssh.run(command).stdout)['passwordauthentication'], ['yes'])
            for inspect in (discovery.sources, lambda path: ssh.inspect(path, POLICY)):
                with self.assertRaisesRegex(RuntimeError, 'Unsupported escaped SSH Include'):
                    inspect(str(config))

    @unittest.skipUnless(shutil.which('sshd') and shutil.which('ssh-keygen'), 'OpenSSH tools unavailable')
    def test_real_sshd_validation_and_effective_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / 'hostkey'
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
            config = Path(directory) / 'config'
            original = f'HostKey {key}\nPermitRootLogin yes\nPasswordAuthentication yes\n'
            for enabled in ('no', 'yes'):
                desired = dict(POLICY, passwordauthentication=enabled, kbdinteractiveauthentication=enabled)
                config.write_text(ssh.policy_config(original, desired))
                ssh.verify(shutil.which('sshd'), str(config), desired, CONTEXT)
                output = io.StringIO()
                with patch.object(discovery, 'daemon', return_value=shutil.which('sshd')), \
                        patch.object(discovery, 'socket_listeners', return_value={}), \
                        patch('sys.argv', ['discover-ssh', '--config', str(config), '--context', CONTEXT]), \
                        contextlib.redirect_stdout(output):
                    discovery.main()
                state = json.loads(output.getvalue())
                self.assertEqual(state['match_rules'], [])
                for key, value in desired.items():
                    self.assertEqual(state['effective'][key], [value])

    @unittest.skipUnless(shutil.which('sshd') and shutil.which('ssh-keygen'), 'OpenSSH tools unavailable')
    def test_apply_repairs_included_match_settings_and_rolls_back_all_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = root / 'hostkey'
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
            dropins = root / 'sshd_config.d'
            dropins.mkdir()
            config, dropin, nested = root / 'sshd_config', dropins / 'vendor.conf', root / 'nested # config.conf'
            crypto = root / 'crypto-policy'
            crypto.write_text('Ciphers aes256-ctr\n')
            crypto_link = root / 'crypto-link'
            crypto_link.symlink_to(crypto)
            config.write_text(f'HostKey {key}\nPort 22\nInclude "{crypto_link}"\n'
                              f'Include "{dropins}/*.conf"\nPasswordAuthentication yes\n')
            dropin.write_text(f'PubkeyAuthentication no\n"Include" "{nested}"\n')
            nested.write_text('"Match" User root\n  "PermitRootLogin" yes\n  "ChallengeResponseAuthentication" yes\n'
                              '  AuthorizedKeysFile .ssh/team_keys\n')
            originals = {path: path.read_bytes() for path in (config, dropin, nested)}
            commands = []
            real_run = ssh.run
            def snapshot(path):
                if Path(path).is_symlink():
                    raise RuntimeError('snapshot must not touch an unchanged symlink')
                return Path(path).read_bytes(), None, {}
            def run(argv, check=True):
                commands.append(argv)
                if argv == ['reload']:
                    if commands.count(['reload']) == 1:
                        raise RuntimeError('injected reload failure')
                    return subprocess.CompletedProcess(argv, 0, '', '')
                if argv == ['status']:
                    return subprocess.CompletedProcess(argv, 0, '', '')
                return real_run(argv, check)
            with patch.object(ssh, 'CONFIG', str(config)), \
                    patch.object(ssh.os, 'geteuid', return_value=0), \
                    patch.object(ssh.pwd, 'getpwnam'), \
                    patch.object(ssh, 'daemon', return_value=shutil.which('sshd')), \
                    patch.object(ssh, 'connection_context', return_value=CONTEXT), \
                    patch.object(ssh, 'service', return_value=('ssh', ['reload'], ['status'])), \
                    patch.object(ssh, 'snapshot', side_effect=snapshot), \
                    patch.object(ssh, 'install', side_effect=lambda path, content, original: Path(path).write_bytes(content)), \
                    patch.object(ssh, 'run', side_effect=run), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError, 'original configuration restored'):
                    ssh.apply('no')
                self.assertEqual({path: path.read_bytes() for path in originals}, originals)
                ssh.apply('no')
                self.assertNotIn('PasswordAuthentication yes', config.read_text())
                self.assertEqual(dropin.read_text(), f'"Include" "{nested}"\n')
                self.assertTrue(crypto_link.is_symlink())
                self.assertEqual(crypto.read_text(), 'Ciphers aes256-ctr\n')
                self.assertEqual(nested.read_text(), '"Match" User root\n  AuthorizedKeysFile .ssh/team_keys\n')
                self.assertEqual(commands.count(['reload']), 3)
                ssh.apply('no')
                self.assertEqual(commands.count(['reload']), 3)
                # Reapply must remove tampered duplicates, not just trust its block.
                with config.open('a') as out:
                    out.write('PasswordAuthentication yes\n')
                with nested.open('a') as out:
                    out.write('PermitRootLogin yes\n')
                ssh.apply('no')
                self.assertEqual(commands.count(['reload']), 4)
                self.assertNotIn('PasswordAuthentication yes', config.read_text())
                self.assertNotIn('PermitRootLogin yes', nested.read_text())
                # A new file under an Include glob invalidates staged validation.
                clean = {path: path.read_bytes() for path in originals}
                attack = dropins / 'new.conf'
                real_verify = ssh.verify
                def concurrent_edit(*args):
                    real_verify(*args)
                    attack.write_text('PermitRootLogin yes\n')
                with patch.object(ssh, 'verify', side_effect=concurrent_edit):
                    with self.assertRaisesRegex(RuntimeError, 'changed during validation'):
                        ssh.apply('no')
                self.assertEqual({path: path.read_bytes() for path in originals}, clean)
                self.assertEqual(commands.count(['reload']), 4)
                ssh.apply('no')
                self.assertEqual(attack.read_text(), '')
                self.assertEqual(commands.count(['reload']), 5)
                # An Include symlink needing policy edits is refused, not replaced.
                crypto.write_text('Ciphers aes256-ctr\nPasswordAuthentication yes\n')
                with self.assertRaisesRegex(RuntimeError, 'snapshot must not touch'):
                    ssh.apply('no')
                self.assertTrue(crypto_link.is_symlink())
                self.assertEqual(crypto.read_text(), 'Ciphers aes256-ctr\nPasswordAuthentication yes\n')
                self.assertEqual(commands.count(['reload']), 5)

    def test_reload_failure_restores_original_and_idempotent_apply_does_not_reload(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'sshd_config'
            original = b'PermitRootLogin yes\n'
            config.write_bytes(original)
            commands = []
            def run(argv, check=True):
                commands.append(argv)
                if argv == ['reload'] and commands.count(['reload']) == 1:
                    raise RuntimeError('injected reload failure')
                return subprocess.CompletedProcess(argv, 0, '', '')
            with patch.object(ssh, 'CONFIG', str(config)), \
                    patch.object(ssh.os, 'geteuid', return_value=0), \
                    patch.object(ssh.pwd, 'getpwnam'), \
                    patch.object(ssh, 'daemon', return_value='/fake/sshd'), \
                    patch.object(ssh, 'connection_context', return_value=CONTEXT), \
                    patch.object(ssh, 'service', return_value=('ssh', ['reload'], ['status'])), \
                    patch.object(ssh, 'snapshot', side_effect=lambda path: (Path(path).read_bytes(), None, {})), \
                    patch.object(ssh, 'install', side_effect=lambda path, content, original: Path(path).write_bytes(content)), \
                    patch.object(ssh, 'verify'), patch.object(ssh, 'run', side_effect=run):
                with self.assertRaisesRegex(RuntimeError, 'original configuration restored'):
                    ssh.apply('no')
                self.assertEqual(config.read_bytes(), original)
                self.assertEqual(commands.count(['reload']), 2)
                config.write_text(ssh.policy_config(original.decode(), POLICY))
                commands.clear()
                with contextlib.redirect_stdout(io.StringIO()):
                    ssh.apply('no')
                self.assertNotIn(['reload'], commands)


if __name__ == '__main__':
    unittest.main()
