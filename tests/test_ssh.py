import contextlib
import io
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
    def test_owned_layer_precedes_original_and_has_no_include_dependency(self):
        original = 'PermitRootLogin yes\nPasswordAuthentication yes\n'
        managed = ssh.policy_config(original, POLICY)
        self.assertLess(managed.index('permitrootlogin no'), managed.index('PermitRootLogin yes'))
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
