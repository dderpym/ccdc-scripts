"""Offline trust replacement with real Ansible/known_hosts and a fake scanner."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('ansible-playbook') and shutil.which('ssh-keygen'),
                     'Ansible/ssh-keygen unavailable')
class HostKeysTests(unittest.TestCase):
    def test_selected_endpoint_replacement_and_failure_safety(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            keys = []
            for name in ('old', 'current'):
                path = root / name
                subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(path)],
                               check=True, capture_output=True, timeout=10)
                keys.append(' '.join(path.with_suffix('.pub').read_text().split()[:2]))
            old, current = keys
            endpoint = '[127.0.0.1]:22270'
            beta = f'192.0.2.2 {old}\n'
            known_hosts = root / 'known_hosts'
            known_hosts.write_text(f'{endpoint} {old}\n' + beta)
            inventory = root / 'inventory.yml'
            # Local connections ensure even a delegation regression cannot contact a lab.
            inventory.write_text(
                'all:\n  vars:\n    ansible_connection: local\n'
                f'    ccdc_known_hosts_file: {json.dumps(str(known_hosts))}\n'
                '  hosts:\n    alpha:\n      ansible_host: 127.0.0.1\n      ansible_port: 22270\n'
                '    beta:\n      ansible_host: 192.0.2.2\n      ansible_port: 22\n')
            scanner_dir = root / 'bin'
            scanner_dir.mkdir()
            scanner = scanner_dir / 'ssh-keyscan'
            scanner.write_text(
                '#!/bin/sh\n'
                '[ "$*" = "-T 5 -p 22270 -- 127.0.0.1" ] || exit 2\n'
                f"printf '%s\\n' '# 127.0.0.1:22270 SSH-2.0-fixture' '{endpoint} {current}'\n")
            scanner.chmod(0o700)
            env = dict(os.environ, ANSIBLE_CONFIG=str(ROOT / 'ansible.cfg'),
                       PATH=str(scanner_dir) + os.pathsep + os.environ['PATH'],
                       HOME=str(root), ANSIBLE_LOCAL_TEMP=str(root / 'ansible-tmp'),
                       CCDC_RESULT_DIR='')

            def invoke(replace=True):
                args = ['ansible-playbook', str(ROOT / 'playbooks/host-keys.yml'),
                        '-i', str(inventory), '--limit', 'alpha']
                if replace:
                    args += ['--extra-vars', 'replace_host_keys=true']
                return subprocess.run(args, cwd=ROOT, env=env, capture_output=True,
                                      text=True, timeout=60)

            before = known_hosts.read_bytes()
            result = invoke(replace=False)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('Use ccdcctl init --replace-host-keys', result.stdout)
            self.assertEqual(known_hosts.read_bytes(), before)

            result = invoke()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            enrolled = known_hosts.read_bytes()
            self.assertIn(beta, enrolled.decode().splitlines(keepends=True))
            found = subprocess.run(['ssh-keygen', '-F', endpoint, '-f', str(known_hosts)],
                                   check=True, capture_output=True, text=True, timeout=10)
            alpha_keys = [' '.join(line.split()[1:3]) for line in found.stdout.splitlines()
                          if line and not line.startswith('#')]
            self.assertEqual(alpha_keys, [current])

            result = invoke()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            # A deliberate reset rehashes names with fresh salts, but trusts
            # exactly the same current key and preserves unrelated endpoints.
            self.assertIn(beta, known_hosts.read_text().splitlines(keepends=True))
            found = subprocess.run(['ssh-keygen', '-F', endpoint, '-f', str(known_hosts)],
                                   check=True, capture_output=True, text=True, timeout=10)
            alpha_keys = [' '.join(line.split()[1:3]) for line in found.stdout.splitlines()
                          if line and not line.startswith('#')]
            self.assertEqual(alpha_keys, [current])

            before = known_hosts.read_bytes()
            for script in ('#!/bin/sh\nexit 1\n', '#!/bin/sh\nprintf "# no host keys available\\n"\n'):
                scanner.write_text(script)
                result = invoke()
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('Read current host keys without sending credentials', result.stdout)
                self.assertEqual(known_hosts.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
