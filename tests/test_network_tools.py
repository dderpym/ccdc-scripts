"""Offline package selection checks; never install packages or touch firewalls."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
TASKS = yaml.safe_load((ROOT / 'roles/network_tools/tasks/main.yml').read_text())


class NetworkToolsTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('ansible-playbook'), 'Ansible unavailable')
    def test_native_ansible_probe_selects_missing_packages_and_is_idempotent(self):
        fixtures = [
            ('Debian', 'Debian', '12', '12', ['iproute2', 'nftables', 'iptables']),
            ('Alpine', 'Alpine', '3', '3.22', ['iproute2', 'nftables', 'iptables']),
            ('Alpine', 'Alpine', '3', '3.18', ['iproute2', 'nftables', 'iptables', 'ip6tables']),
            ('RedHat', 'RedHat', '9', '9.6', ['iproute', 'nftables', 'iptables-nft']),
            ('Void', 'Void', 'rolling', 'rolling', ['iproute2', 'nftables', 'iptables']),
        ]
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            missing, present = base / 'missing', base / 'present'
            missing.mkdir()
            present.mkdir()
            for tool in ('ip', 'ss', 'nft', 'iptables', 'ip6tables', 'iptables-save',
                         'ip6tables-save', 'iptables-restore', 'ip6tables-restore'):
                (present / tool).symlink_to(shutil.which('true'))
            plays = []
            for family, distribution, major, version, expected in fixtures:
                for path, packages in [(missing, expected), (present, [])]:
                    probe = dict(TASKS[1], environment={'PATH': str(path)})
                    plays.append({
                        'name': f'{distribution} {version} {path.name}',
                        'hosts': 'localhost', 'gather_facts': False, 'become': False,
                        'vars': {'ansible_facts': {'os_family': family, 'distribution': distribution,
                                                  'distribution_major_version': major,
                                                  'distribution_version': version}},
                        'tasks': [probe, {'ansible.builtin.assert': {'that': [
                            f'network_tools_missing.stdout_lines == {packages!r}',
                            'not network_tools_missing.changed']}}],
                    })
            playbook = base / 'probe.yml'
            playbook.write_text(yaml.safe_dump(plays, sort_keys=False))
            env = dict(os.environ, ANSIBLE_CONFIG=str(ROOT / 'ansible.cfg'))
            env.pop('CCDC_RESULT_DIR', None)
            result = subprocess.run(['ansible-playbook', '-i', 'localhost,', '-c', 'local',
                                     str(playbook)], env=env, text=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=90)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_provisioning_runs_only_in_the_firewall_preparation_playbook_not_init(self):
        init = yaml.safe_load((ROOT / 'roles/init/tasks/main.yml').read_text())
        self.assertFalse(any(task.get('ansible.builtin.include_role', {}).get('name') == 'network_tools'
                             for task in init))
        play, = yaml.safe_load((ROOT / 'playbooks/network-tools.yml').read_text())
        self.assertEqual(play['roles'], ['network_tools'])
        apt = next(task['ansible.builtin.apt'] for task in TASKS if 'ansible.builtin.apt' in task)
        self.assertEqual(apt['policy_rc_d'], 101)
        self.assertFalse(any('ansible.builtin.service' in task or 'ansible.builtin.systemd' in task
                             for task in TASKS))


if __name__ == '__main__':
    unittest.main()
