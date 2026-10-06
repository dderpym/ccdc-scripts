"""Safety checks for the opt-in disposable lab; never starts containers."""
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import subprocess
import socket
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('lab_manage', str(ROOT / 'lab/manage'))
spec = importlib.util.spec_from_loader(loader.name, loader)
lab = importlib.util.module_from_spec(spec)
loader.exec_module(lab)


class LabSafetyTests(unittest.TestCase):
    def test_inventory_contains_only_standard_host_connection_fields(self):
        import yaml
        hosts = {'hatchery': {'ansible_host': '127.0.0.1', 'ansible_port': 22270},
                 'tarpit': {'ansible_host': '127.0.0.1', 'ansible_port': 22170}}
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory) / 'inventory.yml'
            with patch.object(lab, 'INVENTORY', inventory):
                lab.write_inventory(hosts)
            text = inventory.read_text()
            self.assertIn('\nall:\n  hosts:\n', text)
            self.assertEqual(yaml.safe_load(text), {'all': {'hosts': hosts}})

    def test_remote_docker_host_is_rejected_without_contacting_it(self):
        with patch.dict(os.environ, {'DOCKER_HOST': 'tcp://example.invalid:2375'}, clear=True), \
                patch.object(lab.subprocess, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'local Unix-socket Docker'):
                lab.local_docker()
        run.assert_not_called()

    def test_context_override_cannot_hide_remote_docker_behind_unix_host(self):
        result = subprocess.CompletedProcess([], 0, 'ssh://example.invalid\n', '')
        with patch.dict(os.environ, {'DOCKER_CONTEXT': 'remote', 'DOCKER_HOST': 'unix:///var/run/docker.sock'}, clear=True), \
                patch.object(lab.subprocess, 'run', return_value=result) as run:
            with self.assertRaisesRegex(RuntimeError, 'local Unix-socket Docker'):
                lab.local_docker()
        self.assertIn('remote', run.call_args.args[0])

    def test_private_input_rejects_group_readable_files_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            secret = Path(directory) / 'password'
            secret.write_text('disposable-test-value\n')
            secret.chmod(0o644)
            with self.assertRaises(RuntimeError):
                lab.password_file(secret)
            secret.chmod(0o600)
            self.assertEqual(lab.password_file(secret), 'disposable-test-value')
            link = Path(directory) / 'link'
            link.symlink_to(secret)
            with self.assertRaises(RuntimeError):
                lab.password_file(link)

    def test_relay_rejects_socket_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            source, link, pinned = (Path(directory) / name for name in ('source', 'link', 'pinned'))
            with socket.socket(socket.AF_UNIX) as server:
                server.bind(str(source))
                link.symlink_to(source)
                with self.assertRaises(RuntimeError):
                    lab.pin_socket(link, pinned)
                self.assertFalse(pinned.exists())

    def test_replacing_container_socket_name_cannot_redirect_host_relay(self):
        with tempfile.TemporaryDirectory() as directory:
            source, pinned = (Path(directory) / name for name in ('source', 'pinned'))
            with socket.socket(socket.AF_UNIX) as server, socket.socket(socket.AF_UNIX) as client:
                server.bind(str(source))
                server.listen()
                lab.pin_socket(source, pinned)
                source.unlink()
                source.symlink_to('/nonexistent-unrelated-host-service')
                client.connect(str(pinned))
                accepted, _ = server.accept()
                with accepted:
                    client.sendall(b'original')
                    self.assertEqual(accepted.recv(8), b'original')

    @unittest.skipUnless(Path('/proc/self/cmdline').exists(), 'Linux /proc required')
    def test_teardown_refuses_to_signal_an_unrelated_process(self):
        with tempfile.TemporaryDirectory() as directory:
            pidfile = Path(directory) / 'relay.pid'
            pidfile.write_text(str(os.getpid()))
            with patch.object(lab, 'PID', pidfile), patch.object(lab.os, 'kill') as kill:
                with self.assertRaisesRegex(RuntimeError, 'not our lab process'):
                    lab.stop_relay()
                kill.assert_not_called()


if __name__ == '__main__':
    unittest.main()
