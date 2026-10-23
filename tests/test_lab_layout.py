"""Container setup depends on its own directory, not the competition repo."""
import importlib.machinery
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class LabLayoutTests(unittest.TestCase):
    def test_runtime_bridge_allows_egress_without_publishing_services(self):
        import yaml
        compose = yaml.safe_load((ROOT / 'lab/compose.yml').read_text())
        for network in compose['networks'].values():
            self.assertFalse(network.get('internal', False))
        for service in compose['services'].values():
            self.assertNotIn('network_mode', service)
            self.assertFalse(service.get('ports'))
            self.assertEqual(service['dns'], ['1.1.1.1', '8.8.8.8'])
            self.assertEqual(service.get('dns_search'), ['.'])
            self.assertEqual(set(service['networks']), set(compose['networks']))

    def test_setup_can_live_outside_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            standalone = Path(directory) / 'standalone-lab'
            standalone.mkdir()
            manage = standalone / 'manage'
            shutil.copy2(ROOT / 'lab/manage', manage)
            loader = importlib.machinery.SourceFileLoader('standalone_lab_manage', str(manage))
            spec = importlib.util.spec_from_loader(loader.name, loader)
            lab = importlib.util.module_from_spec(spec)
            loader.exec_module(lab)
            self.assertEqual(lab.SECRETS, standalone / 'secrets')
            self.assertEqual(lab.INVENTORY, standalone / 'inventory.yml')
            self.assertIn(str(standalone / 'compose.yml'), lab.COMPOSE)
            with patch.object(lab.subprocess, 'run') as run:
                lab.run(['docker', 'compose', 'version'])
            self.assertEqual(run.call_args.kwargs['cwd'], standalone)
            hosts = {'hatchery': {'ansible_host': '127.0.0.1', 'ansible_port': 22270}}
            lab.write_inventory(hosts)
            import yaml
            self.assertEqual(yaml.safe_load(lab.INVENTORY.read_text()), {'all': {'hosts': hosts}})


if __name__ == '__main__':
    unittest.main()
