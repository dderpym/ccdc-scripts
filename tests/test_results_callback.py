"""Playbook cleanup must not overwrite scanner JSON or hide failures."""
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

try:
    import ansible  # noqa: F401
except ImportError:
    ansible = None


@unittest.skipIf(ansible is None, 'Ansible not installed in test environment')
class ResultsCallbackTests(unittest.TestCase):
    def test_selected_scanner_task_survives_cleanup_and_failures_are_retained(self):
        path = Path(__file__).resolve().parents[1] / 'callback_plugins/ccdc_results.py'
        spec = importlib.util.spec_from_file_location('results_callback', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        callback = module.CallbackModule()
        def result(task, state):
            return SimpleNamespace(_host=SimpleNamespace(get_name=lambda: 'a'),
                                   _task=SimpleNamespace(get_name=lambda: task), _result=state)
        with tempfile.TemporaryDirectory() as directory, patch.dict('os.environ', {
                'CCDC_RESULT_DIR': directory, 'CCDC_RESULT_TASK': 'Collect LSE security state'}):
            output = Path(directory) / 'a'
            callback.v2_runner_on_ok(result('lse : Allocate temporary directory', {'path': '/tmp/lse'}))
            self.assertFalse(output.exists())
            callback.v2_runner_on_ok(result('lse : Collect LSE security state', {'stdout': '{}', 'rc': 0}))
            callback.v2_runner_on_ok(result('lse : Remove temporary directory', {'changed': True}))
            self.assertEqual(json.loads(output.read_text())['stdout'], '{}')
            callback.v2_runner_on_failed(result('lse : Copy vendor', {'failed': True, 'msg': 'disk full'}))
            callback.v2_runner_on_ok(result('lse : Remove temporary directory', {'changed': True}))
            self.assertEqual(json.loads(output.read_text())['msg'], 'disk full')
            callback.v2_runner_on_unreachable(result('lse : Allocate temporary directory', {'unreachable': True}))
            self.assertTrue(json.loads(output.read_text())['unreachable'])
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
