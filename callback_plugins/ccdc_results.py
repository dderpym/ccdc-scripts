"""Private per-host results for ccdcctl, without parsing Ansible console output."""
import json
import os
from pathlib import Path

from ansible.plugins.callback import CallbackBase


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "notification"
    CALLBACK_NAME = "ccdc_results"
    CALLBACK_NEEDS_ENABLED = True

    def _save(self, result):
        directory = os.environ.get("CCDC_RESULT_DIR")
        if not directory:
            return
        host = result._host.get_name()
        if Path(host).name != host or host in (".", ".."):
            return
        path = Path(directory) / host
        state = result._result
        if state.get("_ansible_no_log"):
            state = {"failed": True, "msg": "result hidden by no_log"}
        path.write_text(json.dumps(state, default=str))
        path.chmod(0o600)

    def v2_runner_on_ok(self, result):
        task = os.environ.get("CCDC_RESULT_TASK")
        if not task or result._task.get_name().split(" : ")[-1] == task:
            self._save(result)

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self._save(result)

    def v2_runner_on_unreachable(self, result):
        self._save(result)
