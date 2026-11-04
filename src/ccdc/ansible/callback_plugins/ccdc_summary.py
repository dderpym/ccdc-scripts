"""Enable with callbacks_enabled=ccdc_summary (notification callback)."""
from ansible.plugins.callback import CallbackBase
import os


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "notification"
    CALLBACK_NAME = "ccdc_summary"
    CALLBACK_NEEDS_ENABLED = True

    def __init__(self):
        super().__init__()
        self._init = False
        self._failures = {}

    def v2_playbook_on_start(self, playbook):
        self._init = os.path.basename(playbook._file_name) == "init.yml"
        self._failures = {}

    def v2_runner_on_failed(self, result, ignore_errors=False):
        if not ignore_errors:
            self._record(result)

    def v2_runner_on_unreachable(self, result):
        self._record(result)

    def _record(self, result):
        if result._result.get("_ansible_no_log"):
            message = "hidden (no_log)"
        else:
            message = str(result._result.get("msg", "task failed"))
            detail = result._result.get("stderr", "").strip()
            if detail:
                message += ": " + detail[-400:]
        self._failures.setdefault(result._host.get_name(), []).append(
            "%s: %s" % (result._task.get_name(), " ".join(message.split())[:500])
        )

    def v2_playbook_on_stats(self, stats):
        if not self._init:
            return
        self._display.banner("INIT SUMMARY")
        for host in sorted(stats.processed):
            summary = stats.summarize(host)
            failed = summary.get("failures", 0) or summary.get("unreachable", 0)
            self._display.display("%s: %s" % (host, "FAILED" if failed else "OK"))
            for message in self._failures.get(host, []):
                self._display.display("  " + message)
