"""Offline stdout-callback checks: no playbooks, subprocesses, or host connections."""
import importlib.util
import io
import os
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch


# Exercise the real base when installed, but keep the suite runnable offline.
try:
    from ansible.plugins.callback import CallbackBase
except ImportError:
    class CallbackBase:
        def __init__(self):
            self._display = None

    modules = {name: ModuleType(name) for name in (
        "ansible", "ansible.plugins", "ansible.plugins.callback")}
    modules["ansible.plugins.callback"].CallbackBase = CallbackBase
else:
    modules = {}

path = Path(__file__).resolve().parents[1] / "callback_plugins/ccdc_progress.py"
spec = importlib.util.spec_from_file_location("progress_callback", path)
progress = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, modules):
    spec.loader.exec_module(progress)


class Output(io.StringIO):
    def __init__(self, tty=False):
        super().__init__()
        self.tty = tty

    def isatty(self):
        return self.tty


class Display:
    def __init__(self, output):
        self.output = output
        self.messages = []
        self.warnings = []

    def display(self, text, **kwargs):
        self.messages.append(text)
        self.output.write(text + "\n")

    def warning(self, text, **kwargs):
        self.warnings.append(text)
        self.display("WARNING: " + text)

    def deprecated(self, msg, **kwargs):
        self.warning(msg)


def task(name="Install packages", **kwargs):
    return SimpleNamespace(get_name=lambda: name, **kwargs)


def result(work, host="a", **data):
    return SimpleNamespace(_task=work, _host=SimpleNamespace(get_name=lambda: host), _result=data)


def stats(**hosts):
    return SimpleNamespace(processed=hosts, summarize=lambda host: hosts[host])


class ProgressTests(unittest.TestCase):
    def callback(self, tty=False, term="xterm", width=80):
        output = Output(tty)
        self.enterContext(patch.object(sys, "stdout", output))
        self.enterContext(patch.dict(os.environ, {"TERM": term}))
        self.enterContext(patch.object(progress.shutil, "get_terminal_size", return_value=os.terminal_size((width, 24))))
        callback = progress.CallbackModule()
        callback._display = Display(output)
        return callback, output

    def test_plugin_identity(self):
        self.assertEqual(progress.CallbackModule.CALLBACK_TYPE, "stdout")
        self.assertEqual(progress.CallbackModule.CALLBACK_NAME, "ccdc_progress")

    def test_non_tty_aggregates_until_next_task_and_stats(self):
        cb, output = self.callback()
        first, second = task(), task("Cleanup")
        cb.v2_playbook_on_task_start(first, False)
        cb.v2_runner_on_ok(result(first, stdout="SECRET success JSON", msg="ordinary result"))
        cb.v2_runner_on_ok(result(first, "b", changed=True))
        cb.v2_runner_on_skipped(result(first, "c"))
        self.assertEqual(output.getvalue(), "")
        cb.v2_playbook_on_task_start(second, False)
        self.assertEqual(cb._display.messages, ["Install packages | hosts=3 ok=1 changed=1 skipped=1 failed=0"])
        cb.v2_runner_on_ok(result(second))
        cb.v2_playbook_on_stats(stats(a={"changed": 2}, b={"failures": 1}, c={"unreachable": 1}))
        self.assertEqual(cb._display.messages[1:], [
            "Cleanup | hosts=1 ok=1 changed=0 skipped=0 failed=0",
            "a: OK changed=2", "b: FAILED changed=0", "c: FAILED changed=0"])
        self.assertNotIn("SECRET", output.getvalue())
        self.assertNotIn("\x1b", output.getvalue())
        self.assertNotIn("\r", output.getvalue())

    def test_tty_replaces_one_line_and_preserves_counts_at_terminal_width(self):
        cb, output = self.callback(tty=True, width=65)
        work = task("Long task " + "界" * 100)
        cb.v2_playbook_on_task_start(work, False)
        cb.v2_runner_on_ok(result(work))
        cb.v2_runner_on_ok(result(work, "b", changed=True))
        self.assertEqual(cb._display.messages, [])
        frames = output.getvalue().split("\r\x1b[2K")[1:]
        self.assertEqual(len(frames), 3)
        self.assertIn("hosts=2 ok=1 changed=1 skipped=0 failed=0", frames[-1])
        self.assertNotIn("\n", output.getvalue())
        for frame in frames:
            width = sum(2 if progress.unicodedata.east_asian_width(char) in ("W", "F") else 1 for char in frame)
            self.assertLessEqual(width, 64)
        cb.v2_playbook_on_stats(stats(a={"changed": 0}))
        self.assertIn("\r\x1b[2K", output.getvalue())
        self.assertFalse(cb._line_visible)
        self.assertEqual(cb._display.messages, ["a: OK changed=0"])

    def test_dumb_terminal_has_no_ansi_even_when_isatty(self):
        cb, output = self.callback(tty=True, term="dumb")
        work = task()
        cb.v2_runner_on_ok(result(work))  # Ad hoc: no task-start event required.
        cb.v2_playbook_on_stats(stats(a={}))
        self.assertNotIn("\x1b", output.getvalue())
        self.assertIn("hosts=1", output.getvalue())

    def test_error_is_prompt_ignored_and_sanitized(self):
        cb, output = self.callback()
        work = task("Deploy\x1b[31m service\x1b[0m\nnow")
        cb.v2_runner_on_failed(result(work, "a\x08", msg="bad\r\nstatus\x1b[2J", stdout="tool output",
                                       stderr="\x1b]0;owned\x07permission denied\u202e"), ignore_errors=True)
        text = output.getvalue()
        self.assertIn("FAILED (ignored) [a] Deploy service now", text)
        for field in ("msg: bad status", "stdout: tool output", "stderr: permission denied"):
            self.assertIn(field, text)
        for control in ("\x1b", "\r", "\x08", "\u202e", "owned"):
            self.assertNotIn(control, text)
        self.assertEqual(len(cb._display.messages), 1)
        cb.v2_runner_on_unreachable(result(task("Connect", ignore_unreachable=True), "b", msg="Connection refused"))
        self.assertIn("UNREACHABLE (ignored) [b] Connect: msg: Connection refused", output.getvalue())

    def test_tty_clears_before_error_and_stats(self):
        cb, output = self.callback(tty=True)
        work = task()
        cb.v2_playbook_on_task_start(work, False)
        cb.v2_runner_on_failed(result(work, msg="disk full"))
        self.assertIn("\r\x1b[2KFAILED [a]", output.getvalue())
        self.assertTrue(cb._line_visible)  # Progress resumes after the diagnostic.
        cb.v2_playbook_on_stats(stats(a={"failures": 1, "changed": 1}))
        self.assertIn("\r\x1b[2KInstall packages", output.getvalue())
        self.assertTrue(output.getvalue().endswith("a: FAILED changed=1\n"))

    def test_no_log_hides_all_result_fields_including_items_retries_and_warnings(self):
        cb, output = self.callback()
        work = task()
        hidden = result(work, _ansible_no_log=True, msg="SECRET", stdout="SECRET", stderr="SECRET",
                        _ansible_item_label="SECRET", attempts="SECRET", rc="SECRET",
                        warnings=["SECRET"], results=[{"failed": True, "msg": "SECRET"}])
        cb.v2_runner_on_failed(hidden, ignore_errors=True)
        cb.v2_runner_on_unreachable(hidden)
        cb.v2_runner_item_on_failed(hidden)
        cb.v2_runner_on_retry(hidden)
        cb.v2_runner_on_ok(hidden)
        cb.v2_runner_on_failed(result(task(no_log=True), msg="SECRET"))
        cb.v2_playbook_on_stats(stats(a={"failures": 1}))
        self.assertNotIn("SECRET", output.getvalue())
        self.assertIn("hidden (no_log)", output.getvalue())
        self.assertIn("RETRY attempt=?", output.getvalue())
        self.assertEqual(cb._display.warnings, [])

    def test_loop_items_and_retries_do_not_count_as_completed_hosts(self):
        cb, output = self.callback()
        work = task(ignore_errors=True)
        cb.v2_runner_item_on_ok(result(work, stdout="successful JSON"))
        cb.v2_runner_item_on_skipped(result(work))
        cb.v2_runner_item_on_failed(result(work, _ansible_item_label="package", msg="not found"))
        cb.v2_runner_on_retry(result(work, attempts=2, stderr="timeout"))
        self.assertIn("FAILED item (ignored)", output.getvalue())
        self.assertIn("item=package; msg: not found", output.getvalue())
        self.assertIn("RETRY attempt=2", output.getvalue())
        self.assertNotIn("successful JSON", output.getvalue())
        cb.v2_runner_on_failed(result(work, msg="items failed", results=[
            {"failed": True, "stderr": "useful child diagnostic"},
            {"failed": True, "_ansible_no_log": True, "msg": "SECRET"},
            {"stdout": "successful JSON"}]), ignore_errors=True)
        cb.v2_playbook_on_stats(stats(a={}))
        self.assertIn("useful child diagnostic; hidden (no_log)", output.getvalue())
        self.assertNotIn("SECRET", output.getvalue())
        self.assertEqual(sum("hosts=" in line for line in cb._display.messages), 1)
        self.assertIn("hosts=1 ok=0 changed=0 skipped=0 failed=1", output.getvalue())

    def test_warnings_are_visible_and_do_not_mutate_results(self):
        cb, output = self.callback(tty=True)
        work = task()
        response = result(work, warnings=["Ansible\x1b[31m warning\x1b[0m"],
                          deprecations=[{"msg": "old\x1b]0;owned\x07 feature"}])
        cb.v2_playbook_on_task_start(work, False)
        cb.v2_runner_on_ok(response)
        self.assertIn("\r\x1b[2KWARNING: Ansible warning", output.getvalue())
        self.assertIn("WARNING: old feature", output.getvalue())
        self.assertNotIn("owned", output.getvalue())
        self.assertEqual(response._result["warnings"], ["Ansible\x1b[31m warning\x1b[0m"])
        self.assertEqual(response._result["deprecations"][0]["msg"], "old\x1b]0;owned\x07 feature")

    def test_tty_does_not_leave_successful_task_logs(self):
        cb, output = self.callback(tty=True)
        for name in ('First', 'Second'):
            work = task(name)
            cb.v2_playbook_on_task_start(work, False)
            cb.v2_runner_on_ok(result(work))
        self.assertEqual(cb._display.messages, [])
        cb.v2_playbook_on_stats(stats(a={'changed': 0}))
        self.assertEqual(cb._display.messages, ['a: OK changed=0'])

    def test_no_hosts_notices_clear_progress_and_remain_visible(self):
        cb, output = self.callback(tty=True)
        cb.v2_playbook_on_task_start(task(), False)
        cb.v2_playbook_on_no_hosts_matched()
        cb.v2_playbook_on_no_hosts_remaining()
        self.assertFalse(cb._line_visible)
        self.assertIn('No hosts matched', output.getvalue())
        self.assertIn('No hosts remaining', output.getvalue())

    def test_handlers_and_free_strategy_aggregate_interleaved_results(self):
        cb, output = self.callback()
        cb.v2_playbook_on_play_start(SimpleNamespace(strategy="free"))
        first, second = task("First"), task("Handler")
        cb.v2_playbook_on_task_start(first, False)
        cb.v2_runner_on_ok(result(first))
        cb.v2_playbook_on_handler_task_start(second)
        cb.v2_runner_on_ok(result(second))
        cb.v2_runner_on_ok(result(first, "b"))
        self.assertEqual(output.getvalue(), "")
        cb.v2_playbook_on_play_start(SimpleNamespace(strategy="linear"))
        self.assertEqual(cb._display.messages, [
            "First | hosts=2 ok=2 changed=0 skipped=0 failed=0",
            "Handler | hosts=1 ok=1 changed=0 skipped=0 failed=0"])
        cb.v2_playbook_on_stats(stats(a={}))
        self.assertEqual(cb._display.messages[-1], "a: OK changed=0")


if __name__ == "__main__":
    unittest.main()
