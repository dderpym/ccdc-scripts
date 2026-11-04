"""Compact stdout for ccdcctl; enable with ANSIBLE_STDOUT_CALLBACK=ccdc_progress."""
import os
import re
import shutil
import sys
import unicodedata

from ansible.plugins.callback import CallbackBase


# Remove whole terminal sequences, not just their ESC byte (including OSC links).
_ESCAPE = re.compile(
    r"(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]"
    r"|(?:\x1b\]|\x9d).*?(?:\x07|\x1b\\|\x9c|$)"
    r"|\x1b[P^_].*?(?:\x1b\\|$)|\x1b[ -/]*[@-~]",
    re.DOTALL,
)


def _clean(value):
    text = _ESCAPE.sub("", str(value))
    return " ".join("".join(
        char if char.isspace() else "" if unicodedata.category(char).startswith("C") else char
        for char in text
    ).split())


def _fit(text, width=None):
    # Reserve the last column to avoid terminal auto-wrap; account for wide glyphs.
    remaining = max(0, shutil.get_terminal_size((80, 24)).columns - 1 if width is None else width)
    output = []
    for char in text:
        width = 0 if unicodedata.combining(char) else 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
        if width > remaining:
            break
        output.append(char)
        remaining -= width
    return "".join(output)


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "stdout"
    CALLBACK_NAME = "ccdc_progress"

    def __init__(self):
        super().__init__()
        self._tty = sys.stdout.isatty() and os.environ.get("TERM") != "dumb"
        self._line_visible = False
        self._tasks = {}
        self._free = False

    def _clear(self):
        if self._line_visible:
            sys.stdout.write("\r\x1b[2K")
            sys.stdout.flush()
            self._line_visible = False

    def _state(self, task):
        key = getattr(task, "_uuid", None) or id(task)
        if key not in self._tasks:
            self._tasks[key] = {"name": _clean(task.get_name()), "hosts": {}}
        return self._tasks[key]

    def _summary(self, state):
        hosts = state["hosts"]
        counts = " ".join("%s=%d" % (kind, sum(value == kind for value in hosts.values()))
                          for kind in ("ok", "changed", "skipped", "failed"))
        counts = "hosts=%d %s" % (len(hosts), counts)
        name = state["name"]
        if self._tty:
            name = _fit(name, shutil.get_terminal_size((80, 24)).columns - len(counts) - 4)
        return (name + " | " if name else "") + counts

    def _update(self, state):
        if self._tty:
            sys.stdout.write("\r\x1b[2K" + _fit(self._summary(state)))
            sys.stdout.flush()
            self._line_visible = True

    def _flush(self):
        self._clear()
        if not self._tty:
            for state in self._tasks.values():
                if state["hosts"]:
                    self._display.display(self._summary(state))
        self._tasks.clear()

    def v2_playbook_on_play_start(self, play):
        self._flush()
        # Free strategy has no task-completion boundary: aggregate until play end.
        self._free = getattr(play, "strategy", "linear") == "free"

    def v2_playbook_on_task_start(self, task, is_conditional):
        if not self._free:
            self._flush()
        self._update(self._state(task))

    def v2_playbook_on_handler_task_start(self, task):
        self.v2_playbook_on_task_start(task, False)

    def _hidden(self, result):
        return result._result.get("_ansible_no_log") or getattr(result._task, "no_log", False)

    def _warnings(self, result):
        if not self._hidden(result):
            # Leave Ansible's warning/deprecation settings intact. Do not mutate
            # the result shared with notification callbacks.
            if result._result.get("warnings") or result._result.get("deprecations"):
                self._clear()
                warnings = result._result.get("warnings") or []
                if isinstance(warnings, str):
                    warnings = [warnings]
                for warning in warnings:
                    self._display.warning(_clean(warning))
                for warning in result._result.get("deprecations") or []:
                    self._display.deprecated(
                        msg=_clean(warning.get("msg", "")),
                        version=warning.get("version"), date=warning.get("date"),
                        collection_name=warning.get("collection_name"))

    def _details(self, data):
        if data.get("_ansible_no_log"):
            return "hidden (no_log)"
        parts = []
        if "_ansible_item_label" in data:
            parts.append("item=" + _clean(data["_ansible_item_label"]))
        for field in ("msg", "stdout", "stderr"):
            if data.get(field):
                parts.append("%s: %s" % (field, _clean(data[field])))
        if "rc" in data:
            parts.append("rc=" + _clean(data["rc"]))
        for item in (data.get("results") or []):
            if isinstance(item, dict) and (item.get("failed") or item.get("unreachable")):
                parts.append(self._details(item))
        return "; ".join(parts) or "no diagnostic returned"

    def _error(self, result, status, ignored=False):
        self._clear()
        detail = "hidden (no_log)" if self._hidden(result) else self._details(result._result)
        self._display.display("%s%s [%s] %s: %s" % (
            status, " (ignored)" if ignored else "", _clean(result._host.get_name()),
            _clean(result._task.get_name()), detail))

    def _complete(self, result, status):
        self._warnings(result)
        state = self._state(result._task)
        state["hosts"][result._host.get_name()] = status
        self._update(state)

    def v2_runner_on_ok(self, result):
        self._complete(result, "changed" if result._result.get("changed") else "ok")

    def v2_runner_on_skipped(self, result):
        self._complete(result, "skipped")

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self._error(result, "FAILED", ignore_errors)
        self._complete(result, "failed")

    def v2_runner_on_unreachable(self, result):
        self._error(result, "UNREACHABLE", getattr(result._task, "ignore_unreachable", False))
        self._complete(result, "failed")

    def v2_runner_item_on_failed(self, result):
        self._error(result, "FAILED item", getattr(result._task, "ignore_errors", False))
        self._warnings(result)

    def v2_runner_item_on_ok(self, result):
        self._warnings(result)

    def v2_runner_item_on_skipped(self, result):
        self._warnings(result)

    def v2_runner_on_retry(self, result):
        attempts = "?" if self._hidden(result) else _clean(result._result.get("attempts", "?"))
        self._error(result, "RETRY attempt=" + attempts)
        self._warnings(result)

    def v2_playbook_on_no_hosts_matched(self):
        self._clear()
        self._display.warning("No hosts matched; no tasks were run.")

    def v2_playbook_on_no_hosts_remaining(self):
        self._clear()
        self._display.warning("No hosts remaining; play stopped.")

    def v2_playbook_on_stats(self, stats):
        self._flush()
        for host in sorted(stats.processed):
            summary = stats.summarize(host)
            failed = summary.get("failures", 0) or summary.get("unreachable", 0)
            self._display.display("%s: %s changed=%d" % (
                _clean(host), "FAILED" if failed else "OK", summary.get("changed", 0)))
