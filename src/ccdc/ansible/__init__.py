"""Scripts that run on a Target, through Ansible.

AnsibleScript owns a remote source file (bash, python, anything with a shebang) that sits
next to the class that defines it. BundleScript is a ComposedScript of AnsibleScripts that
is packed into ONE archive, uploaded once and run in order on the host.
"""
import json
from pathlib import Path
import sys
import tempfile

from ccdc.ansible import archive
from ccdc.runner import AnsibleRunner, RemoteError
from ccdc.script import ComposedScript, Script, Step, accepted

REMOTE_LIB = Path(__file__).resolve().parents[1] / "remote_lib"


class AnsibleScript(Script):
    """A script that runs on a Target; run(target, ...) is its first argument.

    The Target says which host and how to authenticate (see ccdc.target). The class owns
    its remote code:
      source      file name, relative to the directory of the module defining the class
      support     extra files shipped with it (looked up beside the class, then in
                  ccdc/remote_lib); Python sources import them as plain modules
      become      run under sudo; live: show the progress UI and return success as a bool;
      connection  hand the script this login's SSH_CONNECTION; stdin: the controller
                  `payload` file arrives as its standard input
    `arguments(**kw)` builds the argv, `parse(result, **kw)` turns {rc, stdout, stderr}
    into the return value (default: the JSON on stdout; nonzero exit is a RemoteError).
    Keyword arguments given to the constructor are prefilled for every run.
    """
    source = None
    support = ()
    become = True
    live = False
    connection = False
    stdin = False
    timeout = 300

    def __init__(self, runner=None, **params):
        self.runner = runner or AnsibleRunner()
        self.params = params

    def arguments(self, **kwargs):
        return []

    def parse(self, result, **kwargs):
        if result["rc"] != 0:
            raise RemoteError("%s: %s" % (self.name, result["stderr"].strip() or result["stdout"].strip()
                                          or "exit status %s" % result["rc"]))
        try:
            return json.loads(result["stdout"])
        except ValueError as exc:
            raise RemoteError("%s: output is not JSON (%s)" % (self.name, exc))

    def argv(self, **kwargs):
        return [str(a) for a in self.arguments(**{**self.params, **kwargs})]

    def _directory(self, attribute):
        for cls in type(self).__mro__:
            if cls.__dict__.get(attribute):
                return Path(sys.modules[cls.__module__].__file__).resolve().parent
        return None

    def source_path(self):
        return self._directory("source") / self.source

    def support_paths(self):
        found = []
        for name in self.support:
            for base in (self._directory("support"), REMOTE_LIB):
                if base and (base / name).is_file():
                    found.append(base / name)
                    break
            else:
                raise FileNotFoundError("support file %s of %s" % (name, self.name))
        return found

    def run(self, target, payload=None, **kwargs):
        value = BundleScript(Step(self, **kwargs), runner=self.runner).run(target, payload)[0]
        if isinstance(value, Exception):
            raise value
        return value


class BundleScript(ComposedScript):
    """AnsibleScripts packed into ONE archive (only their files), uploaded once, run in order.

    run(target, payload=None, **kw) returns one value per step. With keep_going (default) a
    failed step is a RemoteError VALUE in its slot and the rest still run; without it the
    host stops at the first failure and run() raises. Identical steps (same class, source,
    arguments) run once and share the result. Consecutive steps that need different
    become/connection/live settings go in separate archives, still in order.
    """

    def __init__(self, *steps, keep_going=True, runner=None):
        super().__init__(*steps)
        for step in self.steps:
            if not isinstance(step.script, AnsibleScript) or step.script.source is None:
                raise TypeError("%s cannot be packed: a BundleScript holds AnsibleScripts with a source file"
                                % step.script.name)
        self.keep_going = keep_going
        self.runner = runner or (self.steps[0].script.runner if self.steps else AnsibleRunner())

    def run(self, target, payload=None, **injected):
        plan = []
        for index, step in enumerate(self.steps):
            script = step.script
            call = {**step.prefill, **accepted(script.arguments, injected)}
            args = script.argv(**call)
            kwargs = {**script.params, **call}
            plan.append({"index": index, "script": script, "kwargs": kwargs, "args": args,
                         "mode": (script.become, script.connection, script.live),
                         "key": (type(script), str(script.source_path()), tuple(args), script.stdin)})
        results = [None] * len(plan)
        start = 0
        while start < len(plan):
            end = start
            while end < len(plan) and plan[end]["mode"] == plan[start]["mode"]:
                end += 1
            chunk = plan[start:end]
            try:
                values = self._run_chunk(target, chunk, payload)
            except RemoteError as exc:
                if not self.keep_going:
                    raise
                values = [exc] * len(chunk)
            for item, value in zip(chunk, values):
                results[item["index"]] = value
            failed = next((v for v in values if isinstance(v, Exception)), None)
            if failed and not self.keep_going:
                raise failed
            start = end
        return results

    def _run_chunk(self, target, chunk, payload):
        become, connection, live = chunk[0]["mode"]
        unique, slots = [], []
        for item in chunk:
            if item["key"] not in [u["key"] for u in unique]:
                unique.append(item)
            slots.append([u["key"] for u in unique].index(item["key"]))
        steps = [{"name": str(i), "source": u["script"].source_path(), "args": u["args"],
                  "support": u["script"].support_paths(), "stdin": u["script"].stdin,
                  "timeout": u["script"].timeout} for i, u in enumerate(unique)]
        with tempfile.TemporaryDirectory(prefix="ccdc-archive-") as directory:
            path = Path(directory) / "bundle.pyz"
            archive.build(steps, path, self.keep_going)
            request = dict(become=become, connection=connection, payload=payload)
            if live:
                ok = self.runner.act_archive(target, path, **request)
                if not ok and not self.keep_going:
                    raise RemoteError("%s: Ansible run failed" % target)
                return [ok] * len(chunk)
            envelope = self.runner.archive(target, path, **request)
        done = {s["name"]: s for s in envelope.get("steps", [])}
        values = []
        for item, slot in zip(chunk, slots):
            result = done.get(str(slot))
            if result is None:
                values.append(RemoteError("%s: not run (an earlier step failed)" % item["script"].name))
                continue
            try:
                values.append(item["script"].parse(result, **item["kwargs"]))
            except (RemoteError, ValueError, KeyError, RuntimeError) as exc:
                values.append(exc if isinstance(exc, RemoteError) else RemoteError("%s: %s" % (item["script"].name, exc)))
        return values


class PlaybookScript(AnsibleScript):
    """An AnsibleScript whose source is a .yml, run with ansible-playbook (live, not bundled).

    Either `playbook` (a name under ccdc/ansible/playbooks) or `source` (a .yml beside the class).
    Keyword arguments become extra-vars.
    """
    playbook = None

    def run(self, target, **variables):
        name = self.source_path() if self.source else self.playbook
        return self.runner.playbook(target, name, variables)
