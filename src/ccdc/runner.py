"""The only place that spawns Ansible. Everything else asks this module."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

from controller import remote

VERBOSE = False  # set by ccdcctl --verbose: full Ansible logs instead of the progress UI
ROOT = Path(__file__).resolve().parents[2]
ANSIBLE = Path(__file__).resolve().parent / "ansible"
PLAYBOOKS = ANSIBLE / "playbooks"


def extra_args():
    return shlex.split(os.environ.get("ANSIBLE_ARGS", ""))


def run_ansible(args, capture=True, result_dir=None, result_task=None, verbose=None):
    verbose = VERBOSE if verbose is None else verbose
    env = dict(os.environ, ANSIBLE_CONFIG=str(ANSIBLE / "ansible.cfg"), ANSIBLE_NOCOLOR="1")
    if not capture and not verbose:
        env.update(ANSIBLE_STDOUT_CALLBACK="ccdc_progress", ANSIBLE_LOAD_CALLBACK_PLUGINS="1",
                   ANSIBLE_CALLBACKS_ENABLED="ccdc_results")
    if result_dir:
        env.update(CCDC_RESULT_DIR=result_dir, ANSIBLE_LOAD_CALLBACK_PLUGINS="1",
                   ANSIBLE_CALLBACKS_ENABLED="ccdc_results")
    else:
        env.pop("CCDC_RESULT_DIR", None)
    if result_task:
        env["CCDC_RESULT_TASK"] = result_task
    else:
        env.pop("CCDC_RESULT_TASK", None)
    return subprocess.run(args, cwd=ROOT, env=env, text=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None, check=False)


def with_vars(args, variables, run=run_ansible, **kwargs):
    """Secrets travel in a private 0600 file, never argv or the console log."""
    with tempfile.NamedTemporaryFile(mode="w", prefix="ccdc-vars-", suffix=".json") as out:
        json.dump(variables, out)
        out.flush()
        os.fsync(out.fileno())
        return run([*args, "--extra-vars", "@" + out.name], **kwargs)


def _failure(response, result):
    # SSH script tasks use a PTY: the script's stderr can land in stdout.
    for stream in ("stdout", "stderr"):
        try:
            document = json.loads(response.get(stream) or "")
        except ValueError:
            continue
        if isinstance(document, dict) and isinstance(document.get("error"), str):
            return document["error"]
    return ("\n".join(response[key].strip() for key in ("stdout", "stderr") if response.get(key))
            or response.get("msg") or "remote command failed")


def collect(hosts, entry, args=(), variables=None, run=run_ansible, **request):
    """One Ansible batch running a bundle entry; (states, errors) keyed by host.

    Successful hosts are kept even when another is unreachable. `variables` are
    connection overrides (see ccdc.target.Auth); `request` goes to remote.request.
    """
    with tempfile.TemporaryDirectory(prefix="ccdc-results-") as directory:
        command = ["ansible-playbook", str(PLAYBOOKS / "remote.yml"), "--limit", ":".join(hosts), *extra_args(),
                   "--extra-vars", remote.request(entry, args, **request)]
        if variables:
            result = with_vars(command, variables, run, result_dir=directory, result_task=remote.TASK)
        else:
            result = run(command, result_dir=directory, result_task=remote.TASK)
        states, errors = {}, {}
        for host in hosts:
            try:
                response = json.loads((Path(directory) / host).read_text())
                if response.get("unreachable") or response.get("failed") or response.get("rc", 0):
                    raise ValueError(_failure(response, result))
                states[host] = json.loads(response["stdout"])
            except FileNotFoundError:
                errors[host] = result.stderr.strip() or result.stdout.strip() or "No Ansible result"
            except (OSError, ValueError, KeyError) as exc:
                errors[host] = str(exc)
        return states, errors


class RemoteError(RuntimeError):
    pass


class AnsibleRunner:
    """Runs bundle entries and playbooks on one Target. Tests substitute a fake.

    Target.host is passed to --limit, so it may be a pattern such as 'all' or 'a:b'.
    """

    def entry(self, target, entry, args=(), **request):
        """Captured run of a bundle entry; returns its parsed JSON stdout."""
        states, errors = collect([target.host], entry, args, target.auth.variables(), **request)
        if target.host in errors:
            raise RemoteError(f"{target.host}: {errors[target.host]}")
        return states[target.host]

    def act(self, target, entry, args=(), **request):
        """Live (progress UI) run of a mutating bundle entry; True when Ansible succeeded."""
        command = ["ansible-playbook", str(PLAYBOOKS / "remote.yml"), "--limit", target.host, *extra_args(),
                   "--extra-vars", remote.request(entry, args, **request)]
        return self._live(command, target.auth.variables()).returncode == 0

    def playbook(self, target, name, variables=None):
        command = ["ansible-playbook", str(PLAYBOOKS / f"{name}.yml"), "--limit", target.host, *extra_args()]
        if not self._live(command, {**target.auth.variables(), **(variables or {})}).returncode:
            return True
        raise RemoteError(f"{target.host}: playbook {name} failed")

    @staticmethod
    def _live(command, variables):
        if variables:
            return with_vars(command, variables, capture=False)
        return run_ansible(command, capture=False)
