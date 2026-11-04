#!/usr/bin/env python3
"""Runs on the target as the __main__ of an archive built by ccdc.ansible.archive.

Reads manifest.json, extracts every step into a private 0700 directory, runs the steps
in order and prints ONE JSON envelope {"steps": [{name, rc, stdout, stderr}, ...]}.
Standard library only, python3.9 compatible.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile


def interpreter(path):
    """The shebang's command, so a noexec scratch directory cannot stop a step; sh otherwise."""
    with open(path, "rb") as handle:
        first = handle.readline(256).decode("utf-8", "replace")
    return first[2:].split() if first.startswith("#!") and first[2:].split() else ["/bin/sh"]


def text(data):
    return data.decode("utf-8", "replace")


def run_step(step, work, env, payload):
    path = os.path.join(work, step["file"])
    stdin = subprocess.DEVNULL
    handle = None
    if step.get("stdin") and payload:
        handle = stdin = open(payload, "rb")
    try:
        result = subprocess.run(interpreter(path) + [path] + step["args"], stdin=stdin, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=env, cwd=work, timeout=step.get("timeout") or 300)
        return {"name": step["name"], "rc": result.returncode, "stdout": text(result.stdout),
                "stderr": text(result.stderr)}
    except subprocess.TimeoutExpired:
        return {"name": step["name"], "rc": 124, "stdout": "", "stderr": "timed out"}
    except OSError as exc:
        return {"name": step["name"], "rc": 127, "stdout": "", "stderr": "cannot run step: %s" % exc}
    finally:
        if handle:
            handle.close()


def main():
    payload = os.environ.pop("CCDC_PAYLOAD", None)
    work = tempfile.mkdtemp(prefix="ccdc-")  # mode 0700
    try:
        with zipfile.ZipFile(os.path.abspath(sys.argv[0])) as archive:
            manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
            archive.extractall(work, [n for n in archive.namelist() if n.startswith(("steps/", "lib/"))])
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
                   PYTHONPATH=os.pathsep.join(filter(None, [os.path.join(work, "lib"), os.environ.get("PYTHONPATH")])))
        results = []
        for step in manifest["steps"]:
            results.append(run_step(step, work, env, payload))
            if results[-1]["rc"] != 0 and not manifest.get("keep_going", True):
                break
        print(json.dumps({"steps": results}))
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
