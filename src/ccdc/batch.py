"""One AnsibleScript on MANY hosts in a single Ansible batch.

BundleScript.run takes one Target per call. Reads such as `ccdcctl listeners all` want every
host in one batch (Ansible's forks run them in parallel), with an unreachable or failing host
reported per host instead of failing the batch.
"""
from pathlib import Path
import tempfile

from ccdc import runner
from ccdc.ansible import archive
from ccdc.runner import RemoteError


def collect(script, hosts, run=None, payload=None, **kwargs):
    """({host: script.parse(result)}, {host: error text}); `script` is an AnsibleScript instance.

    Keyword arguments reach script.arguments/parse exactly as in AnsibleScript.run. Successful
    hosts are kept even when others fail. `run` replaces runner.run_ansible (ccdcctl passes its own).
    """
    merged = {**script.params, **kwargs}
    step = {"name": "0", "source": script.source_path(), "args": script.argv(**kwargs),
            "support": script.support_paths(), "stdin": script.stdin, "timeout": script.timeout}
    with tempfile.TemporaryDirectory(prefix="ccdc-archive-") as directory:
        path = Path(directory) / "bundle.pyz"
        archive.build([step], path, keep_going=True)
        envelopes, errors = runner.collect(hosts, None, (), None, run=run or runner.run_ansible, archive=path,
                                           become=script.become, connection=script.connection, payload=payload)
    states = {}
    for host, envelope in envelopes.items():
        try:
            result = envelope["steps"][0]
            states[host] = script.parse(result, **merged)
        except (RemoteError, ValueError, KeyError, IndexError) as exc:
            errors[host] = str(exc)
    return states, errors
