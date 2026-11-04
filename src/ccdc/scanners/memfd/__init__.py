"""Processes running fileless (exe -> /memfd:...) or from a deleted file outside system dirs."""
from dataclasses import dataclass

from ccdc.ansible import AnsibleScript
from ccdc.findings import Finding, Scanner


@dataclass(frozen=True)
class MemfdProcess(Finding):
    pid: int
    exe: str
    comm: str
    cmdline: str
    kind: str  # "memfd" or "deleted"
    code = "memfd-process"
    severity = "critical"

    @property
    def summary(self):
        what = "runs fileless from memory" if self.kind == "memfd" else "runs from a deleted file"
        return f"process {self.comm} (pid {self.pid}) {what}: {self.exe}"


class ScanMemfd(AnsibleScript):
    """Prints {"findings": [process rows with kind], "errors": []}; --proc DIR reads a fixture tree."""
    source = "remote.py"
    support = ("procfs.py", "processes.py")

    def arguments(self, proc=None, **kwargs):
        return ["--proc", proc] if proc else []


class MemfdScanner(Scanner):
    def __init__(self, runner=None, proc=None):
        super().__init__(runner)
        self.proc = proc

    def remote_step(self, target):
        return ScanMemfd(self.runner, proc=self.proc)

    def findings(self, target, row):
        return [MemfdProcess(target, row["pid"], row["exe"], row["comm"], row["cmdline"], row["kind"])]
