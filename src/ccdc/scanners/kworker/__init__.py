"""Fake kernel threads: a kernel-thread name whose /proc/PID/exe resolves (real ones have none)."""
from dataclasses import dataclass

from ccdc.ansible import AnsibleScript
from ccdc.findings import Finding, Scanner


@dataclass(frozen=True)
class FakeKernelThread(Finding):
    pid: int
    comm: str
    exe: str
    code = "fake-kernel-thread"
    severity = "critical"

    @property
    def summary(self):
        return f"{self.comm} (pid {self.pid}) poses as a kernel thread but runs {self.exe}"


class ScanKworker(AnsibleScript):
    """Prints {"findings": [process rows], "errors": []}; --proc DIR reads a fixture tree."""
    source = "remote.py"
    support = ("procfs.py", "processes.py")

    def arguments(self, proc=None, **kwargs):
        return ["--proc", proc] if proc else []


class KworkerScanner(Scanner):
    def __init__(self, runner=None, proc=None):
        super().__init__(runner)
        self.proc = proc

    def remote_step(self, target):
        return ScanKworker(self.runner, proc=self.proc)

    def findings(self, target, row):
        return [FakeKernelThread(target, row["pid"], row["comm"], row["exe"])]
