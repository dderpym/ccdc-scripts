from ccdc.ansible import AnsibleScript
from ccdc.findings import AutoFix
from ccdc.scanners.kworker import FakeKernelThread
from ccdc.scanners.memfd import MemfdProcess


class KillProcess(AnsibleScript):
    """SIGSTOP then SIGKILL; the target re-checks that the PID still matches `kind` (memfd|kworker)."""
    source = "remote.py"
    support = ("procfs.py", "processes.py")

    def arguments(self, pid, kind, proc=None, **kwargs):
        return [str(pid), kind, *(["--proc", proc] if proc else [])]


class KillSuspiciousProcess(AutoFix):
    def can_fix(self, finding):
        return isinstance(finding, (MemfdProcess, FakeKernelThread))

    def get_fix(self, finding):
        kind = "memfd" if isinstance(finding, MemfdProcess) else "kworker"
        return KillProcess().bind(target=finding.host, pid=finding.pid, kind=kind)

    def describe(self, finding):
        return f"freeze and kill pid {finding.pid} ({finding.exe})"
