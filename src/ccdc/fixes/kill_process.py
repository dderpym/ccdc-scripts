from ccdc.ansible import BundleScript
from ccdc.findings import AutoFix
from ccdc.scanners.kworker import FakeKernelThread
from ccdc.scanners.memfd import MemfdProcess


class KillProcess(BundleScript):
    """SIGSTOP then SIGKILL; the host re-checks that the PID still matches `kind`."""
    entry = "fix_kill_process"

    def arguments(self, pid, kind, **kwargs):
        return [str(pid), kind]


class KillSuspiciousProcess(AutoFix):
    def can_fix(self, finding):
        return isinstance(finding, (MemfdProcess, FakeKernelThread))

    def get_fix(self, finding):
        kind = "memfd" if isinstance(finding, MemfdProcess) else "kworker"
        return KillProcess().bind(target=finding.host, pid=finding.pid, kind=kind)

    def describe(self, finding):
        return f"freeze and kill pid {finding.pid} ({finding.exe})"
