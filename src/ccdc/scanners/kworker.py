from dataclasses import dataclass

from ccdc.findings import BundleScanner, Finding


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


class KworkerScanner(BundleScanner):
    cheap = True  # live and quick: eligible for the rescan guard\'s fast poll
    entry = "scan_kworker"

    def findings(self, target, row):
        return [FakeKernelThread(target, row["pid"], row["comm"], row["exe"])]
