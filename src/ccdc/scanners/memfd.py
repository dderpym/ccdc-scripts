from dataclasses import dataclass

from ccdc.findings import BundleScanner, Finding


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


class MemfdScanner(BundleScanner):
    cheap = True  # live and quick: eligible for the rescan guard\'s fast poll
    entry = "scan_memfd"

    def findings(self, target, row):
        return [MemfdProcess(target, row["pid"], row["exe"], row["comm"], row["cmdline"], row["kind"])]
