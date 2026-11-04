from dataclasses import dataclass

from ccdc.findings import BundleScanner, Finding


@dataclass(frozen=True)
class UnownedCapabilityBinary(Finding):
    path: str
    capabilities: str
    code = "unowned-capability-binary"
    severity = "critical"

    @property
    def summary(self):
        return f"unowned binary {self.path} has file capabilities {self.capabilities}"


class CapBinaryScanner(BundleScanner):
    entry = "scan_cap_binaries"

    def findings(self, target, row):
        return [UnownedCapabilityBinary(target, row["path"], row["capabilities"])]
