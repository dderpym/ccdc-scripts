from dataclasses import dataclass

from ccdc.ansible import AnsibleScript
from ccdc.findings import Finding, Scanner


@dataclass(frozen=True)
class UnownedCapabilityBinary(Finding):
    path: str
    capabilities: str
    code = "unowned-capability-binary"
    severity = "critical"

    @property
    def summary(self):
        return f"unowned binary {self.path} has file capabilities {self.capabilities}"


class ScanCapBinaries(AnsibleScript):
    """remote.py prints {"findings": [{path, capabilities}], "errors": [...]}."""
    source = "remote.py"
    support = ("pkgowner.py",)


class CapBinaryScanner(Scanner):
    def remote_step(self, target):
        return ScanCapBinaries(self.runner)

    def findings(self, target, row):
        return [UnownedCapabilityBinary(target, row["path"], row["capabilities"])]
