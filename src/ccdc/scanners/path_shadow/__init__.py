from dataclasses import dataclass

from ccdc.ansible import AnsibleScript
from ccdc.findings import Finding, Scanner


@dataclass(frozen=True)
class PathShadowing(Finding):
    name: str
    paths: tuple
    unowned: tuple
    code = "path-shadowing"
    severity = "critical"

    @property
    def summary(self):
        return f"{self.name} exists at {', '.join(self.paths)}; not package-owned: {', '.join(self.unowned)}"


class ScanPathShadow(AnsibleScript):
    """remote.py prints {"findings": [{name, paths, unowned}], "errors": [...]}."""
    source = "remote.py"
    support = ("pkgowner.py",)


class PathShadowScanner(Scanner):
    def remote_step(self, target):
        return ScanPathShadow(self.runner)

    def findings(self, target, row):
        return [PathShadowing(target, row["name"], tuple(row["paths"]), tuple(row["unowned"]))]
