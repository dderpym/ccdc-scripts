from dataclasses import dataclass

from ccdc.findings import BundleScanner, Finding


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


class PathShadowScanner(BundleScanner):
    cheap = True  # live and quick: eligible for the rescan guard\'s fast poll
    entry = "scan_path_shadow"

    def findings(self, target, row):
        return [PathShadowing(target, row["name"], tuple(row["paths"]), tuple(row["unowned"]))]
