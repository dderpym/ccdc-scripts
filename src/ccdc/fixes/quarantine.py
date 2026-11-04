from ccdc.findings import AutoFix
from ccdc.scanners.unowned import TimestompedFile, UnitRunsUnownedBinary, UnownedExecutable
from scripts.fix.quarantine import Quarantine


def paths(finding):
    if isinstance(finding, UnitRunsUnownedBinary):
        return [finding.unit, finding.binary]
    return [finding.file]


class QuarantineUnowned(AutoFix):
    """Critical findings only; a package-owned unit is never deleted."""

    def can_fix(self, finding):
        if isinstance(finding, UnitRunsUnownedBinary):
            return not finding.unit_owned and finding.severity == "critical"
        return isinstance(finding, (UnownedExecutable, TimestompedFile)) and finding.severity == "critical"

    def get_fix(self, finding):
        return Quarantine().bind(target=finding.host, paths=paths(finding))

    def describe(self, finding):
        return "quarantine (evidence copy, kill, delete): " + ", ".join(paths(finding))
