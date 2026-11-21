from dataclasses import dataclass

from ccdc.scanners.lse import LSEScanner
from ccdc.findings import Finding


@dataclass(frozen=True)
class PasswordlessSudo(Finding):
    """The scanning account can sudo without a password. Note: expected for oski (LSE drops it there)."""
    evidence: tuple = ()
    code = "passwordless-sudo"
    severity = "critical"

    @property
    def summary(self):
        return "account can run sudo without a password"


class SudoScanner(LSEScanner):
    tests = ("sud000",)

    def typed(self, target, row):
        return [PasswordlessSudo(target, tuple(l for c in row.get("context", []) for l in c.get("evidence", [])))]
