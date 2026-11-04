from dataclasses import dataclass

from ccdc.findings import Finding
from ccdc.scanners.lse import LSEScanner, evidence_lines


@dataclass(frozen=True)
class ExtraUidZeroAccount(Finding):
    account: str
    code = "extra-uid-zero-account"
    severity = "critical"

    @property
    def summary(self):
        return f"account {self.account} has UID 0"


class AccountScanner(LSEScanner):
    tests = ("sys020", "sys022", "sys030", "sys040")

    def typed(self, target, row):
        if row["id"] != "sys040":
            return None
        return [ExtraUidZeroAccount(target, line.split(":", 1)[0]) for line in evidence_lines(row)]
