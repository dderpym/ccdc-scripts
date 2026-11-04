from dataclasses import dataclass

from ccdc.findings import BundleScanner, Finding


@dataclass(frozen=True)
class AuditWatchMissing(Finding):
    path: str
    code = "audit-watch-missing"

    @property
    def summary(self):
        return f"auditd is not watching {self.path}"


class AuditRulesScanner(BundleScanner):
    entry = "scan_audit_rules"

    def findings(self, target, row):
        return [AuditWatchMissing(target, row["watch"])]
