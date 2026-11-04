from dataclasses import dataclass

from ccdc.findings import BundleScanner, Finding


@dataclass(frozen=True)
class AuditWatchMissing(Finding):
    path: str
    code = "audit-watch-missing"

    @property
    def summary(self):
        return f"auditd is not watching {self.path}"


@dataclass(frozen=True)
class AuditDisabled(Finding):
    """Rules may be loaded, but the kernel is not auditing (`auditctl -s`: enabled 0)."""
    code = "audit-disabled"
    severity = "critical"

    @property
    def summary(self):
        return "kernel auditing is disabled; loaded watches record nothing"


class AuditRulesScanner(BundleScanner):
    cheap = True  # live and quick: eligible for the rescan guard\'s fast poll
    entry = "scan_audit_rules"

    def findings(self, target, row):
        if row.get("disabled"):
            return [AuditDisabled(target)]
        return [AuditWatchMissing(target, row["watch"])]
