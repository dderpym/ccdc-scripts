from dataclasses import dataclass

from ccdc.ansible import AnsibleScript
from ccdc.findings import Finding, Scanner


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


class ScanAuditRules(AnsibleScript):
    """Prints {"findings": [{"watch"} | {"disabled"}], "errors": [...]} from the LOADED rules (auditctl -l / -s)."""
    source = "remote.py"
    support = ("audit_watches.py",)


class AuditRulesScanner(Scanner):
    def remote_step(self, target):
        return ScanAuditRules(self.runner)

    def findings(self, target, row):
        if row.get("disabled"):
            return [AuditDisabled(target)]
        return [AuditWatchMissing(target, row["watch"])]
