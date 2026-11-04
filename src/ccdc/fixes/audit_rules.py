from ccdc.findings import AutoFix
from ccdc.scanners.audit_rules import AuditWatchMissing
from ccdc.scripts.audit import EnableAuditWatches


class FixAuditWatches(AutoFix):
    def can_fix(self, finding):
        return isinstance(finding, AuditWatchMissing)

    def get_fix(self, finding):
        return EnableAuditWatches().bind(target=finding.host)

    def describe(self, finding):
        return f"install auditd and its watch rules (covers {finding.path})"
