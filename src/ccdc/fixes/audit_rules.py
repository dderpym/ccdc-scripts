from ccdc.ansible import EntryScript
from ccdc.findings import AutoFix
from ccdc.packages import InstallAuditd
from ccdc.scanners.audit_rules import AuditWatchMissing
from ccdc.script import ComposedScript, Step


class InstallAuditRules(EntryScript):
    entry = "install_audit_rules"


class EnableAuditWatches(ComposedScript):
    """Install auditd for this OS, then the persistence-path watch rules."""

    def __init__(self, runner=None):
        super().__init__(Step(InstallAuditd(runner)), Step(InstallAuditRules(runner)))


class FixAuditWatches(AutoFix):
    def can_fix(self, finding):
        return isinstance(finding, AuditWatchMissing)

    def get_fix(self, finding):
        return EnableAuditWatches().bind(target=finding.host)

    def describe(self, finding):
        return f"install auditd and its watch rules (covers {finding.path})"
