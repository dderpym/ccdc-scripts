from ccdc.ansible import BundleScript
from ccdc.packages import InstallAuditd
from ccdc.script import ComposedScript, Step


class InstallAuditRules(BundleScript):
    entry = "install_audit_rules"


class EnableAuditWatches(ComposedScript):
    """Install auditd for this OS, then the persistence-path watch rules."""

    def __init__(self, runner=None):
        super().__init__(Step(InstallAuditd(runner)), Step(InstallAuditRules(runner)))
