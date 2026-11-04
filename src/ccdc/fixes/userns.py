from ccdc.ansible import EntryScript
from ccdc.findings import AutoFix
from ccdc.scanners.userns import UnprivilegedUserNamespaces


class DisableSysctls(EntryScript):
    """Set allow-listed sysctls to 0, live and persisted."""
    entry = "fix_sysctl"

    def arguments(self, names=(), **kwargs):
        return list(names)


class DisableUserNamespaces(AutoFix):
    def can_fix(self, finding):
        return isinstance(finding, UnprivilegedUserNamespaces)

    def get_fix(self, finding):
        return DisableSysctls().bind(target=finding.host, names=list(finding.sysctls))

    def describe(self, finding):
        return ("set " + ", ".join(finding.sysctls) + " to 0, persisted "
                "(breaks rootless containers and browser sandboxes)")
