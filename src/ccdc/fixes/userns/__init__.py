from ccdc.ansible import AnsibleScript
from ccdc.findings import AutoFix
from ccdc.scanners.userns import UnprivilegedUserNamespaces


class DisableSysctls(AnsibleScript):
    """Set allow-listed sysctls to 0, live and persisted."""
    source = "remote.py"
    support = ("sysctls.py",)

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
