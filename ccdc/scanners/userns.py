from dataclasses import dataclass

from ccdc.findings import Finding
from ccdc.scanners.lse import LSEScanner


@dataclass(frozen=True)
class UnprivilegedUserNamespaces(Finding):
    sysctls: tuple  # names that should be 0
    code = "unprivileged-userns"

    @property
    def summary(self):
        return "unprivileged user namespaces enabled (" + ", ".join(self.sysctls) + ")"


class UserNamespaceScanner(LSEScanner):
    tests = ("ns-unprivileged-userns",)

    def typed(self, target, row):
        names = sorted({n for fix in row.get("fixes", []) if fix.get("kind") == "sysctl" for n in fix["settings"]})
        return [UnprivilegedUserNamespaces(target, tuple(names))] if names else []
