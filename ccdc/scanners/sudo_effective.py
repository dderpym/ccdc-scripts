"""Effective sudo privileges per `sudo -l -U`, from every source sudo consults."""
from dataclasses import dataclass

from ccdc.findings import BundleScanner, Finding


@dataclass(frozen=True)
class EffectiveSudoGrant(Finding):
    """A grant sudo really applies to `user`, wherever it is defined (files, groups, sssd/LDAP).

    Report-only: when the grant lives in a sudoers file the static scanner reports the
    same grant as SudoersWorldGrant/SudoersUnexpectedNopasswd and owns the fix.
    """
    user: str
    rule: str
    nopasswd: bool
    code = "effective-sudo-grant"
    severity = "critical"

    @property
    def summary(self):
        how = "passwordless " if self.nopasswd else ""
        return f"{self.user} has {how}sudo per sudo -l: {self.rule}"


class SudoEffectiveScanner(BundleScanner):
    entry = "scan_sudo_effective"

    def findings(self, target, row):
        return [EffectiveSudoGrant(target, row["user"], row["rule"], row["nopasswd"])]
