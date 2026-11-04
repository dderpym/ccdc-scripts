"""Sudo as active on the host: what `sudo -l` grants each account, and whether the config is valid."""
from dataclasses import dataclass

from ccdc.ansible import AnsibleScript
from ccdc.findings import Finding, Scanner


@dataclass(frozen=True)
class SudoGrant(Finding):
    """A grant sudo really applies to `user`, wherever it is defined (files, groups, sssd/LDAP).

    `file`/`line` are what `sudo -l -l` reports for the rule, "" and 0 when this sudo
    does not say; the fix then locates the line among the files `visudo -c` loads.
    """
    user: str
    rule: str
    nopasswd: bool
    file: str = ""
    line: int = 0

    @property
    def where(self):
        return f" ({self.file}:{self.line})" if self.file else ""


@dataclass(frozen=True)
class SudoGrantsEveryone(SudoGrant):
    """Even `nobody` is granted this, so an ALL/%ALL rule is active."""
    code = "sudo-grants-everyone"
    severity = "critical"

    @property
    def summary(self):
        how = "passwordless " if self.nopasswd else ""
        return f"everyone has {how}sudo: {self.rule}{self.where}"


@dataclass(frozen=True)
class UnexpectedSudoGrant(SudoGrant):
    """ALL commands, or any NOPASSWD, for an account other than the team's."""
    code = "unexpected-sudo-grant"
    severity = "critical"

    @property
    def summary(self):
        how = "passwordless " if self.nopasswd else ""
        return f"{self.user} has {how}sudo: {self.rule}{self.where}"


@dataclass(frozen=True)
class SudoersInvalid(Finding):
    detail: str
    code = "sudoers-invalid"
    severity = "critical"

    @property
    def summary(self):
        return "visudo -c rejects the active sudo configuration: " + self.detail.replace("\n", "; ")[:200]


class ScanSudoers(AnsibleScript):
    """Prints {"findings": [grant/world/invalid rows], "errors": [...]}: visudo -c plus sudo -l -U per account."""
    source = "remote.py"


class SudoersScanner(Scanner):
    def remote_step(self, target):
        return ScanSudoers(self.runner)

    KINDS = {"world": SudoGrantsEveryone, "grant": UnexpectedSudoGrant}

    def findings(self, target, row):
        if row["kind"] == "invalid":
            return [SudoersInvalid(target, row["detail"])]
        return [self.KINDS[row["kind"]](target, row["user"], row["rule"], row["nopasswd"],
                                        row.get("file", ""), row.get("line", 0))]
