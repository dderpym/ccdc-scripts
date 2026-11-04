from ccdc.findings import AutoFix
from ccdc.scanners.sudoers import SudoGrant
from ccdc.scripts.sudoers import RemoveSudoersGrant


class FixSudoGrant(AutoFix):
    def can_fix(self, finding):
        return isinstance(finding, SudoGrant)

    def get_fix(self, finding):
        return RemoveSudoersGrant().bind(target=finding.host, user=finding.user, rule=finding.rule,
                                         file=finding.file, line=finding.line)

    def describe(self, finding):
        return (f"remove the sudoers line granting '{finding.rule}' to {finding.user}"
                + (f" at {finding.file}:{finding.line}" if finding.file else "")
                + " (visudo-validated, original kept in /root/ir)")
