from ccdc.ansible import AnsibleScript
from ccdc.findings import AutoFix
from ccdc.scanners.sudoers import SudoGrant


class RemoveSudoersGrant(AnsibleScript):
    """Remove the sudoers line(s) behind a live `sudo -l` grant, validated by visudo, original kept in /root/ir."""
    source = "remote.py"

    def arguments(self, user, rule, file="", line=0, **kwargs):
        return ["--locate", user, rule, "--file", file, "--line", str(line)]


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
