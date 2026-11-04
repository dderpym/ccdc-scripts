from ccdc.findings import AutoFix
from ccdc.scanners.sudoers import SudoersGrant
from ccdc.scripts.sudoers import RemoveSudoersLine


class FixSudoersGrant(AutoFix):
    def can_fix(self, finding):
        return isinstance(finding, SudoersGrant)

    def get_fix(self, finding):
        return RemoveSudoersLine().bind(target=finding.host, file=finding.file, text=finding.text)

    def describe(self, finding):
        return f"remove '{finding.text}' from {finding.file} (visudo-validated, original kept in /root/ir)"
