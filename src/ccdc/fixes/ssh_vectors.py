"""sshd_config problems are reported only: editing it can lock the team out."""
from ccdc.findings import AutoFix
from ccdc.scanners.ssh_vectors import RogueAuthorizedKey, SSHStartupScript, team_keys
from ccdc.scripts.ssh_vectors import RemoveAuthorizedKey, RemoveSSHStartupFile


class FixSSHStartupScript(AutoFix):
    def can_fix(self, finding):
        return isinstance(finding, SSHStartupScript)

    def get_fix(self, finding):
        return RemoveSSHStartupFile().bind(target=finding.host, path=finding.path)

    def describe(self, finding):
        return f"remove {finding.path} (backup in /root/ir)"


class FixRogueAuthorizedKey(AutoFix):
    def can_fix(self, finding):
        return isinstance(finding, RogueAuthorizedKey)

    def get_fix(self, finding):
        return RemoveAuthorizedKey().bind(target=finding.host, path=finding.file,
                                          fingerprint=finding.fingerprint, allow_keys=team_keys())

    def describe(self, finding):
        return f"remove key {finding.fingerprint} from {finding.file} (backup in /root/ir)"
