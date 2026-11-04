"""sshd_config problems are reported only: editing it can lock the team out."""
from ccdc.ansible import BundleScript
from ccdc.findings import AutoFix
from ccdc.scanners.ssh_vectors import RogueAuthorizedKey, SSHStartupScript, team_keys


class RemoveSSHStartupFile(BundleScript):
    """Remove sshrc / ~/.ssh/rc after copying it to /root/ir (the host script refuses anything else)."""
    entry = "fix_ssh_vectors"

    def arguments(self, path, **kwargs):
        return ["remove-file", path]


class RemoveAuthorizedKey(BundleScript):
    """Drop every line with this fingerprint from an authorized_keys file, keeping a backup in /root/ir."""
    entry = "fix_ssh_vectors"

    def arguments(self, path, fingerprint, allow_keys=(), **kwargs):
        return ["remove-key", path, fingerprint, *[a for key in allow_keys for a in ("--allow-key", key)]]


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
