"""sshd_config problems are reported only: editing it can lock the team out."""
from ccdc.ansible import AnsibleScript
from ccdc.findings import AutoFix
from ccdc.scanners.ssh_vectors import RogueAuthorizedKey, SSHStartupScript, team_keys


class RemoveSSHStartupFile(AnsibleScript):
    """Remove sshrc / ~/.ssh/rc after copying it to /root/ir (remote.py refuses anything else)."""
    source = "remote.py"
    support = ("sshkeys.py",)

    def arguments(self, path, **kwargs):
        return ["remove-file", path]


class RemoveAuthorizedKey(AnsibleScript):
    """Drop every line with this fingerprint from an authorized_keys file, keeping a backup in /root/ir."""
    source = "remote.py"
    support = ("sshkeys.py",)

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
