from ccdc.ansible import BundleScript


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
