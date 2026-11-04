from ccdc.ansible import BundleScript


class RemoveSudoersGrant(BundleScript):
    """Remove the sudoers line(s) behind a live `sudo -l` grant, validated by visudo, original kept in /root/ir."""
    entry = "fix_sudoers"

    def arguments(self, user, rule, file="", line=0, **kwargs):
        return ["--locate", user, rule, "--file", file, "--line", str(line)]
