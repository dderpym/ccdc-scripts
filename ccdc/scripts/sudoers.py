from ccdc.ansible import BundleScript


class RemoveSudoersLine(BundleScript):
    """Delete a line from a sudoers file, validated by visudo, original kept in /root/ir."""
    entry = "fix_sudoers"

    def arguments(self, file, text, **kwargs):
        return [file, text]
