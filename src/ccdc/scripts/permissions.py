from ccdc.ansible import BundleScript


class SetPermissions(BundleScript):
    """Clear mode bits (octal string) and optionally chown to root:root."""
    entry = "fix_permissions"

    def arguments(self, path, clear="0", root=False, **kwargs):
        return [path, "--clear", clear, *(["--root"] if root else [])]
