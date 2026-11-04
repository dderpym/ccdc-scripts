from ccdc.ansible import BundleScript


class Quarantine(BundleScript):
    """Evidence copy, freeze, kill and delete of binaries/units (host/fix_quarantine.py)."""
    entry = "fix_quarantine"

    def arguments(self, paths=(), **kwargs):
        return list(paths)
