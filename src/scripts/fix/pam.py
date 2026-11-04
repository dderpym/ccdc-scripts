"""Remediation: remove PAM hooks and restore the distribution modules."""
from ccdc.ansible import BundleScript
from ccdc.osinfo import DetectOS
from ccdc.script import Script

MANAGERS = {"debian": "apt", "rhel": "dnf", "suse": "zypper"}



class RemovePamLine(BundleScript):
    """Delete a rule (and optionally its payload file) from a /etc/pam.d file, with backup."""
    entry = "fix_pam"

    def arguments(self, file, line, payload="", **kwargs):
        return ["remove-line", file, line, *(["--payload", payload] if payload else [])]


class RemovePamFile(BundleScript):
    entry = "fix_pam"

    def arguments(self, path, **kwargs):
        return ["remove-file", path]


class _Reinstall(BundleScript):
    entry = "fix_pam"

    def arguments(self, manager, **kwargs):
        return ["reinstall", manager]


class ReinstallPam(Script):
    """Reinstall the PAM packages with the native manager, chosen by OS detection each run."""

    def __init__(self, runner=None):
        self.runner = runner

    def run(self, target):
        family = DetectOS(self.runner).run(target).family
        if family not in MANAGERS:
            raise RuntimeError(f"cannot reinstall PAM on {family} hosts")
        return _Reinstall(self.runner).run(target, manager=MANAGERS[family])

