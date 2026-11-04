"""PAM repair steps and the password-rotation gate."""
from ccdc.ansible import BundleScript
from ccdc.osinfo import DetectOS
from ccdc.scanners.pam import PamScanner
from ccdc.script import ComposedScript, Script, Step

MANAGERS = {"debian": "apt", "rhel": "dnf", "suse": "zypper"}


class PamDirty(RuntimeError):
    pass


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


class PamGate(Script):
    """Refuse to continue while the ACTIVE PAM stack (as resolved on the host, plus loaded modules) is dirty.

    Password changes (chpasswd) run through PAM, so a pam_exec expose_authtok hook sees
    every rotated password. Anything rotated before the stack was clean must be rotated again.
    """

    def __init__(self, runner=None):
        self.scanner = PamScanner(runner)

    def run(self, target):
        result = self.scanner.run(target)
        # A stack that cannot be resolved (missing include, loop) is unknown, not clean.
        unknown = [e for e in result.errors if "PAM include" in e or "cannot read PAM" in e]
        if result or unknown:
            raise PamDirty(f"{target}: PAM stack is not clean; refusing to proceed. Passwords set while "
                           "a hook was live are exposed and must be rotated again after cleanup.\n"
                           + "\n".join("  " + f.summary for f in result)
                           + "".join("\n  unresolved: " + e for e in unknown))
        return result


def gated(script, runner=None):
    """`script` preceded by a PamGate: run(target, ...) only gets past the gate on a clean host."""
    return ComposedScript(PamGate(runner), script)
