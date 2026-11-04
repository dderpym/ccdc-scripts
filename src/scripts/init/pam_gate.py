"""Init phase: never rotate passwords through a PAM stack that captures them."""
from ccdc.scanners.pam import PamScanner
from ccdc.script import ComposedScript, Script


class PamDirty(RuntimeError):
    pass


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

