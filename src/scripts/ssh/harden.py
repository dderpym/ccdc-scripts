"""SSH phase: harden sshd without risking a lock-out."""
from ccdc.ansible import AnsibleScript
from ccdc.target import Auth, Target


class FreshLogin(Auth):
    """Wraps another Auth but forbids connection reuse, so a login really is new."""

    def __init__(self, base):
        self.base = base

    def variables(self):
        variables = dict(self.base.variables())
        variables["ansible_ssh_args"] = (variables.get("ansible_ssh_args", "")
                                         + " -o ControlMaster=no -o ControlPath=none -o ForwardAgent=no").strip()
        return variables


class HardenSSHD(AnsibleScript):
    """Apply the sshd drop-in, prove a fresh key login still works, then cancel the on-host revert.

    If the login fails, the host's watchdog removes the drop-in by itself; we also
    ask for an immediate revert when the host is still reachable.
    """

    def run(self, target, **kwargs):
        applied = self.runner.entry(target, "fix_sshd_hardening", ["apply"])
        fresh = Target(target.host, FreshLogin(target.auth))
        try:
            self.runner.entry(fresh, "detect_os", [], become=False)
        except Exception as exc:
            try:
                self.runner.entry(target, "fix_sshd_hardening", ["revert"])
            except Exception:
                pass  # the on-host watchdog still reverts
            raise RuntimeError(f"fresh login failed after hardening; reverted: {exc}") from exc
        self.runner.entry(target, "fix_sshd_hardening", ["confirm"])
        return applied

