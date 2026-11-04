"""SSH phase: bring sshd to the policy the inventory declares, without risking a lock-out."""
from ccdc.ansible import AnsibleScript
from ccdc.findings import AutoFix
from ccdc.scanners.ssh_vectors import SSHPolicyDeviation
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


class EnforceSSHSetting(AnsibleScript):
    """Write one declared sshd setting, prove a fresh key login still works, then cancel the on-host revert.

    If the login fails, the host's watchdog removes the drop-in by itself; we also
    ask for an immediate revert when the host is still reachable.
    """

    def run(self, target, option, value, **kwargs):
        applied = self.runner.entry(target, "fix_sshd_hardening", ["apply", f"{option}={value}"])
        fresh = Target(target.host, FreshLogin(target.auth))
        try:
            self.runner.entry(fresh, "detect_os", [], become=False)
        except Exception as exc:
            try:
                self.runner.entry(target, "fix_sshd_hardening", ["revert"])
            except Exception:
                pass  # the on-host watchdog still reverts
            raise RuntimeError(f"fresh login failed after setting {option}; reverted: {exc}") from exc
        self.runner.entry(target, "fix_sshd_hardening", ["confirm"])
        return applied


class EnforceSSHPolicy(AutoFix):
    """Set exactly the deviating option to the inventory's value; the key-login proof guards lock-outs."""

    def can_fix(self, finding):
        return isinstance(finding, SSHPolicyDeviation)

    def get_fix(self, finding):
        return EnforceSSHSetting().bind(target=finding.host, option=finding.option, value=finding.expected)

    def describe(self, finding):
        return (f"set sshd {finding.option} to {finding.expected} via 00-hardening.conf "
                "(sshd -t validated; auto-revert unless a fresh key login succeeds)")
