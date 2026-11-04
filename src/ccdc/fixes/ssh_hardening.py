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


# Turning these off only is safe if key login works, so it is proven before AND after.
LOCKOUT_RISK = {("passwordauthentication", "no"), ("permitrootlogin", "no"), ("pubkeyauthentication", "no")}


class EnforceSSHSettings(AnsibleScript):
    """Write every given sshd setting as ONE change, prove a fresh key login still works, then confirm.

    The host script verifies the effective values with `sshd -T -C` before sshd reloads,
    falls back to a managed block at the top of sshd_config when a drop-in would lose
    (first value wins), and restores everything on failure. If the fresh login fails after
    the change, we ask for an immediate revert; the host's watchdog reverts on its own anyway.
    """

    def _fresh_login(self, target):
        self.runner.entry(Target(target.host, FreshLogin(target.auth)), "detect_os", [], become=False)

    def run(self, target, settings, **kwargs):
        pairs = [f"{option}={value}" for option, value in sorted(settings.items())]
        risky = any((o.lower(), str(v).lower()) in LOCKOUT_RISK for o, v in settings.items())
        if risky:
            try:
                self._fresh_login(target)
            except Exception as exc:
                raise RuntimeError(f"refusing to change {', '.join(sorted(settings))}: a fresh key login "
                                   f"does not work before the change: {exc}") from exc
        applied = self.runner.entry(target, "fix_sshd_hardening", ["apply", *pairs])
        token = applied["token"]
        try:
            self._fresh_login(target)
        except Exception as exc:
            try:
                self.runner.entry(target, "fix_sshd_hardening", ["revert", token])
            except Exception:
                pass  # the on-host watchdog still reverts
            raise RuntimeError(f"fresh login failed after the change; reverted: {exc}") from exc
        self.runner.entry(target, "fix_sshd_hardening", ["confirm", token])
        return applied


class EnforceSSHPolicy(AutoFix):
    """Set the deviating options to the inventory's values; deviations on one host are fixed together."""

    def can_fix(self, finding):
        return isinstance(finding, SSHPolicyDeviation)

    def get_fix(self, finding):
        return EnforceSSHSettings().bind(target=finding.host, settings={finding.option: finding.expected})

    def group_key(self, finding):
        return finding.host.host

    def get_group_fix(self, findings):
        return EnforceSSHSettings().bind(target=findings[0].host,
                                         settings={f.option: f.expected for f in findings})

    def describe(self, finding):
        return (f"set sshd {finding.option} to {finding.expected} (verified with sshd -T before reload; "
                "auto-revert unless a fresh key login succeeds)")
