"""Hardening scripts: free fixes from the incident review (sections 4.1, 4.2, 4.9)."""
from ccdc.ansible import AnsibleScript, BundleScript
from ccdc.script import ComposedScript, Step
from ccdc.target import Auth, Target

# Desktop/hardware daemons a server does not need. gdm, NetworkManager, sssd,
# docker, atd and snapd are left alone on purpose.
UNNEEDED_SERVICES = (
    "ModemManager.service", "wpa_supplicant.service", "avahi-daemon.service", "avahi-daemon.socket",
    "cups.service", "cups.socket", "cups-browsed.service", "udisks2.service", "upower.service",
    "packagekit.service", "libstoragemgmt.service", "mcelog.service", "colord.service", "bluetooth.service",
)


class DisableUnneededServices(BundleScript):
    """Disable the unneeded daemons except `allow` (units a scored service on this host needs)."""
    entry = "fix_services"

    def arguments(self, allow=(), services=UNNEEDED_SERVICES, **kwargs):
        return ["disable", *(s for s in services if s not in set(allow))]


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


class Harden(ComposedScript):
    """SSH hardening first (it self-verifies), then the service clean-up."""

    def __init__(self, runner=None, allow=()):
        super().__init__(Step(HardenSSHD(runner)), Step(DisableUnneededServices(runner), allow=tuple(allow)))
