"""Desktop/hardware daemons a server does not need, judged on what systemd says is enabled/running now."""
from dataclasses import dataclass

from ccdc.ansible import AnsibleScript
from ccdc.findings import Finding, Scanner

# gdm, NetworkManager, sssd, docker, atd and snapd are left alone on purpose.
UNNEEDED_SERVICES = (
    "ModemManager.service", "wpa_supplicant.service", "avahi-daemon.service", "avahi-daemon.socket",
    "cups.service", "cups.socket", "cups-browsed.service", "udisks2.service", "upower.service",
    "packagekit.service", "libstoragemgmt.service", "mcelog.service", "colord.service", "bluetooth.service",
)

# host name -> units a scored service on that host needs; fill in per competition.
ALLOWLIST = {}


@dataclass(frozen=True)
class UnneededService(Finding):
    unit: str
    enabled: str
    active: str
    code = "unneeded-service"
    severity = "warning"

    @property
    def summary(self):
        return f"{self.unit} is {self.active} (enabled: {self.enabled}); a server does not need it"


class ScanUnneededServices(AnsibleScript):
    """remote.sh [--allow UNIT]... UNIT... prints {"findings": [{unit, enabled, active}], "errors": [...]}."""
    source = "remote.sh"

    def arguments(self, units=(), allow=(), **kwargs):
        return [*[a for unit in allow for a in ("--allow", unit)], *units]


class UnneededServiceScanner(Scanner):
    def __init__(self, runner=None, allowlist=None):
        super().__init__(runner)
        self.allowlist = ALLOWLIST if allowlist is None else allowlist

    def remote_step(self, target):
        allow = tuple(self.allowlist.get(getattr(target, "host", None), ()))
        return ScanUnneededServices(self.runner, units=UNNEEDED_SERVICES, allow=allow)

    def findings(self, target, row):
        return [UnneededService(target, row["unit"], row["enabled"], row["active"])]
