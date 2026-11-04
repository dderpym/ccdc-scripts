"""Desktop/hardware daemons a server does not need, judged on what systemd says is enabled/running now."""
from dataclasses import dataclass

from ccdc.findings import BundleScanner, Finding

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


class UnneededServiceScanner(BundleScanner):
    entry = "scan_unneeded_services"

    def __init__(self, runner=None, allowlist=None):
        super().__init__(runner)
        self.allowlist = ALLOWLIST if allowlist is None else allowlist

    def arguments(self, target=None, **kwargs):
        allow = self.allowlist.get(getattr(target, "host", None), ())
        return [*[a for unit in allow for a in ("--allow", unit)], *UNNEEDED_SERVICES]

    def scan(self, target):
        from ccdc.findings import ScanResult
        document = self.runner.entry(target, self.entry, self.arguments(target=target), become=self.become)
        return ScanResult([f for row in document.get("findings", []) for f in self.findings(target, row)],
                          document.get("errors", []))

    def findings(self, target, row):
        return [UnneededService(target, row["unit"], row["enabled"], row["active"])]
