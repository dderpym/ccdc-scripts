"""Disable desktop/hardware daemons a server does not need."""
from ccdc.ansible import BundleScript

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

