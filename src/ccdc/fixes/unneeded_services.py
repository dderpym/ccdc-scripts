from ccdc.ansible import BundleScript
from ccdc.findings import AutoFix
from ccdc.scanners.unneeded_services import UnneededService


class DisableServices(BundleScript):
    """`systemctl disable --now` the named units; units not installed are skipped (host/fix_services.py)."""
    entry = "fix_services"

    def arguments(self, units=(), **kwargs):
        return ["disable", *units]

    def parse(self, document, **kwargs):
        if document.get("failed"):
            raise RuntimeError("could not disable: " + ", ".join(f"{u} ({r})" for u, r in document["failed"].items()))
        return document


class DisableUnneededService(AutoFix):
    def can_fix(self, finding):
        return isinstance(finding, UnneededService)

    def get_fix(self, finding):
        return DisableServices().bind(target=finding.host, units=(finding.unit,))

    def describe(self, finding):
        return f"systemctl disable --now {finding.unit}"
