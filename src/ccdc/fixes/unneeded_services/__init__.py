from ccdc.ansible import AnsibleScript
from ccdc.findings import AutoFix
from ccdc.scanners.unneeded_services import UnneededService


class DisableServices(AnsibleScript):
    """`systemctl disable --now` the named units; units not installed are skipped (remote.sh)."""
    source = "remote.sh"

    def arguments(self, units=(), **kwargs):
        return ["disable", *units]

    def parse(self, result, **kwargs):
        document = super().parse(result, **kwargs)
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
