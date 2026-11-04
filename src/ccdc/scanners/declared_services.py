"""Listening services judged against the services the inventory declares (live `ss`, not a file)."""
from dataclasses import dataclass

from ccdc.findings import BundleScanner, Finding, ScanResult
from ccdc.services import NOT_DECLARED, declared, exposed


@dataclass(frozen=True)
class UnapprovedService(Finding):
    port: int
    proto: str
    process: str
    address: str
    code = "unapproved-service"
    severity = "warning"

    @property
    def summary(self):
        return f"{self.proto}/{self.port} ({self.process}) listens on {self.address} but is not in the inventory"


@dataclass(frozen=True)
class ApprovedServiceDown(Finding):
    port: int
    proto: str
    name: str
    code = "approved-service-down"
    severity = "critical"

    @property
    def summary(self):
        return f"approved service {self.name} ({self.proto}/{self.port}) is not listening"


class DeclaredServicesScanner(BundleScanner):
    """Non-loopback listeners (discover_listeners, as root) against `services:` in the inventory."""
    entry = "discover_listeners"

    def scan(self, target):
        try:
            approved = declared(target.vars)
        except ValueError as exc:
            return ScanResult([], [str(exc)])
        if approved is None:
            return ScanResult([], [NOT_DECLARED])
        live = exposed(self.runner.entry(target, self.entry, [], become=self.become))
        listed = {(proto, port) for proto, port, _ in approved}
        findings = [UnapprovedService(target, port, proto, info["process"] or "unknown", ", ".join(info["addresses"]))
                    for (proto, port), info in sorted(live.items()) if (proto, port) not in listed]
        findings += [ApprovedServiceDown(target, port, proto, name)
                     for proto, port, name in approved if (proto, port) not in live]
        return ScanResult(findings)
