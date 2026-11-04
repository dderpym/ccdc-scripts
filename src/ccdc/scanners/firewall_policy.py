"""The EFFECTIVE inbound firewall (discover_firewall, as root) against the services the inventory declares."""
from dataclasses import dataclass

from ccdc.findings import Finding, Scanner, ScanResult
from ccdc.services import declared
from scripts.firewall.discover import DiscoverFirewall


@dataclass(frozen=True)
class FirewallBlocksService(Finding):
    port: int
    proto: str
    name: str
    code = "firewall-blocks-service"
    severity = "critical"

    @property
    def summary(self):
        return f"firewall blocks approved service {self.name} ({self.proto}/{self.port}); scoring would fail"


@dataclass(frozen=True)
class FirewallOpensUnapproved(Finding):
    port: int
    proto: str
    code = "firewall-opens-unapproved"
    severity = "warning"

    @property
    def summary(self):
        return f"firewall accepts {self.proto}/{self.port}, which is not in the inventory"


@dataclass(frozen=True)
class FirewallNotRestricting(Finding):
    backend: str
    code = "firewall-not-restricting"
    severity = "warning"

    @property
    def summary(self):
        return f"inbound default is accept ({self.backend}): nothing outside the inventory is blocked"


class FirewallPolicyScanner(Scanner):
    """Exact comparison only when the policy is one we can summarize; otherwise an explicit error, never a guess."""

    def remote_step(self, target):
        try:
            if declared(target.vars) is None:
                return None
        except ValueError:
            return None
        return DiscoverFirewall(self.runner)

    def scan(self, target):
        try:
            if declared(target.vars) is None:
                return ScanResult([], ["no services declared in inventory; firewall comparison skipped"])
        except ValueError as exc:
            return ScanResult([], [str(exc)])
        return super().scan(target)

    def findings_from(self, target, state):
        approved = declared(target.vars)
        tcp, udp = state.get("allowed_tcp"), state.get("allowed_udp")
        if state.get("default_inbound") == "accept":
            return ScanResult([FirewallNotRestricting(target, state.get("backend") or "none")])
        if state.get("default_inbound") != "drop" or tcp is None or udp is None:
            return ScanResult([], [f"{state.get('backend')} policy is custom or managed ({', '.join(state.get('rules', {}).get('managers', [])) or 'unsummarizable'}); "
                                   "not compared with the inventory"])
        opened = {("tcp", p) for p in tcp} | {("udp", p) for p in udp}
        want = {(proto, port): name for proto, port, name in approved}
        findings = [FirewallBlocksService(target, port, proto, name)
                    for (proto, port), name in sorted(want.items()) if (proto, port) not in opened]
        # tcp/22 is always open: the apply path refuses to run without it.
        findings += [FirewallOpensUnapproved(target, port, proto)
                     for proto, port in sorted(opened) if (proto, port) not in want and (proto, port) != ("tcp", 22)]
        return ScanResult(findings)
