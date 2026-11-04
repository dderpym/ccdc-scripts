"""Apply the inventory's approved services as the host's inbound firewall, with the same lock-out guards as `firewall configure`."""
import json

from ccdc.findings import AutoFix
from ccdc.fixes.ssh_hardening import FreshLogin
from ccdc.osinfo import DetectOS
from ccdc.runner import ROOT
from ccdc.script import HostScript
from ccdc.scanners.firewall_policy import FirewallBlocksService, FirewallNotRestricting, FirewallOpensUnapproved
from ccdc.services import declared, policy_ports
from ccdc.target import Target
from scripts.firewall.apply import ApplyFirewall, RestoreFirewall
from scripts.firewall.discover import DiscoverFirewall, DiscoverSSH

SNAPSHOTS = ROOT / "state" / "reports" / "rollback"


class EnforceApprovedFirewall(HostScript):
    """Approved ports only (tcp/22 always), with every guard of the interactive path:

    refuse unless every ACTIVE sshd port is approved; fresh key login before and after;
    controller-side rollback snapshot; the host script itself verifies the exact policy
    and restores on failure; if the login is lost afterwards the snapshot is restored.
    """

    def __init__(self, runner=None):
        self.runner = runner

    def run(self, target, **kwargs):
        approved = declared(target.vars)
        if approved is None:
            raise RuntimeError(f"{target}: no services declared in inventory; run ccdcctl services")
        tcp, udp = policy_ports(approved)
        ssh = DiscoverSSH(self.runner).run(target)
        ports = ssh.get("effective", {}).get("port", ["22"])
        active = [int(p) for p in (ports if isinstance(ports, list) else [ports])]
        missing = [p for p in active if p not in tcp]
        if missing:
            raise RuntimeError(f"{target}: sshd listens on {missing} which is not approved; "
                               "run ccdcctl services first (refusing: that could lock you out)")
        fresh = Target(target.host, FreshLogin(target.auth))
        DetectOS(self.runner).run(fresh)  # fresh key login works before we touch anything
        snapshot = DiscoverFirewall(self.runner).run(target, snapshot=True)
        path = SNAPSHOTS / target.host / "firewall.json"
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n")
        path.chmod(0o600)
        if not ApplyFirewall(self.runner).run(target, tcp=tcp, udp=udp):
            raise RuntimeError(f"{target}: firewall apply failed (the host restored its previous rules)")
        try:
            DetectOS(self.runner).run(fresh)
        except Exception as exc:
            RestoreFirewall(self.runner).run(target, payload=path)
            raise RuntimeError(f"{target}: fresh login failed after apply; snapshot restored: {exc}") from exc
        return {"tcp": tcp, "udp": udp}


class ApplyApprovedFirewall(AutoFix):
    def can_fix(self, finding):
        return isinstance(finding, (FirewallBlocksService, FirewallOpensUnapproved, FirewallNotRestricting))

    def get_fix(self, finding):
        return EnforceApprovedFirewall().bind(target=finding.host)

    def describe(self, finding):
        return ("apply the inventory's approved services as the inbound firewall "
                "(tcp/22 always open; snapshot saved to state/reports/rollback for `firewall rollback`)")
