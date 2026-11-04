from dataclasses import dataclass

from ccdc.ansible import AnsibleScript
from ccdc.findings import Finding, Scanner


@dataclass(frozen=True)
class RemoteAccessAgent(Finding):
    kind: str  # process, unit, path
    name: str
    location: str
    pid: int = 0
    code = "remote-access-agent"
    severity = "warning"  # REVIEW: may be the team's own; report only

    @property
    def summary(self):
        return f"remote-access agent {self.name} ({self.kind}): {self.location}"


class ScanRemoteAgents(AnsibleScript):
    """remote.py prints {"findings": [{kind, name, location, pid}], "errors": [...]}; IOC names are in remote_lib/ioc_agents.py."""
    source = "remote.py"
    support = ("ioc_agents.py", "procfs.py")


class RemoteAgentScanner(Scanner):
    def remote_step(self, target):
        return ScanRemoteAgents(self.runner)

    def findings(self, target, row):
        return [RemoteAccessAgent(target, row["kind"], row["name"], row["location"], row["pid"])]
