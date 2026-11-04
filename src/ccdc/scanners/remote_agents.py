from dataclasses import dataclass

from ccdc.findings import EntryScanner, Finding


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


class RemoteAgentScanner(EntryScanner):
    entry = "scan_remote_agents"

    def findings(self, target, row):
        return [RemoteAccessAgent(target, row["kind"], row["name"], row["location"], row["pid"])]
