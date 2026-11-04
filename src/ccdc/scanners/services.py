from dataclasses import dataclass

from ccdc.findings import Finding
from ccdc.scanners.lse import LSEScanner, evidence_lines


@dataclass(frozen=True)
class UninspectedService(Finding):
    """A systemd unit the scanner could not read: unknown, so it must be reviewed by hand."""
    unit: str
    reason: str
    code = "uninspected-service"

    @property
    def summary(self):
        return f"{self.unit} could not be inspected ({self.reason})"


@dataclass(frozen=True)
class DockerSocketMount(Finding):
    """A container with the runtime socket bind-mounted is root-equivalent on the host."""
    container: str
    mount: str
    code = "docker-socket-mount"
    severity = "critical"

    @property
    def summary(self):
        return f"{self.container} mounts a container runtime socket ({self.mount})"


class ServiceScanner(LSEScanner):
    """Root service paths, root processes, runtime sockets, SGID files, container socket mounts."""
    tests = ("extra-services", "extra-services-unverified", "extra-root-processes",
             "extra-runtime-sockets", "extra-sgid", "extra-docker-sock-mounts")

    def typed(self, target, row):
        if row["id"] == "extra-services-unverified":
            out = []
            for line in evidence_lines(row):
                unit, _, reason = line.partition(": ")
                out.append(UninspectedService(target, unit, reason))
            return out
        if row["id"] == "extra-docker-sock-mounts":
            return [DockerSocketMount(target, container, mount.removeprefix("runtime socket mounted: "))
                    for context in row.get("context", [])
                    for container, mount in zip(context["evidence"], [context["summary"]])]
        return None
