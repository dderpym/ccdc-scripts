"""OS detection layer: everything distro-specific starts from DetectOS."""
from dataclasses import dataclass

from ccdc.ansible import AnsibleScript
from ccdc.runner import RemoteError, failure_message


@dataclass(frozen=True)
class OSInfo:
    id: str
    id_like: str
    version: str
    family: str


class DetectOS(AnsibleScript):
    """Reads /etc/os-release on the target; no privileges needed."""
    source = "remote.py"
    become = False

    def parse(self, result, **kwargs):
        if result["rc"] != 0:
            raise RemoteError("%s: %s" % (self.name, failure_message(result)))
        document = super().parse(result, **kwargs)
        return OSInfo(document["id"], document["id_like"], document["version"], document["family"])
