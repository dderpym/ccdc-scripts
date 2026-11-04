"""OS detection: report which OS this is, nothing more. Deciding what to do about it is up to the caller."""
from dataclasses import dataclass

from ccdc.ansible import AnsibleScript
from ccdc.runner import RemoteError, failure_message


@dataclass(frozen=True)
class OSInfo:
    id: str
    id_like: str
    version: str
    name: str

    @property
    def lineage(self):
        """This distro, then its declared parents, nearest first (ID then ID_LIKE)."""
        return tuple(part for part in (self.id, *self.id_like.split()) if part)


class DetectOS(AnsibleScript):
    """Reads /etc/os-release on the target; no privileges needed."""
    source = "remote.py"
    become = False

    def parse(self, result, **kwargs):
        if result["rc"] != 0:
            raise RemoteError("%s: %s" % (self.name, failure_message(result)))
        document = super().parse(result, **kwargs)
        return OSInfo(document["id"], document["id_like"], document["version"], document["name"])
