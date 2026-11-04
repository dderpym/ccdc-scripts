"""OS detection layer: everything distro-specific starts from DetectOS."""
from dataclasses import dataclass

from ccdc.ansible import EntryScript


@dataclass(frozen=True)
class OSInfo:
    id: str
    id_like: str
    version: str
    family: str


class DetectOS(EntryScript):
    entry = "detect_os"
    become = False

    def parse(self, document, **kwargs):
        return OSInfo(document["id"], document["id_like"], document["version"], document["family"])
