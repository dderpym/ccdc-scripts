from dataclasses import dataclass

from ccdc.scanners.lse import ListedPath, LSEScanner


@dataclass(frozen=True)
class ServiceFileIssue(ListedPath):
    code = "service-file-issue"
    what = "service configuration is writable or not root-owned"


class ServiceFileScanner(LSEScanner):
    tests = ("srv000", "srv500", "srv020", "srv030", "srv040", "srv050", "srv520")
    listing_type = ServiceFileIssue
