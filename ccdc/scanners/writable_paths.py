from dataclasses import dataclass

from ccdc.scanners.lse import ListedPath, LSEScanner


@dataclass(frozen=True)
class WritableCriticalPath(ListedPath):
    code = "writable-critical-path"
    severity = "critical"
    what = "writable critical file, directory, or PATH entry"


class WritablePathScanner(LSEScanner):
    tests = ("fst160", "fst170", "fst180", "usr080")
    listing_type = WritableCriticalPath
