from dataclasses import dataclass

from ccdc.findings import Finding
from ccdc.scanners.lse import LSEScanner, listing_entries


@dataclass(frozen=True)
class WritableSUIDBinary(Finding):
    file: str
    permissions: str
    code = "writable-suid-binary"
    severity = "critical"

    @property
    def summary(self):
        return f"setuid binary {self.file} is writable ({self.permissions})"


@dataclass(frozen=True)
class UncommonSUIDBinary(Finding):
    file: str
    permissions: str
    code = "uncommon-suid-binary"

    @property
    def summary(self):
        return f"uncommon setuid binary {self.file} ({self.permissions})"


class SUIDScanner(LSEScanner):
    tests = ("fst020", "fst030")

    def typed(self, target, row):
        kind = WritableSUIDBinary if row["id"] == "fst030" else UncommonSUIDBinary
        return [kind(target, path, permissions) for permissions, _, _, path in listing_entries(row)]
