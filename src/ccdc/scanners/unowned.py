"""Files in system directories that no package owns (doc 5.1)."""
from dataclasses import dataclass, field

from ccdc.findings import EntryScanner, Finding


@dataclass(frozen=True)
class UnownedExecutable(Finding):
    file: str
    flags: tuple = ()
    pids: tuple = ()
    level: str = "warning"
    code = "unowned-executable"

    @property
    def severity(self):
        return self.level

    @property
    def summary(self):
        return f"unowned executable {self.file} ({', '.join(self.flags)})"


@dataclass(frozen=True)
class TimestompedFile(Finding):
    file: str
    flags: tuple = ()
    pids: tuple = ()
    code = "timestomped-file"
    severity = "critical"

    @property
    def summary(self):
        return f"unowned file {self.file} has mtime far older than ctime (backdated)"


@dataclass(frozen=True)
class UnitRunsUnownedBinary(Finding):
    unit: str
    binary: str
    unit_owned: bool
    pids: tuple = ()
    level: str = "warning"
    # RestartSec of the unit: the rescan guard waits at least this long. Not part of identity.
    restart_sec: int = field(default=0, compare=False)
    code = "unit-runs-unowned-binary"

    @property
    def severity(self):
        return self.level

    @property
    def summary(self):
        who = "package-owned unit" if self.unit_owned else "unowned unit"
        return f"{who} {self.unit} runs unowned binary {self.binary}"


@dataclass(frozen=True)
class UnownedUnit(Finding):
    unit: str
    code = "unowned-unit"

    @property
    def summary(self):
        return f"unowned systemd unit {self.unit}"


@dataclass(frozen=True)
class UnitMissingBinary(Finding):
    unit: str
    binary: str
    code = "unit-missing-binary"
    severity = "info"

    @property
    def summary(self):
        return f"unit {self.unit} points at missing {self.binary} (leftover?)"


class UnownedScanner(EntryScanner):
    entry = "scan_unowned"

    def findings(self, target, row):
        kind, pids = row["kind"], tuple(row.get("pids", []))
        if kind == "unowned-exec":
            return [UnownedExecutable(target, row["path"], tuple(row["flags"]), pids, row["severity"])]
        if kind == "timestomped":
            return [TimestompedFile(target, row["path"], tuple(row["flags"]), pids)]
        if kind == "unit-runs-unowned":
            return [UnitRunsUnownedBinary(target, row["unit"], row["binary"], row["unit_owned"], pids, row["severity"], row.get("restart_sec", 0))]
        if kind == "unowned-unit":
            return [UnownedUnit(target, row["unit"])]
        if kind == "unit-missing-binary":
            return [UnitMissingBinary(target, row["unit"], row["binary"])]
        return []
