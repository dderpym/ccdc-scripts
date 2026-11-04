from dataclasses import dataclass

from ccdc.findings import BundleScanner, Finding


@dataclass(frozen=True)
class LibraryInjection(Finding):
    """LD_PRELOAD / LD_LIBRARY_PATH / LD_AUDIT set where a service or every process inherits it."""
    file: str
    unit: str
    variable: str
    value: str
    code = "library-injection"
    severity = "critical"

    @property
    def summary(self):
        where = f"unit {self.unit}" if self.unit else "the environment"
        return f"{self.variable}={self.value} injected into {where} by {self.file}"


@dataclass(frozen=True)
class UnreadableUnit(Finding):
    """Fail closed: a file that could not be read or parsed may be hiding an injection."""
    file: str
    reason: str
    code = "unparseable-unit"

    @property
    def summary(self):
        return f"cannot parse {self.file}: {self.reason}"


@dataclass(frozen=True)
class UnownedMappedLibrary(Finding):
    """A package-unowned shared object is mapped into a running process."""
    library: str
    processes: tuple
    code = "unowned-mapped-library"

    @property
    def summary(self):
        return f"unowned library {self.library} mapped by {', '.join(self.processes)}"


class LibraryInjectionScanner(BundleScanner):
    entry = "scan_ld_preload"

    def findings(self, target, row):
        kind = row["kind"]
        if kind in ("unit-env", "profile-env"):
            return [LibraryInjection(target, row["file"], row.get("unit", ""), row["variable"], row["value"])]
        if kind == "ld-so-preload":
            return [LibraryInjection(target, row["file"], "", "ld.so.preload", ":".join(row["libraries"]))]
        if kind == "unreadable":
            return [UnreadableUnit(target, row["file"], row["reason"])]
        if kind == "mapped-unowned":
            procs = tuple(f"{p['comm']}[{p['pid']}]" for p in row["processes"])
            return [UnownedMappedLibrary(target, row["library"], procs)]
        return []
