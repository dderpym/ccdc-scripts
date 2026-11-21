"""LSE distilled: each scanner reports only its own tests, but a host's LSE scanners share ONE LSE run.

Every LSEScanner's remote step is the same ScanLSE (all tests of all LSE scanners), so the
bundle that scan_target builds for a host runs it once; each scanner then filters the shared
document down to its own tests in findings_from.
"""
import re
from dataclasses import dataclass

from ccdc.ansible import AnsibleScript
from ccdc.findings import Finding, ScanResult, Scanner
from ccdc.scanners.permissions import drift_from_fix

LISTING = re.compile(r"^(\S{10}[.+@]?) (\S+) (\S+) (/.+)$")


@dataclass(frozen=True)
class LSEFinding(Finding):
    """Any LSE test without a more specific type."""
    test: str
    text: str
    evidence: tuple = ()
    level: str = "warning"
    code = "lse"

    @property
    def severity(self):
        return self.level

    @property
    def summary(self):
        return f"{self.test}: {self.text}"


def listing_entries(row):
    """(permissions, owner, group, path) for each ls-style evidence line of an LSE row."""
    for context in row.get("context", []):
        for line in context.get("evidence", []):
            match = LISTING.match(line)
            if match:
                yield match.groups()


def evidence_lines(row):
    return tuple(line for context in row.get("context", []) for line in context.get("evidence", []))


class ScanLSE(AnsibleScript):
    """The pinned LSE plus the passive supplemental checks; prints one JSON document.

    tests: finding ids to run (default: everything allow-listed); deep adds the level-1
    checks. Runs as the unprivileged login account (it drops privileges itself).
    """
    source = "remote.py"
    support = ("kernel_risks.py", "lse_extras.py", "lse_host_risks.py",
               "../../../vendor/lse.sh", "../../../vendor/LSE-LICENSE")

    def arguments(self, tests=None, deep=False, script=None, user=None, **kwargs):
        args = ["--only", ",".join(tests)] if tests else []
        args += ["--deep"] if deep else []
        args += ["--script", script] if script else []
        args += ["--user", user] if user else []
        return args


def all_tests():
    """Union of `tests` over every concrete LSEScanner currently defined."""
    found, pending = set(), list(LSEScanner.__subclasses__())
    while pending:
        cls = pending.pop()
        pending.extend(cls.__subclasses__())
        if not cls.__dict__.get("abstract", False):
            found.update(cls.tests)
    return sorted(found)


class LSEScanner(Scanner):
    """Base for scanners over a subset of LSE tests.

    `tests` are the finding ids this scanner reports. `listing_type`, if set, is built as
    listing_type(host, path, permissions, test) for each ls-style evidence line; rows that
    carry permission fixes also yield a shared PermissionDrift. Override typed() for
    anything else.
    """
    abstract = True  # only concrete subclasses are registered
    tests = ()
    listing_type = None

    def remote_step(self, target):
        # Identical for every LSE scanner, so a host's bundle runs LSE once.
        return ScanLSE(self.runner, tests=tuple(all_tests()))

    def scan(self, target):
        # Alone, a scanner only asks for its own tests.
        return self.findings_from(target, ScanLSE(self.runner, tests=tuple(self.tests)).run(target))

    def findings_from(self, target, document):
        rows = document.get("findings", [])
        findings = [f for row in rows for f in self.findings(target, row)]
        # Coverage gaps (missing find/getcap/...) mean "no finding" does not mean "clean".
        # The shared run reports every gap; keep those that touch this scanner's tests.
        affected = document.get("incomplete_ids")
        gaps = [row["summary"] for row in rows if row["id"].startswith("scanner-")
                and (affected is None or not self.tests or set(affected) & set(self.tests))]
        return ScanResult(findings, [*document.get("errors", []), *gaps])

    def findings(self, target, row):
        if row["id"].startswith("scanner-") or row["id"] not in self.tests:
            return []
        typed = self.typed(target, row)
        if typed is None:
            typed = self.listing(target, row) or [
                LSEFinding(target, row["id"], row["summary"], evidence_lines(row), row["severity"])]
            typed += [d for d in (drift_from_fix(target, fix, "lse") for fix in row.get("fixes", [])) if d]
        return typed

    def listing(self, target, row):
        if self.listing_type is None:
            return []
        return [self.listing_type(target, path, permissions, row["id"])
                for permissions, _, _, path in listing_entries(row)]

    def typed(self, target, row):
        return None


@dataclass(frozen=True)
class ListedPath(Finding):
    """Base for findings about one path seen in an LSE ls-style listing."""
    path: str
    permissions: str
    test: str

    @property
    def summary(self):
        return f"{self.path} ({self.permissions}): {self.what}"

    what = ""
