"""LSE distilled: each scanner asks the pinned LSE for just its own tests."""
import re
from dataclasses import dataclass

from ccdc.findings import BundleScanner, Finding

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


class LSEScanner(BundleScanner):
    """Base for scanners over a subset of LSE tests; subclasses list `tests` and may override typed()."""
    entry = "discover_lse"
    tests = ()

    def arguments(self, **kwargs):
        return ["--only", ",".join(self.tests)]

    def findings(self, target, row):
        if row["id"].startswith("scanner-") or row["id"] not in self.tests:
            return []
        typed = self.typed(target, row)
        if typed is not None:
            return typed
        return [LSEFinding(target, row["id"], row["summary"], evidence_lines(row), row["severity"])]

    def typed(self, target, row):
        return None
