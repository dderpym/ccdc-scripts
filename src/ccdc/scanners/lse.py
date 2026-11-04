"""LSE distilled: each scanner asks the pinned LSE for just its own tests."""
import re
import threading
from dataclasses import dataclass

from ccdc.findings import EntryScanner, Finding, ScanResult
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


class LSERun:
    """One discover_lse run per host per round, shared by every LSEScanner.

    Outside a round (begin() not called for that host) nothing is cached, so a
    stray scanner.run() or a later rescan can never read an old document. A failed
    run is remembered for the round too, so an unreachable host is tried once.
    """

    def __init__(self):
        self._guard = threading.Lock()
        self._rounds = {}  # host -> [lock, outcome or None]

    def begin(self, host):
        with self._guard:
            self._rounds.setdefault(host, [threading.Lock(), None])

    def end(self, host):
        with self._guard:
            self._rounds.pop(host, None)

    def fetch(self, host, own, shared):
        """own() -> document for just the caller's tests; shared() -> document for every LSE test."""
        with self._guard:
            slot = self._rounds.get(host)
        if slot is None:
            return own()
        with slot[0]:
            if slot[1] is None:
                try:
                    slot[1] = (shared(), None)
                except Exception as exc:
                    slot[1] = (None, exc)
        document, error = slot[1]
        if error is not None:
            raise error
        return document


SHARED = LSERun()


def all_tests():
    """Union of `tests` over every concrete LSEScanner currently defined."""
    found, pending = set(), list(LSEScanner.__subclasses__())
    while pending:
        cls = pending.pop()
        pending.extend(cls.__subclasses__())
        if not cls.__dict__.get("abstract", False):
            found.update(cls.tests)
    return sorted(found)


class LSEScanner(EntryScanner):
    """Base for scanners over a subset of LSE tests.

    `tests` are the finding ids to run. `listing_type`, if set, is built as
    listing_type(host, path, permissions, test) for each ls-style evidence line;
    rows that carry permission fixes also yield a shared PermissionDrift. Override
    typed() for anything else.
    """
    abstract = True  # only concrete subclasses are registered
    entry = "discover_lse"
    tests = ()
    listing_type = None

    run_cache = SHARED

    def arguments(self, tests=None, **kwargs):
        return ["--only", ",".join(self.tests if tests is None else tests)]

    def begin_round(self, target):
        self.run_cache.begin(target.host)

    def end_round(self, target):
        self.run_cache.end(target.host)

    def _document(self, target, tests=None):
        return self.runner.entry(target, self.entry, self.arguments(tests), become=self.become)

    def scan(self, target):
        document = self.run_cache.fetch(target.host, lambda: self._document(target),
                                        lambda: self._document(target, all_tests()))
        findings = [f for row in document.get("findings", []) for f in self.findings(target, row)]
        # Coverage gaps (missing find/getcap/...) mean "no finding" does not mean "clean".
        # The shared run reports every gap; keep those that touch this scanner's tests.
        affected = document.get("incomplete_ids")
        gaps = [row["summary"] for row in document.get("findings", []) if row["id"].startswith("scanner-")
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
