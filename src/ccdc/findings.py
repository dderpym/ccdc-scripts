"""Findings, Scanners, AutoFixes.

A Scanner is a Script that must not change the target (or only ephemerally); it
returns Findings. An AutoFix turns a Finding into a Script with the finding's
data already filled in, so callers can just .run() it.
"""
from dataclasses import asdict, dataclass, fields
from typing import ClassVar

from ccdc.ansible import EntryScript
from ccdc.script import HostScript
from ccdc.target import Target

SEVERITIES = ("critical", "warning", "info")


@dataclass(frozen=True)
class Finding:
    """Base finding. Subclasses add their own fields; `code` and `severity` are class-level."""
    host: Target
    code: ClassVar[str] = "finding"
    severity: ClassVar[str] = "warning"

    @property
    def summary(self):
        return self.code

    def as_dict(self):
        data = {f.name: getattr(self, f.name) for f in fields(self) if f.name != "host"}
        return {"host": self.host.host, "code": self.code, "severity": self.severity,
                "summary": self.summary, **data}

    def __str__(self):
        return f"[{self.severity}] {self.host}: {self.summary}"


class ScanResult(list):
    """Findings, plus the reasons a scan may be incomplete. Empty != clean when errors is set."""

    def __init__(self, findings=(), errors=()):
        super().__init__(findings)
        self.errors = list(errors)


class Scanner(HostScript):
    """Claims not to affect the server, so it is safe to run as often as wanted.

    A scanner runs locally (it is a HostScript). Its detection runs on the target as an
    AnsibleScript: `remote_step(target)` returns it (None for a purely local scanner) and
    `findings_from(target, result)` turns the step's parsed output
    ({"findings": [rows], "errors": [...]}) into a ScanResult. scan_target puts the steps
    of all scanners into one BundleScript per host; `scan` runs this scanner's step alone.
    """

    def __init__(self, runner=None):
        self.runner = runner

    def remote_step(self, target):
        return None

    def findings_from(self, target, result):
        findings = [f for row in result.get("findings", []) for f in self.findings(target, row)]
        return ScanResult(findings, result.get("errors", []))

    def findings(self, target, row):
        """Zero or more Findings for one row of host output."""
        raise NotImplementedError

    def scan(self, target):
        step = self.remote_step(target)
        if step is None:
            raise NotImplementedError
        return self.findings_from(target, step.run(target))

    def run(self, target):
        return self.scan(target)

    # A round is one scan_target pass. Scanners that can share work inside a round
    # (see LSEScanner) must forget it at end_round, so a later round never sees old data.
    def begin_round(self, target):
        pass

    def end_round(self, target):
        pass


class EntryScanner(Scanner, EntryScript):
    """DEPRECATED with EntryScript: detection is an entry of the global host bundle."""

    def __init__(self, runner=None):
        EntryScript.__init__(self, runner)

    def scan(self, target):
        document = self.runner.entry(target, self.entry, self.arguments(), become=self.become)
        return self.findings_from(target, document)

    run = Scanner.run


class AutoFix:
    def can_fix(self, finding):
        raise NotImplementedError

    def get_fix(self, finding):
        """A Script with everything filled in from the finding; .run() takes no arguments."""
        raise NotImplementedError

    def describe(self, finding):
        return type(self).__name__

    def group_key(self, finding):
        """Findings with the same non-None key are fixed by ONE script run (get_group_fix)."""
        return None

    def get_group_fix(self, findings):
        raise NotImplementedError


class GlobalAutofix:
    """Several AutoFixes; the highest-priority one that matches a finding wins."""

    def __init__(self):
        self._fixes = []

    def register(self, autofix, priority=0):
        self._fixes.append((priority, len(self._fixes), autofix))
        return autofix

    def _match(self, finding):
        matching = [entry for entry in self._fixes if entry[2].can_fix(finding)]
        return max(matching, key=lambda entry: (entry[0], -entry[1]))[2] if matching else None

    def can_fix(self, finding):
        return self._match(finding) is not None

    def get_fix(self, finding):
        autofix = self._match(finding)
        if autofix is None:
            raise LookupError(f"no autofix for {finding.code}")
        return autofix.get_fix(finding)

    def describe(self, finding):
        return self._match(finding).describe(finding)

    def group_key(self, finding):
        autofix = self._match(finding)
        key = autofix.group_key(finding)
        return None if key is None else (id(autofix), key)

    def get_group_fix(self, findings):
        return self._match(findings[0]).get_group_fix(findings)


def finding_types():
    return {cls.code: cls for cls in _all_subclasses(Finding)}


def _all_subclasses(cls):
    for sub in cls.__subclasses__():
        yield sub
        yield from _all_subclasses(sub)
