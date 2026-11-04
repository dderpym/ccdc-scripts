"""Findings, Scanners, AutoFixes.

A Scanner is a Script that must not change the target (or only ephemerally); it
returns Findings. An AutoFix turns a Finding into a Script with the finding's
data already filled in, so callers can just .run() it.
"""
from dataclasses import asdict, dataclass, fields
from typing import ClassVar

from ccdc.ansible import BundleScript
from ccdc.script import Script
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


class Scanner(Script):
    """Claims not to affect the server, so it is safe to run as often as wanted."""

    def scan(self, target):
        raise NotImplementedError

    def run(self, target):
        return self.scan(target)

    # A round is one scan_target pass. Scanners that can share work inside a round
    # (see LSEScanner) must forget it at end_round, so a later round never sees old data.
    def begin_round(self, target):
        pass

    def end_round(self, target):
        pass


class BundleScanner(Scanner, BundleScript):
    """A scanner whose detection runs on the host as a bundle entry printing
    {"findings": [...], "errors": [...]}. Subclasses turn each row into a Finding."""

    def __init__(self, runner=None):
        BundleScript.__init__(self, runner)

    def scan(self, target):
        document = self.runner.entry(target, self.entry, self.arguments(), become=self.become)
        findings = [finding for row in document.get("findings", []) for finding in self.findings(target, row)]
        return ScanResult(findings, document.get("errors", []))

    def findings(self, target, row):
        """Zero or more Findings for one row of host output."""
        raise NotImplementedError

    run = Scanner.run


class AutoFix:
    def can_fix(self, finding):
        raise NotImplementedError

    def get_fix(self, finding):
        """A Script with everything filled in from the finding; .run() takes no arguments."""
        raise NotImplementedError

    def describe(self, finding):
        return type(self).__name__


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


def finding_types():
    return {cls.code: cls for cls in _all_subclasses(Finding)}


def _all_subclasses(cls):
    for sub in cls.__subclasses__():
        yield sub
        yield from _all_subclasses(sub)
