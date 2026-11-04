"""System integrity: packaged files that differ from the distro, and critical-path policy."""
from dataclasses import dataclass

from ccdc.ansible import AnsibleScript
from ccdc.findings import Finding, ScanResult, Scanner
from ccdc.scanners.permissions import drift_from_fix


@dataclass(frozen=True)
class IntegrityFinding(Finding):
    path: str
    text: str
    source: str  # metadata, policy, rpm, dpkg, apk, ...
    level: str = "warning"
    code = "integrity"

    @property
    def severity(self):
        return self.level

    @property
    def summary(self):
        return f"{self.path}: {self.text}" if self.path else self.text


class ScanIntegrity(AnsibleScript):
    """Read-only package verification and critical-path metadata; prints one JSON document."""
    source = "remote.py"

    def arguments(self, deep=False, **kwargs):
        return ["--deep"] if deep else []


class IntegrityScanner(Scanner):
    def remote_step(self, target):
        return ScanIntegrity(self.runner)

    def findings_from(self, target, document):
        rows = document.get("findings", [])
        findings = [f for row in rows for f in self.findings(target, row)]
        # Rows the scanner raises about itself are coverage gaps, not host findings.
        gaps = [row["summary"] for row in rows if row.get("scanner_error")]
        return ScanResult(findings, [*document.get("errors", []), *gaps])

    def findings(self, target, row):
        if row.get("scanner_error"):
            return []
        found = [IntegrityFinding(target, row.get("path", ""), row["summary"], row.get("source", ""), row["severity"])]
        drift = drift_from_fix(target, row.get("fix"), "integrity")
        return found + ([drift] if drift else [])
