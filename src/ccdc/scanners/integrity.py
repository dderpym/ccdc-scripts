"""System integrity: packaged files that differ from the distro, and critical-path policy."""
from dataclasses import dataclass

from ccdc.findings import BundleScanner, Finding, ScanResult
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


class IntegrityScanner(BundleScanner):
    entry = "discover_integrity"

    def scan(self, target):
        document = self.runner.entry(target, self.entry, self.arguments(), become=self.become)
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
