from dataclasses import dataclass

from ccdc.findings import BundleScanner, Finding


@dataclass(frozen=True)
class SudoersGrant(Finding):
    file: str
    line: int
    text: str


@dataclass(frozen=True)
class SudoersWorldGrant(SudoersGrant):
    code = "sudoers-world-grant"
    severity = "critical"

    @property
    def summary(self):
        return f"{self.file}:{self.line} grants sudo to everyone: {self.text}"


@dataclass(frozen=True)
class SudoersUnexpectedNopasswd(SudoersGrant):
    code = "sudoers-unexpected-nopasswd"
    severity = "critical"

    @property
    def summary(self):
        return f"{self.file}:{self.line} passwordless sudo for a non-team account: {self.text}"


class SudoersScanner(BundleScanner):
    entry = "scan_sudoers"
    KINDS = {"world": SudoersWorldGrant, "nopasswd": SudoersUnexpectedNopasswd}

    def findings(self, target, row):
        return [self.KINDS[row["kind"]](target, row["file"], row["line"], row["text"])]
