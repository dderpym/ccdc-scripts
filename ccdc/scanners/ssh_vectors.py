"""SSH side doors: odd sshd settings, unknown authorized keys, sshrc, unowned files in /etc/ssh."""
from dataclasses import dataclass, field
from pathlib import Path

from ccdc.findings import BundleScanner, Finding, ScanResult

ROOT = Path(__file__).resolve().parents[2]
TEAM_KEYS = ROOT / "files" / "oski.pub"


@dataclass
class SSHAllow:
    """Things on one host that are legitimate and must not be reported."""
    options: tuple = ()   # "trustedusercakeys=/etc/ssh/vault-ca.pem"
    paths: tuple = ()     # "/etc/ssh/vault-ca.pem"
    keys: tuple = ()      # extra authorized public-key lines


# host name -> SSHAllow. Fill in per competition; the scanner also accepts one in its constructor.
ALLOWLIST = {}


@dataclass(frozen=True)
class UnexpectedSSHOption(Finding):
    option: str
    value: str
    why: str
    level: str = "warning"
    code = "sshd-option"

    @property
    def severity(self):
        return self.level

    @property
    def summary(self):
        return f"sshd {self.option} {self.value}: {self.why}"


@dataclass(frozen=True)
class RogueAuthorizedKey(Finding):
    file: str
    user: str
    line: int
    fingerprint: str
    comment: str = ""
    code = "rogue-authorized-key"
    severity = "critical"

    @property
    def summary(self):
        return f"unknown key {self.fingerprint} ({self.comment or 'no comment'}) in {self.file}:{self.line}"


@dataclass(frozen=True)
class SSHStartupScript(Finding):
    path: str
    what: str
    code = "ssh-startup-script"
    severity = "critical"

    @property
    def summary(self):
        return f"{self.what} {self.path} runs on every SSH login"


@dataclass(frozen=True)
class UnownedSSHFile(Finding):
    path: str
    code = "unowned-ssh-file"

    @property
    def summary(self):
        return f"{self.path} is not owned by any package"


def team_keys(path=TEAM_KEYS):
    try:
        return tuple(line.strip() for line in path.read_text().splitlines() if line.strip() and not line.startswith("#"))
    except OSError:
        return ()


class SSHVectorScanner(BundleScanner):
    entry = "scan_ssh_vectors"

    def __init__(self, runner=None, allowlist=None, keys=None):
        super().__init__(runner)
        self.allowlist = ALLOWLIST if allowlist is None else allowlist
        self.keys = team_keys() if keys is None else tuple(keys)

    def arguments(self, target=None, **kwargs):
        allow = self.allowlist.get(getattr(target, "host", None), SSHAllow())
        args = []
        for key in (*self.keys, *allow.keys):
            args += ["--allow-key", key]
        for option in allow.options:
            args += ["--allow", option]
        for path in allow.paths:
            args += ["--allow-path", path]
        return args

    def scan(self, target):
        document = self.runner.entry(target, self.entry, self.arguments(target=target), become=self.become)
        findings = [f for row in document.get("findings", []) for f in self.findings(target, row)]
        return ScanResult(findings, document.get("errors", []))

    def findings(self, target, row):
        kind = row["kind"]
        if kind == "sshd-option":
            return [UnexpectedSSHOption(target, row["option"], row["value"], row["why"], row["severity"])]
        if kind == "authorized-key":
            return [RogueAuthorizedKey(target, row["file"], row["user"], row["line"], row["fingerprint"], row["comment"])]
        if kind == "ssh-startup":
            return [SSHStartupScript(target, row["path"], row["what"])]
        if kind == "unowned-ssh-file":
            return [UnownedSSHFile(target, row["path"])]
        return []
