"""SSH side doors, judged on what the running sshd does: per-user effective settings (Match blocks),
the key files sshd would read, sshrc it would run, files its config references, config edited after
the daemon started, live LD_* environment and libraries, and sockets its config does not explain."""
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
    contexts: tuple = ()  # "default" or "user@address" the setting is effective for
    code = "sshd-option"

    @property
    def severity(self):
        return self.level

    @property
    def summary(self):
        who = ""
        if self.contexts:
            who = " for " + ", ".join(self.contexts[:4]) + (" ..." if len(self.contexts) > 4 else "")
        return f"sshd {self.option} {self.value}{who}: {self.why}"


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
        return f"{self.path} is referenced by the effective sshd config but hidden or not owned by any package"


@dataclass(frozen=True)
class StaleSSHConfig(Finding):
    path: str
    edited: int
    started: int
    code = "ssh-config-not-reloaded"
    severity = "critical"

    @property
    def summary(self):
        return f"{self.path} changed after sshd started; the running daemon may not match its config"


@dataclass(frozen=True)
class SSHLiveEnvironment(Finding):
    pid: int
    name: str
    value: str
    code = "ssh-live-environment"
    severity = "critical"

    @property
    def summary(self):
        return f"sshd pid {self.pid} runs with {self.name}={self.value}"


@dataclass(frozen=True)
class SSHLiveLibrary(Finding):
    pid: int
    path: str
    why: str
    code = "ssh-live-library"
    severity = "critical"

    @property
    def summary(self):
        return f"sshd pid {self.pid} has {self.path} mapped: {self.why}"


@dataclass(frozen=True)
class OddSSHListener(Finding):
    address: str
    port: int
    why: str
    code = "ssh-odd-listener"
    severity = "critical"

    @property
    def summary(self):
        return f"sshd listens on {self.address}:{self.port}: {self.why}"


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
            return [UnexpectedSSHOption(target, row["option"], row["value"], row["why"], row["severity"],
                                        tuple(row.get("contexts", ())))]
        if kind == "authorized-key":
            return [RogueAuthorizedKey(target, row["file"], row["user"], row["line"], row["fingerprint"], row["comment"])]
        if kind == "ssh-startup":
            return [SSHStartupScript(target, row["path"], row["what"])]
        if kind == "unowned-ssh-file":
            return [UnownedSSHFile(target, row["path"])]
        if kind == "stale-config":
            return [StaleSSHConfig(target, row["path"], row["edited"], row["started"])]
        if kind == "live-env":
            return [SSHLiveEnvironment(target, row["pid"], row["name"], row["value"])]
        if kind == "live-library":
            return [SSHLiveLibrary(target, row["pid"], row["path"], row["why"])]
        if kind == "odd-listener":
            return [OddSSHListener(target, row["address"], row["port"], row["why"])]
        return []
