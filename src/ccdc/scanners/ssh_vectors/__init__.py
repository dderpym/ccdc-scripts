"""SSH side doors, judged on what the running sshd does: per-user effective settings (Match blocks),
the key files sshd would read, sshrc it would run, files its config references, config edited after
the daemon started, live LD_* environment and libraries, and sockets its config does not explain."""
import json
from dataclasses import dataclass, field
from pathlib import Path

from ccdc.ansible import AnsibleScript
from ccdc.findings import Finding, Scanner
from ccdc.runner import ROOT

TEAM_KEYS = ROOT / "secrets" / "oski.pub"


@dataclass
class SSHAllow:
    """Things on one host that are legitimate and must not be reported."""
    options: tuple = ()   # "trustedusercakeys=/etc/ssh/vault-ca.pem"
    paths: tuple = ()     # "/etc/ssh/vault-ca.pem"
    keys: tuple = ()      # extra authorized public-key lines


# host name -> SSHAllow, in code. Normally leave empty: declare `ssh_allow:` in inventory.yml instead.
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
class SSHPolicyDeviation(Finding):
    """An effective sshd value that differs from what the inventory's `ssh:` policy declares."""
    option: str
    value: str
    expected: str
    contexts: tuple = ()  # "default" or "user@address" the value is effective for
    code = "ssh-policy-deviation"

    @property
    def severity(self):
        return "critical" if self.option == "permitrootlogin" else "warning"

    @property
    def summary(self):
        who = " for " + ", ".join(self.contexts[:4]) + (" ..." if len(self.contexts) > 4 else "") if self.contexts else ""
        return f"{self.option} is {self.value}{who}, inventory says {self.expected}"


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


def yaml_text(value):
    """Unquoted yes/no in YAML arrive as booleans; sshd spells them yes/no."""
    return {True: "yes", False: "no"}.get(value, str(value)) if isinstance(value, bool) else str(value)


def declared_allow(variables):
    """Inventory `ssh_allow:` (options / paths / keys), merged across group and host by Ansible's
    own variable precedence. Options are 'name=value' as `sshd -T` prints them."""
    block = variables.get("ssh_allow")
    block = block if isinstance(block, dict) else {}

    def items(name):
        value = block.get(name) or ()
        return tuple(str(v) for v in ([value] if isinstance(value, str) else value))
    return SSHAllow(options=items("options"), paths=items("paths"), keys=items("keys"))


def team_keys(path=TEAM_KEYS):
    try:
        return tuple(line.strip() for line in path.read_text().splitlines() if line.strip() and not line.startswith("#"))
    except OSError:
        return ()


def declared_policy(variables):
    """Inventory `ssh:` (defaults) overlaid with `ssh_overrides:` (per group/host).

    Ansible replaces a whole mapping when a host redefines it, so overrides live in their
    own variable and are merged here. An override of null stops checking that setting.
    """
    merged = {}
    for name in ("ssh", "ssh_overrides"):
        block = variables.get(name)
        if isinstance(block, dict):
            merged.update({str(k).lower(): v for k, v in block.items()})
    return {k: v for k, v in merged.items() if v is not None}


class ScanSSHVectors(AnsibleScript):
    """remote.py [--policy JSON] [--allow-key LINE]... [--allow OPTION=VALUE]... [--allow-path PATH]...

    Prints {"findings": [rows], "errors": [...]}; reads sshd's EFFECTIVE configuration on the host.
    """
    source = "remote.py"
    support = ("sshkeys.py", "pkgowner.py")

    def arguments(self, policy=None, keys=(), options=(), paths=(), **kwargs):
        args = []
        if policy:
            args += ["--policy", json.dumps({k: yaml_text(v) for k, v in policy.items()}, sort_keys=True)]
        for key in keys:
            args += ["--allow-key", key]
        for option in options:
            args += ["--allow", option]
        for path in paths:
            args += ["--allow-path", path]
        return args


class SSHVectorScanner(Scanner):
    def __init__(self, runner=None, allowlist=None, keys=None):
        super().__init__(runner)
        self.allowlist = ALLOWLIST if allowlist is None else allowlist
        self.keys = team_keys() if keys is None else tuple(keys)

    def remote_step(self, target):
        variables = getattr(target, "vars", None) or {}
        code, declared = self.allowlist.get(getattr(target, "host", None), SSHAllow()), declared_allow(variables)
        return ScanSSHVectors(self.runner, policy=declared_policy(variables),
                              keys=(*self.keys, *code.keys, *declared.keys),
                              options=(*code.options, *declared.options), paths=(*code.paths, *declared.paths))

    def findings(self, target, row):
        kind = row["kind"]
        if kind == "sshd-option":
            return [UnexpectedSSHOption(target, row["option"], row["value"], row["why"], row["severity"],
                                        tuple(row.get("contexts", ())))]
        if kind == "sshd-policy":
            return [SSHPolicyDeviation(target, row["option"], row["value"], row["wanted"], tuple(row.get("contexts", ())))]
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
