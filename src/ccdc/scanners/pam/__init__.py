"""PAM as active on the host: effective per-service stacks, loaded modules, package integrity."""
from dataclasses import dataclass

from ccdc.ansible import AnsibleScript
from ccdc.findings import Finding, Scanner


def runs_for(services, file):
    """'chpasswd, passwd and 3 more (via common-password)': who is affected, and where the rule lives."""
    name = file.rsplit("/", 1)[-1]
    others = [s for s in services if s != name] or [name]
    shown = ", ".join(others[:6]) + (f" and {len(others) - 6} more" if len(others) > 6 else "")
    return shown if others == [name] else f"{shown} (via {name})"


@dataclass(frozen=True)
class PamExecHook(Finding):
    """A pam_exec/pam_script rule in the effective stack of `services`; file/line locate it for the fix."""
    file: str
    line: str
    payload: str
    expose_authtok: bool
    services: tuple = ()
    code = "pam-exec-hook"
    severity = "critical"

    @property
    def summary(self):
        captured = " (receives plaintext passwords)" if self.expose_authtok else ""
        return f"{runs_for(list(self.services), self.file)} run pam_exec/pam_script{captured}: {self.line.strip()}"


@dataclass(frozen=True)
class PamForeignModule(Finding):
    file: str
    line: str
    module: str
    services: tuple = ()
    code = "pam-foreign-module"
    severity = "critical"

    @property
    def summary(self):
        return f"{runs_for(list(self.services), self.file)} load a PAM module outside system security dirs: {self.module}"


@dataclass(frozen=True)
class PamMappedModule(Finding):
    """A PAM module loaded into a running process that is deleted, foreign or unowned. Report-only."""
    path: str
    reason: str
    pids: tuple = ()
    code = "pam-mapped-module"
    severity = "critical"

    @property
    def summary(self):
        return f"{self.path} is loaded by running processes {list(self.pids)}: {self.reason}"


@dataclass(frozen=True)
class PamStrayFile(Finding):
    path: str
    reason: str
    code = "pam-stray-file"
    severity = "critical"

    @property
    def summary(self):
        return f"{self.path}: {self.reason}"


@dataclass(frozen=True)
class PamModuleModified(Finding):
    path: str
    detail: str
    code = "pam-module-modified"
    severity = "critical"

    @property
    def summary(self):
        return f"{self.path} fails package verification ({self.detail})"


class ScanPam(AnsibleScript):
    """Prints {"findings": [pam-* rows], "errors": [...]}: effective stacks, mapped modules, package verify."""
    source = "remote.py"
    support = ("pkgowner.py",)


class PamScanner(Scanner):
    def remote_step(self, target):
        return ScanPam(self.runner)

    def findings(self, target, row):
        kind = row["kind"]
        if kind == "pam-exec":
            return [PamExecHook(target, row["file"], row["line"], row["payload"], row["expose_authtok"],
                                tuple(row.get("services", ())))]
        if kind == "pam-foreign-module":
            return [PamForeignModule(target, row["file"], row["line"], row["module"], tuple(row.get("services", ())))]
        if kind == "pam-mapped-module":
            return [PamMappedModule(target, row["path"], row["reason"], tuple(row.get("pids", ())))]
        if kind == "pam-stray-file":
            return [PamStrayFile(target, row["path"], row["reason"])]
        if kind == "pam-module-modified":
            return [PamModuleModified(target, row["path"], row["detail"])]
        return []
