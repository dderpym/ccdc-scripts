"""PAM audit: credential-capturing hooks, foreign modules, stray/tampered modules."""
from dataclasses import dataclass

from ccdc.findings import BundleScanner, Finding


@dataclass(frozen=True)
class PamExecHook(Finding):
    file: str
    line: str
    payload: str
    expose_authtok: bool
    code = "pam-exec-hook"
    severity = "critical"

    @property
    def summary(self):
        captured = " (receives plaintext passwords)" if self.expose_authtok else ""
        return f"{self.file}: pam_exec/pam_script hook{captured}: {self.line.strip()}"


@dataclass(frozen=True)
class PamForeignModule(Finding):
    file: str
    line: str
    module: str
    code = "pam-foreign-module"
    severity = "critical"

    @property
    def summary(self):
        return f"{self.file}: PAM module outside system security dirs: {self.module}"


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


class PamScanner(BundleScanner):
    entry = "scan_pam"

    def findings(self, target, row):
        kind = row["kind"]
        if kind == "pam-exec":
            return [PamExecHook(target, row["file"], row["line"], row["payload"], row["expose_authtok"])]
        if kind == "pam-foreign-module":
            return [PamForeignModule(target, row["file"], row["line"], row["module"])]
        if kind == "pam-stray-file":
            return [PamStrayFile(target, row["path"], row["reason"])]
        if kind == "pam-module-modified":
            return [PamModuleModified(target, row["path"], row["detail"])]
        return []
