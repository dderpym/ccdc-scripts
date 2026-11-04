"""Remediation: remove PAM hooks and restore the distribution modules."""
from ccdc.ansible import AnsibleScript
from ccdc.findings import AutoFix
from ccdc.packages import InstallPam
from ccdc.scanners.pam import PamExecHook, PamForeignModule, PamModuleModified, PamStrayFile
from ccdc.script import ComposedScript, HostScript, Step
from scripts.init.pam_gate import PamGate



class PamRepair(AnsibleScript):
    """One remote.py with two actions (remove-line, remove-file); each backs up first."""
    source = "remote.py"


class RemovePamLine(PamRepair):
    """Delete a rule (and optionally its payload file) from a /etc/pam.d file, with backup."""

    def arguments(self, file, line, payload_path="", **kwargs):
        return ["remove-line", file, line, *(["--payload", payload_path] if payload_path else [])]


class RemovePamFile(PamRepair):
    """Quarantine a stray file under /etc/pam.d or a security dir."""

    def arguments(self, path, **kwargs):
        return ["remove-file", path]


class FixPam(AutoFix):
    """Back up, remove the offending rule/file, reinstall pam, then re-verify the stack.

    Keep a second root SSH session open while this runs.
    """

    def can_fix(self, finding):
        return isinstance(finding, (PamExecHook, PamForeignModule, PamStrayFile, PamModuleModified))

    def get_fix(self, finding):
        target = finding.host
        tail = [Step(InstallPam(reinstall=True), target=target), Step(PamGate(), target=target)]
        if isinstance(finding, PamExecHook):
            return ComposedScript(Step(RemovePamLine(), target=target, file=finding.file, line=finding.line,
                                       payload_path=finding.payload), *tail)
        if isinstance(finding, PamForeignModule):
            return ComposedScript(Step(RemovePamLine(), target=target, file=finding.file, line=finding.line), *tail)
        if isinstance(finding, PamStrayFile):
            return ComposedScript(Step(RemovePamFile(), target=target, path=finding.path), *tail)
        return ComposedScript(*tail)

    def describe(self, finding):
        return f"remove PAM tamper ({finding.code}), reinstall pam, re-verify; keep a second SSH session open"
