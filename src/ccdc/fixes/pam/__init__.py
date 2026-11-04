"""Remediation: remove PAM hooks and restore the distribution modules."""
from ccdc.ansible import AnsibleScript
from ccdc.findings import AutoFix
from ccdc.osinfo import DetectOS
from ccdc.scanners.pam import PamExecHook, PamForeignModule, PamModuleModified, PamStrayFile
from ccdc.script import ComposedScript, HostScript, Step
from scripts.init.pam_gate import PamGate


MANAGERS = {"debian": "apt", "rhel": "dnf", "suse": "zypper"}


class PamRepair(AnsibleScript):
    """One remote.py with three actions (remove-line, remove-file, reinstall); each backs up first."""
    source = "remote.py"


class RemovePamLine(PamRepair):
    """Delete a rule (and optionally its payload file) from a /etc/pam.d file, with backup."""

    def arguments(self, file, line, payload_path="", **kwargs):
        return ["remove-line", file, line, *(["--payload", payload_path] if payload_path else [])]


class RemovePamFile(PamRepair):
    """Quarantine a stray file under /etc/pam.d or a security dir."""

    def arguments(self, path, **kwargs):
        return ["remove-file", path]


class _Reinstall(PamRepair):
    """Reinstall the PAM packages with the given manager (apt|dnf|yum|zypper)."""

    def arguments(self, manager, **kwargs):
        return ["reinstall", manager]


class ReinstallPam(HostScript):
    """Reinstall the PAM packages with the native manager, chosen by OS detection each run."""

    def __init__(self, runner=None):
        self.runner = runner

    def run(self, target):
        family = DetectOS(self.runner).run(target).family
        if family not in MANAGERS:
            raise RuntimeError(f"cannot reinstall PAM on {family} hosts")
        return _Reinstall(self.runner).run(target, manager=MANAGERS[family])


class FixPam(AutoFix):
    """Back up, remove the offending rule/file, reinstall pam, then re-verify the stack.

    Keep a second root SSH session open while this runs.
    """

    def can_fix(self, finding):
        return isinstance(finding, (PamExecHook, PamForeignModule, PamStrayFile, PamModuleModified))

    def get_fix(self, finding):
        target = finding.host
        tail = [Step(ReinstallPam(), target=target), Step(PamGate(), target=target)]
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
