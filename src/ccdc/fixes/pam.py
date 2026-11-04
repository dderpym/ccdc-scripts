"""Remediation: remove PAM hooks and restore the distribution modules."""
from ccdc.ansible import EntryScript
from ccdc.findings import AutoFix
from ccdc.osinfo import DetectOS
from ccdc.scanners.pam import PamExecHook, PamForeignModule, PamModuleModified, PamStrayFile
from ccdc.script import ComposedScript, HostScript, Step
from scripts.init.pam_gate import PamGate


MANAGERS = {"debian": "apt", "rhel": "dnf", "suse": "zypper"}



class RemovePamLine(EntryScript):
    """Delete a rule (and optionally its payload file) from a /etc/pam.d file, with backup."""
    entry = "fix_pam"

    def arguments(self, file, line, payload="", **kwargs):
        return ["remove-line", file, line, *(["--payload", payload] if payload else [])]


class RemovePamFile(EntryScript):
    entry = "fix_pam"

    def arguments(self, path, **kwargs):
        return ["remove-file", path]


class _Reinstall(EntryScript):
    entry = "fix_pam"

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
                                       payload=finding.payload), *tail)
        if isinstance(finding, PamForeignModule):
            return ComposedScript(Step(RemovePamLine(), target=target, file=finding.file, line=finding.line), *tail)
        if isinstance(finding, PamStrayFile):
            return ComposedScript(Step(RemovePamFile(), target=target, path=finding.path), *tail)
        return ComposedScript(*tail)

    def describe(self, finding):
        return f"remove PAM tamper ({finding.code}), reinstall pam, re-verify; keep a second SSH session open"
