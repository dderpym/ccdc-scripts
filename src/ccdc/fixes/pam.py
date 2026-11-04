from ccdc.findings import AutoFix
from ccdc.scanners.pam import PamExecHook, PamForeignModule, PamModuleModified, PamStrayFile
from ccdc.script import ComposedScript, Step
from ccdc.scripts.pam import PamGate, RemovePamFile, RemovePamLine, ReinstallPam


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
