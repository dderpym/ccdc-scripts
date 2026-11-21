from ccdc.ansible import AnsibleScript
from ccdc.findings import AutoFix
from ccdc.scanners.permissions import PermissionDrift


class SetPermissions(AnsibleScript):
    """Clear mode bits (octal string), set an exact mode/owner, optionally chown to root:root."""
    source = "remote.py"

    def arguments(self, path, clear="0", root=False, mode=None, uid=None, gid=None, **kwargs):
        extra = [] if mode is None else ["--mode", mode]
        extra += [] if uid is None else ["--uid", str(uid)]
        extra += [] if gid is None else ["--gid", str(gid)]
        return [path, "--clear", clear, *extra, *(["--root"] if root else [])]


class ApplyFixes(AnsibleScript):
    """Apply a reviewed JSON list of permission/sysctl fixes (the run's `payload` file arrives on stdin).

    Used by the interactive `ccdcctl lse|integrity` fix offers; live progress, returns success as a bool.
    """
    source = "remote_apply.py"
    support = ("sysctls.py",)
    stdin = True
    live = True


class RestorePermissions(AutoFix):
    def can_fix(self, finding):
        return isinstance(finding, PermissionDrift)

    def get_fix(self, finding):
        return SetPermissions().bind(target=finding.host, path=finding.path, mode=format(finding.mode, "o"),
                                     uid=finding.uid, gid=finding.gid)

    def describe(self, finding):
        return "restore " + finding.summary
