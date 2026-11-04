from ccdc.ansible import EntryScript
from ccdc.findings import AutoFix
from ccdc.scanners.permissions import PermissionDrift


class SetPermissions(EntryScript):
    """Clear mode bits (octal string), set an exact mode/owner, optionally chown to root:root."""
    entry = "fix_permissions"

    def arguments(self, path, clear="0", root=False, mode=None, uid=None, gid=None, **kwargs):
        extra = [] if mode is None else ["--mode", mode]
        extra += [] if uid is None else ["--uid", str(uid)]
        extra += [] if gid is None else ["--gid", str(gid)]
        return [path, "--clear", clear, *extra, *(["--root"] if root else [])]


class RestorePermissions(AutoFix):
    def can_fix(self, finding):
        return isinstance(finding, PermissionDrift)

    def get_fix(self, finding):
        return SetPermissions().bind(target=finding.host, path=finding.path, mode=format(finding.mode, "o"),
                                     uid=finding.uid, gid=finding.gid)

    def describe(self, finding):
        return "restore " + finding.summary
