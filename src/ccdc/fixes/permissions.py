from ccdc.findings import AutoFix
from ccdc.scanners.permissions import PermissionDrift
from scripts.fix.permissions import SetPermissions


class RestorePermissions(AutoFix):
    def can_fix(self, finding):
        return isinstance(finding, PermissionDrift)

    def get_fix(self, finding):
        return SetPermissions().bind(target=finding.host, path=finding.path, mode=format(finding.mode, "o"),
                                     uid=finding.uid, gid=finding.gid)

    def describe(self, finding):
        return "restore " + finding.summary
