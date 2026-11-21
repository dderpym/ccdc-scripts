from ccdc.findings import AutoFix
from ccdc.scanners.suid import WritableSUIDBinary
from ccdc.fixes.permissions import SetPermissions


class FixSUIDBinary(AutoFix):
    def can_fix(self, finding):
        return isinstance(finding, WritableSUIDBinary)

    def get_fix(self, finding):
        return SetPermissions().bind(target=finding.host, path=finding.file, clear="022", root=True)

    def describe(self, finding):
        return f"remove group/other write from {finding.file} and make it root-owned"
