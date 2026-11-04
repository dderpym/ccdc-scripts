from ccdc.findings import AutoFix
from ccdc.scanners.ld_preload import LibraryInjection
from scripts.fix.ld_preload import RemoveLibraryInjection


class FixLibraryInjection(AutoFix):
    def can_fix(self, finding):
        return isinstance(finding, LibraryInjection)

    def get_fix(self, finding):
        variable = "" if finding.variable == "ld.so.preload" else finding.variable
        return RemoveLibraryInjection().bind(target=finding.host, path=finding.file,
                                             unit=finding.unit, variable=variable)

    def describe(self, finding):
        restart = f" and restart {finding.unit}" if finding.unit else ""
        return f"remove {finding.variable} from {finding.file}{restart} (backup in /root/ir)"
