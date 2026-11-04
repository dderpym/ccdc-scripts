from ccdc.ansible import EntryScript
from ccdc.findings import AutoFix
from ccdc.scanners.ld_preload import LibraryInjection


class RemoveLibraryInjection(EntryScript):
    """Remove an injected variable (or file), restart the unit, confirm the library is unmapped."""
    entry = "fix_ld_preload"

    def arguments(self, path, unit="", variable="", **kwargs):
        return [path, *(["--unit", unit] if unit else []), *(["--var", variable] if variable else [])]

    def parse(self, document, **kwargs):
        if document.get("still_mapped"):
            raise RuntimeError("library still mapped after restart: " + ", ".join(document["still_mapped"]))
        return document


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
