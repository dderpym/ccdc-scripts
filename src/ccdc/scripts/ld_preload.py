from ccdc.ansible import BundleScript


class RemoveLibraryInjection(BundleScript):
    """Remove an injected variable (or file), restart the unit, confirm the library is unmapped."""
    entry = "fix_ld_preload"

    def arguments(self, path, unit="", variable="", **kwargs):
        return [path, *(["--unit", unit] if unit else []), *(["--var", variable] if variable else [])]

    def parse(self, document, **kwargs):
        if document.get("still_mapped"):
            raise RuntimeError("library still mapped after restart: " + ", ".join(document["still_mapped"]))
        return document
