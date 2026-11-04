"""Auto-discovery: every Scanner in ccdc.scanners and AutoFix in ccdc.fixes is registered.

Adding a feature means adding a module to one of those packages; no list to edit.
A module may define PRIORITY (int, default 0) for each of its AutoFix classes via
a `PRIORITY = {ClassName: n}` mapping.
"""
import importlib
import inspect
import pkgutil

from ccdc.findings import AutoFix, GlobalAutofix, Scanner


def _modules(package):
    module = importlib.import_module(package)
    for info in pkgutil.iter_modules(module.__path__):
        yield importlib.import_module(f"{package}.{info.name}")


def _classes(package, base):
    for module in _modules(package):
        for _, cls in inspect.getmembers(module, inspect.isclass):
            if (issubclass(cls, base) and cls.__module__ == module.__name__
                    and not inspect.isabstract(cls) and not cls.__dict__.get("abstract", False)):
                yield module, cls


def scanners(runner=None):
    return [cls(runner) for _, cls in _classes("ccdc.scanners", Scanner)]


def global_autofix():
    registry = GlobalAutofix()
    for module, cls in _classes("ccdc.fixes", AutoFix):
        registry.register(cls(), getattr(module, "PRIORITY", {}).get(cls, 0))
    return registry
