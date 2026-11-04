"""PermissionDrift: a path whose mode/owner should be something else.

Both LSE (permission rows) and the integrity scanner emit it. Equality ignores
`tier` and `source`, so the same drift seen by both collapses to one finding.
"""
from dataclasses import dataclass, field

from ccdc.findings import Finding

KEYS = ("mode", "uid", "gid")


@dataclass(frozen=True)
class PermissionDrift(Finding):
    path: str
    mode: int  # what it should be
    uid: int
    gid: int
    was: tuple  # (mode, uid, gid) observed
    tier: str = field(default="all", compare=False)  # 'simple' = mode-only change
    source: str = field(default="", compare=False)
    code = "permission-drift"

    @property
    def summary(self):
        parts = []
        if self.mode != self.was[0]:
            parts.append(f"mode {self.was[0]:04o} -> {self.mode:04o}")
        if (self.uid, self.gid) != self.was[1:]:
            parts.append(f"owner {self.was[1]}:{self.was[2]} -> {self.uid}:{self.gid}")
        return f"{self.path}: " + ", ".join(parts)


def drift_from_fix(target, fix, source):
    """A PermissionDrift from an LSE/integrity fix dict, or None if it is not a valid permission fix."""
    if not isinstance(fix, dict) or fix.get("kind") == "sysctl":
        return None
    try:
        values = [fix[key] for key in KEYS]
        was = tuple(fix["was"][key] for key in KEYS)
        path = fix["path"]
    except (KeyError, TypeError):
        return None
    if (not isinstance(path, str) or not path.startswith("/")
            or not all(type(v) is int and v >= 0 for v in (*values, *was))):
        return None
    return PermissionDrift(target, path, *values, was, fix.get("tier", "all"), source)
