"""Rescan guard: scan, wait, scan again, say what changed.

RescanGuard knows nothing about fixes: give it any scanners and it reports which
findings stayed, vanished or appeared. VerifyStaysFixed is a thin layer on top that
is seeded with the pre-fix findings and reports which *fixed* findings came back,
the usual sign of a watchdog re-planting an artifact.
"""
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from ccdc.script import HostScript

SLACK = 10  # seconds beyond the largest RestartSec, for fix verification


@dataclass
class GuardReport:
    stable: list = field(default_factory=list)    # in the first and the last full scan
    vanished: list = field(default_factory=list)  # in the first, gone from the last
    appeared: list = field(default_factory=list)  # in a later round, not in the first
    seen_later: list = field(default_factory=list)  # everything any later round saw
    errors: list = field(default_factory=list)    # scan errors from every round
    partial: list = field(default_factory=list)   # errors from one round only: coverage differed
    scans: int = 0

    @property
    def changed(self):
        return bool(self.vanished or self.appeared or self.partial)


@dataclass
class RespawnReport:
    returned: list = field(default_factory=list)  # fixed earlier, present again
    new: list = field(default_factory=list)       # not present before at all
    errors: list = field(default_factory=list)
    scans: int = 0

    @property
    def clean(self):
        return not (self.returned or self.new or self.errors)


def settle_time(findings, wait=0):
    """max(configured wait, largest RestartSec any finding reports) + SLACK."""
    restarts = [getattr(f, "restart_sec", 0) or 0 for f in findings]
    return max([wait, *restarts]) + SLACK


def compare(before, after):
    before_set = set(before)
    return [f for f in after if f in before_set], [f for f in after if f not in before_set]


def _unique(items):
    return list(dict.fromkeys(items))


def _scan(target, scanners):
    from ccdc.scan import scan_target
    return scan_target(target, scanners)


class RescanGuard(HostScript):
    """run(target, first=None): scan (or take `first` as the earlier scan), sleep, scan again.

    delay is a floor: if the first findings carry `restart_sec` hints the wait is at
    least that long.
    """

    def __init__(self, scanners, delay=0, sleep=time.sleep):
        self.scanners, self.delay = scanners, delay
        self.sleep = sleep

    def wait_for(self, first):
        hints = [getattr(f, "restart_sec", 0) or 0 for f in first]
        return max([self.delay, *hints])

    def run(self, target, first=None):
        scans = 1 if first is None else 0  # only scans this guard ran itself
        found, first_errors = _scan(target, self.scanners) if first is None else first
        self.sleep(self.wait_for(found))
        last, last_errors = _scan(target, self.scanners)
        seen_later = list(last)
        scans += 1
        stable, vanished = compare(last, found)[0], compare(last, found)[1]
        seen_later = _unique(seen_later)
        return GuardReport(
            stable=stable, vanished=vanished,
            appeared=[f for f in seen_later if f not in set(found)],
            seen_later=seen_later,
            errors=_unique([*first_errors, *last_errors]),
            partial=sorted(set(first_errors) ^ set(last_errors)), scans=scans)


class VerifyStaysFixed(RescanGuard):
    """run(target, before, fixed=None): `before` is the scan that preceded the fixes,
    `fixed` the subset a fix was applied to (default: all). Fixed findings seen again
    are "returned"; findings not in `before` are "new"; unfixed leftovers are ignored."""

    def __init__(self, scanners, wait=0, **options):
        super().__init__(scanners, **options)
        self.wait = wait

    def wait_for(self, first):
        return settle_time(first, self.wait)

    def run(self, target, before=(), fixed=None):
        before = list(before)
        fixed = set(before if fixed is None else fixed)
        guard = super().run(target, first=(before, []))
        return RespawnReport(
            returned=[f for f in guard.seen_later if f in fixed],
            new=guard.appeared, errors=guard.errors, scans=guard.scans)


def _parallel(function, items):
    # Threads mostly sleep, so one per target makes N hosts cost one delay, not N.
    items = list(items)
    if not items:
        return {}
    with ThreadPoolExecutor(max_workers=len(items)) as pool:
        return dict(zip((key for key, _ in items), pool.map(function, items)))


def guard_all(targets, scanners, seeded=None, **options):
    """RescanGuard on every target concurrently. seeded: {target: (findings, errors)} of an
    earlier scan to use as the first round instead of scanning again."""
    seeded = seeded or {}
    return _parallel(lambda item: RescanGuard(scanners, **options).run(item[0], seeded.get(item[0])),
                     ((target, None) for target in targets))


def verify_all(results, scanners, fixed=None, **options):
    """results: {target: (findings, errors)} from before the fixes -> {target: RespawnReport}.
    fixed: optional {target: [findings]} of what was actually fixed."""
    return _parallel(lambda item: VerifyStaysFixed(scanners, **options).run(
        item[0], item[1][0], (fixed or {}).get(item[0])), results.items())


def render_guard(reports, out=print):
    changed = False
    for target, report in reports.items():
        out(f"\n=== {target} after rescan ({report.scans} scan(s)) ===")
        out(f"  {len(report.stable)} finding(s) unchanged")
        for finding in report.vanished:
            out(f"  VANISHED {finding.summary}")
        for finding in report.appeared:
            out(f"  APPEARED {finding.summary}")
        for error in report.partial[:10]:
            out(f"  WARNING scanner coverage differed between rounds: {error}")
        for error in report.errors[:10]:
            if error not in report.partial:
                out(f"  WARNING scanner: {error}")
        changed = changed or report.changed or bool(report.errors)
    return changed


def render(reports, out=print):
    bad = False
    for target, report in reports.items():
        out(f"\n=== {target} after settle ({report.scans} scan(s)) ===")
        for finding in report.returned:
            out(f"  RETURNED {finding.summary}")
        for finding in report.new:
            out(f"  NEW      {finding.summary}")
        for error in report.errors[:10]:
            out(f"  WARNING scanner: {error}")
        if report.clean:
            out("  nothing came back")
        bad = bad or not report.clean
    return bad
