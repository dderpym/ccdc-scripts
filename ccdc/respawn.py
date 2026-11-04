"""Respawn guard: after fixing, wait, rescan, and say which findings came back.

Planted artifacts re-appear minutes after a cleanup, so "fixed" only counts once a
rescan after the watchdogs' restart delay is still clean.
"""
import time
from dataclasses import dataclass, field

from ccdc.script import Script

SLACK = 10  # seconds beyond the largest RestartSec


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


class VerifyStaysFixed(Script):
    """run(target, before): wait, rescan, then optionally fast-poll cheap scanners.

    `before` is the finding list from the scan that preceded the fixes, `fixed`
    the subset a fix was applied to (default: all). Fixed findings seen again are
    "returned"; findings not in `before` are "new"; unfixed leftovers are ignored.
    """

    def __init__(self, scanners, wait=0, poll_interval=0, poll_duration=0,
                 sleep=time.sleep, clock=time.monotonic):
        self.scanners, self.wait = scanners, wait
        self.poll_interval, self.poll_duration = poll_interval, poll_duration
        self.sleep, self.clock = sleep, clock

    def _scan(self, target, scanners):
        from ccdc.scan import scan_target
        return scan_target(target, scanners)

    def _merge(self, report, before, fixed, found, errors):
        returned, new = compare(before, found)
        returned = [f for f in returned if f in fixed]  # untouched findings are not "respawns"
        report.returned.extend(f for f in returned if f not in report.returned)
        report.new.extend(f for f in new if f not in report.new)
        report.errors.extend(e for e in errors if e not in report.errors)
        report.scans += 1

    def run(self, target, before=(), fixed=None):
        before = list(before)
        fixed = set(before if fixed is None else fixed)
        report = RespawnReport()
        self.sleep(settle_time(before, self.wait))
        self._merge(report, before, fixed, *self._scan(target, self.scanners))
        cheap = [s for s in self.scanners if getattr(s, "cheap", False)]
        if self.poll_interval > 0 and self.poll_duration > 0 and cheap:
            deadline = self.clock() + self.poll_duration
            while self.clock() < deadline:
                self.sleep(self.poll_interval)
                self._merge(report, before, fixed, *self._scan(target, cheap))
        return report


def verify_all(results, scanners, fixed=None, **options):
    """results: {target: (findings, errors)} from before the fixes -> {target: RespawnReport}.
    fixed: optional {target: [findings]} of what was actually fixed.

    Sleeps once per target sequentially; use ccdc.scan for parallel work if needed.
    """
    return {target: VerifyStaysFixed(scanners, **options).run(target, findings, (fixed or {}).get(target))
            for target, (findings, _) in results.items()}


def render(reports, out=print):
    bad = False
    for target, report in reports.items():
        out(f"\n=== {target} after settle ({report.scans} rescan(s)) ===")
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
