"""Respawn guard with a fake clock; no sleeping, no hosts."""
from dataclasses import dataclass
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ccdc import respawn  # noqa: E402
from ccdc.findings import Finding, ScanResult, Scanner  # noqa: E402
from ccdc.target import Target  # noqa: E402

T = Target("web01")


@dataclass(frozen=True)
class Planted(Finding):
    path: str
    restart_sec: int = 0
    code = "planted"


class Clock:
    def __init__(self):
        self.now, self.sleeps = 0.0, []

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds

    def __call__(self):
        return self.now


class Seq(Scanner):
    def __init__(self, *rounds, cheap=False):
        self.rounds, self.cheap, self.calls = list(rounds), cheap, 0

    def run(self, target):
        found = self.rounds[min(self.calls, len(self.rounds) - 1)]
        self.calls += 1
        return ScanResult(found, [])


class RescanGuardTests(unittest.TestCase):
    def test_stable_vanished_appeared(self):
        a, b, c = Planted(T, "/a"), Planted(T, "/b"), Planted(T, "/c")
        clock = Clock()
        guard = respawn.RescanGuard([Seq([a, b], [a, c])], delay=30, sleep=clock.sleep, clock=clock)
        report = guard.run(T)
        self.assertEqual((report.stable, report.vanished, report.appeared), ([a], [b], [c]))
        self.assertEqual(clock.sleeps, [30])
        self.assertTrue(report.changed)

    def test_unchanged_scan_is_not_changed(self):
        a = Planted(T, "/a")
        report = respawn.RescanGuard([Seq([a])], sleep=Clock().sleep).run(T)
        self.assertEqual(report.stable, [a])
        self.assertFalse(report.changed)

    def test_restart_sec_is_a_floor(self):
        clock = Clock()
        respawn.RescanGuard([Seq([Planted(T, "/a", 45)])], delay=5, sleep=clock.sleep).run(T)
        self.assertEqual(clock.sleeps, [45])

    def test_error_in_one_round_is_partial(self):
        class Flaky(Scanner):
            calls = 0

            def run(self, target):
                Flaky.calls += 1
                return ScanResult([], ["ssh timeout"] if Flaky.calls == 2 else [])
        report = respawn.RescanGuard([Flaky()], sleep=Clock().sleep).run(T)
        self.assertTrue(report.partial)
        self.assertTrue(report.changed)
        self.assertEqual(len(report.errors), 1)

    def test_seeded_first_round_skips_initial_scan(self):
        a, scanner = Planted(T, "/a"), Seq([])
        report = respawn.RescanGuard([scanner], sleep=Clock().sleep).run(T, ([a], []))
        self.assertEqual(scanner.calls, 1)
        self.assertEqual(report.vanished, [a])

    def test_hosts_share_one_delay(self):
        import threading
        t2 = Target("web02")
        lock, sleeps = threading.Lock(), []

        def sleep(seconds):
            with lock:
                sleeps.append(seconds)
        reports = respawn.guard_all([T, t2], [Seq([])], delay=60, sleep=sleep)
        self.assertEqual(set(reports), {T, t2})
        self.assertEqual(sleeps, [60, 60])  # concurrent: two sleeps of 60, not one of 120

    def test_render_guard(self):
        a = Planted(T, "/a")
        reports = {T: respawn.RescanGuard([Seq([a], [])], sleep=Clock().sleep).run(T)}
        lines = []
        self.assertTrue(respawn.render_guard(reports, lines.append))
        self.assertTrue(any("VANISHED" in l for l in lines))


class RespawnTests(unittest.TestCase):
    def test_wait_uses_largest_restartsec_plus_slack(self):
        self.assertEqual(respawn.settle_time([Planted(T, "a", 30)], wait=5), 40)
        self.assertEqual(respawn.settle_time([], wait=20), 30)

    def test_returned_vs_new(self):
        a, b = Planted(T, "/a"), Planted(T, "/b")
        clock = Clock()
        guard = respawn.VerifyStaysFixed([Seq([a, b])], wait=0, sleep=clock.sleep, clock=clock)
        report = guard.run(T, before=[a], fixed=[a])
        self.assertEqual((report.returned, report.new), ([a], [b]))
        self.assertEqual(clock.sleeps, [10])
        self.assertFalse(report.clean)

    def test_unfixed_leftover_is_not_a_respawn(self):
        a = Planted(T, "/a")
        report = respawn.VerifyStaysFixed([Seq([a])], sleep=Clock().sleep).run(T, [a], fixed=[])
        self.assertTrue(report.clean)

    def test_fast_poll_runs_only_cheap_scanners_and_catches_late_replant(self):
        a = Planted(T, "/a")
        slow, cheap = Seq([], cheap=False), Seq([], [], [a], cheap=True)
        clock = Clock()
        guard = respawn.VerifyStaysFixed([slow, cheap], poll_interval=5, poll_duration=20,
                                         sleep=clock.sleep, clock=clock)
        report = guard.run(T, [a])
        self.assertEqual(slow.calls, 1)
        self.assertEqual(cheap.calls, 1 + 4)
        self.assertEqual(report.returned, [a])
        self.assertEqual(report.scans, 5)

    def test_render_and_verify_all(self):
        a = Planted(T, "/a")
        reports = respawn.verify_all({T: ([a], [])}, [Seq([a])], {T: [a]}, sleep=Clock().sleep)
        lines = []
        self.assertTrue(respawn.render(reports, lines.append))
        self.assertTrue(any("RETURNED" in l for l in lines))

    def test_is_a_script_in_a_composition(self):
        from ccdc.script import ComposedScript, Step
        guard = respawn.VerifyStaysFixed([Seq([])], sleep=Clock().sleep)
        [report] = ComposedScript(Step(guard, before=[])).run(target=T)
        self.assertTrue(report.clean)


if __name__ == "__main__":
    unittest.main()
