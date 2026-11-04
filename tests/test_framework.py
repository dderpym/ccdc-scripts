"""Script/Composed/Scanner/AutoFix plumbing with a fake runner; never touches a host."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ccdc import registry, scan  # noqa: E402
from ccdc.findings import AutoFix, GlobalAutofix, Finding, Scanner  # noqa: E402
from ccdc.fixes.suid import FixSUIDBinary  # noqa: E402
from ccdc.osinfo import DetectOS  # noqa: E402
from ccdc.packages import InstallNftables, UnsupportedOS  # noqa: E402
from ccdc.scanners.suid import SUIDScanner, UncommonSUIDBinary, WritableSUIDBinary  # noqa: E402
from ccdc.script import ComposedScript, Script, Step  # noqa: E402
from ccdc.target import PasswordAuth, Target  # noqa: E402
from host import detect_os, install_packages  # noqa: E402

TARGET = Target("web01")


class FakeRunner:
    def __init__(self, **entries):
        self.entries, self.calls = entries, []

    def entry(self, target, entry, args=(), **request):
        self.calls.append((target.host, entry, list(args)))
        response = self.entries[entry]
        return response(args) if callable(response) else response


class Record(Script):
    def __init__(self):
        self.calls = []

    def run(self, target, password="x"):
        self.calls.append((target, password))
        return password


class ComposedTests(unittest.TestCase):
    def test_prefill_and_injection(self):
        a, b = Record(), Record()
        composed = ComposedScript(Step(a, password="super_secure"), b)
        self.assertEqual(composed.run(target=TARGET), ["super_secure", "x"])
        composed.run(target=TARGET, password="new", unrelated=1)
        self.assertEqual(a.calls[-1][1], "new")
        self.assertEqual(b.calls[-1][1], "new")

    def test_bind_prefills(self):
        record = Record()
        self.assertEqual(record.bind(target=TARGET).run(), ["x"])

    def test_failure_stops_sequence(self):
        class Boom(Script):
            def run(self):
                raise RuntimeError("no")
        after = Record()
        with self.assertRaises(RuntimeError):
            ComposedScript(Boom(), Step(after, target=TARGET)).run()
        self.assertEqual(after.calls, [])

    def test_password_never_in_repr(self):
        self.assertNotIn("hunter2", repr(Target("h", PasswordAuth("root", "hunter2"))))


class OSAndPackages(unittest.TestCase):
    def test_family(self):
        self.assertEqual(detect_os.family("ubuntu"), "debian")
        self.assertEqual(detect_os.family("rocky", "rhel centos fedora"), "rhel")
        self.assertEqual(detect_os.family("pop", "ubuntu debian"), "debian")
        self.assertEqual(detect_os.family("tinycore"), "unknown")

    def test_install_delegates_by_os(self):
        for family, manager in (("debian", "apt"), ("rhel", "dnf"), ("alpine", "apk")):
            runner = FakeRunner(detect_os={"id": "x", "id_like": "", "version": "1", "family": family},
                                install_packages={"installed": [], "already": []})
            InstallNftables(runner).run(TARGET)
            self.assertEqual(runner.calls[-1][1:], ("install_packages", [manager, "nftables"]))

    def test_unknown_os_refused(self):
        runner = FakeRunner(detect_os={"id": "tc", "id_like": "", "version": "", "family": "unknown"})
        with self.assertRaises(UnsupportedOS):
            InstallNftables(runner).run(TARGET)

    def test_installer_only_installs_missing(self):
        calls = []

        class R:
            def __init__(self, returncode, stdout=""):
                self.returncode, self.stdout = returncode, stdout

        def run(argv, **kw):
            calls.append(argv)
            if argv[0] == "rpm":
                return R(0 if argv[-1] == "have" else 1)
            return R(0)
        result = install_packages.install("dnf", ["have", "need"], run)
        self.assertEqual(result, {"installed": ["need"], "already": ["have"]})
        self.assertEqual(calls[-1], ["dnf", "install", "-y", "need"])


class ScannerAutofix(unittest.TestCase):
    ROW = {"id": "fst030", "severity": "critical", "summary": "Writable setuid binaries",
           "context": [{"summary": "s", "evidence": ["-rwsrwxrwx root root /usr/bin/evil"]}]}

    def test_suid_scanner_and_fix(self):
        runner = FakeRunner(discover_lse={"findings": [self.ROW], "errors": ["partial"]})
        result = SUIDScanner(runner).run(TARGET)
        self.assertEqual(list(result), [WritableSUIDBinary(TARGET, "/usr/bin/evil", "-rwsrwxrwx")])
        self.assertEqual(result.errors, ["partial"])
        self.assertEqual(runner.calls[0][2], ["--only", "fst020,fst030"])
        fix = FixSUIDBinary()
        self.assertTrue(fix.can_fix(result[0]))
        self.assertFalse(fix.can_fix(UncommonSUIDBinary(TARGET, "/x", "-rwsr-xr-x")))
        fixer = FakeRunner(fix_permissions={"path": "/usr/bin/evil"})
        script = fix.get_fix(result[0])
        script.steps[0].script.runner = fixer
        script.run()
        self.assertEqual(fixer.calls, [("web01", "fix_permissions", ["/usr/bin/evil", "--clear", "022", "--root"])])

    def test_priority_picks_highest_then_first(self):
        class Always(AutoFix):
            def __init__(self, tag):
                self.tag = tag

            def can_fix(self, finding):
                return True

            def get_fix(self, finding):
                return self.tag
        registry_ = GlobalAutofix()
        finding = Finding(TARGET)
        self.assertFalse(registry_.can_fix(finding))
        registry_.register(Always("low"), 1)
        registry_.register(Always("high-first"), 5)
        registry_.register(Always("high-second"), 5)
        self.assertEqual(registry_.get_fix(finding), "high-first")

    def test_registry_discovers_scanner_and_fix(self):
        self.assertIn(SUIDScanner, [type(s) for s in registry.scanners()])
        self.assertTrue(registry.global_autofix().can_fix(WritableSUIDBinary(TARGET, "/a", "-rwsrwxrwx")))

    def test_scan_collects_and_dedupes(self):
        finding = WritableSUIDBinary(TARGET, "/a", "-rwsrwxrwx")

        class S(Scanner):
            name = "S"

            def run(self, target):
                from ccdc.findings import ScanResult
                return ScanResult([finding], ["gap"])
        findings, errors = scan.scan_target(TARGET, [S(), S()])
        self.assertEqual(findings, [finding])
        self.assertEqual(errors, ["S: gap", "S: gap"])

    def test_broken_scanner_is_reported_not_fatal(self):
        class Broken(Scanner):
            name = "Broken"

            def run(self, target):
                raise RuntimeError("ssh down")
        self.assertEqual(scan.scan_target(TARGET, [Broken()]), ([], ["Broken: ssh down"]))


if __name__ == "__main__":
    unittest.main()
