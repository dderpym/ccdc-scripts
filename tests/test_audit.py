from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ccdc import registry  # noqa: E402
from ccdc.fixes.audit_rules import FixAuditWatches  # noqa: E402
from ccdc.packages import InstallAuditd, UnsupportedOS  # noqa: E402
from ccdc.scanners.audit_rules import AuditRulesScanner, AuditWatchMissing  # noqa: E402
from ccdc.scripts.audit import EnableAuditWatches  # noqa: E402
from ccdc.target import Target  # noqa: E402
from host import install_audit_rules, scan_audit_rules  # noqa: E402
from host.audit_watches import WATCHES, missing_watches, rules_text  # noqa: E402

TARGET = Target("web01")


class Fake:
    def __init__(self, os_family, **entries):
        self.entries = {"detect_os": {"id": "x", "id_like": "", "version": "1", "family": os_family}, **entries}
        self.calls = []

    def entry(self, target, entry, args=(), **request):
        self.calls.append((entry, list(args)))
        return self.entries[entry]


class Done:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


class AuditdPackages(unittest.TestCase):
    def test_package_name_per_family(self):
        for family, manager, package in (("debian", "apt", "auditd"), ("rhel", "dnf", "audit"), ("alpine", "apk", "audit")):
            fake = Fake(family, install_packages={"installed": [], "already": []})
            InstallAuditd(fake).run(TARGET)
            self.assertEqual(fake.calls[-1], ("install_packages", [manager, package]))

    def test_unsupported(self):
        with self.assertRaises(UnsupportedOS):
            InstallAuditd(Fake("void")).run(TARGET)


class Composed(unittest.TestCase):
    def test_installs_then_loads_rules(self):
        fake = Fake("debian", install_packages={}, install_audit_rules={"changed": True, "missing": []})
        EnableAuditWatches(fake).run(target=TARGET)
        self.assertEqual([c[0] for c in fake.calls], ["detect_os", "install_packages", "install_audit_rules"])


class HostRules(unittest.TestCase):
    def test_rules_cover_all_paths(self):
        text = rules_text()
        for path, key in WATCHES:
            self.assertIn(f"-w {path} -p wa -k {key}", text)

    def test_missing_watches(self):
        listing = "-w /etc/pam.d -p wa -k ccdc-pam\n"
        self.assertNotIn("/etc/pam.d", missing_watches(listing))
        self.assertIn("/etc/ssh", missing_watches(listing))

    def test_install_writes_then_is_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "rules.d" / "99-ccdc.rules")
            seen = []

            def run(argv, **kw):
                seen.append(argv[0])
                if argv[:2] == ["auditctl", "-l"]:
                    return Done(0, rules_text() if "augenrules" in seen else "")
                return Done(0)
            self.assertEqual(install_audit_rules.install(path, run), {"changed": True, "missing": []})
            self.assertEqual(Path(path).read_text(), rules_text())
            again = install_audit_rules.install(path, lambda argv, **kw: Done(0, rules_text()))
            self.assertEqual(again, {"changed": False, "missing": []})

    def test_falls_back_to_auditctl(self):
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "r.rules")
            seen = []

            def run(argv, **kw):
                seen.append(argv[:2])
                if argv[0] == "augenrules":
                    return Done(1)
                if argv[:2] == ["auditctl", "-l"]:
                    return Done(0, rules_text() if ["auditctl", "-R"] in seen else "")
                return Done(0)
            self.assertEqual(install_audit_rules.install(path, run)["missing"], [])

    def test_scan_host(self):
        out = scan_audit_rules.scan(lambda *a, **k: Done(0, rules_text()), lambda n: "/sbin/auditctl")
        self.assertEqual(out["findings"], [])
        out = scan_audit_rules.scan(which=lambda n: None)
        self.assertEqual(len(out["findings"]), len(WATCHES))
        self.assertTrue(out["errors"])


class ScannerAndFix(unittest.TestCase):
    def test_scanner_and_fix(self):
        fake = Fake("debian", scan_audit_rules={"findings": [{"watch": "/etc/ssh"}], "errors": []})
        result = AuditRulesScanner(fake).run(TARGET)
        self.assertEqual(list(result), [AuditWatchMissing(TARGET, "/etc/ssh")])
        self.assertTrue(FixAuditWatches().can_fix(result[0]))
        self.assertTrue(registry.global_autofix().can_fix(result[0]))
        self.assertIn(AuditRulesScanner, [type(s) for s in registry.scanners()])


if __name__ == "__main__":
    unittest.main()
