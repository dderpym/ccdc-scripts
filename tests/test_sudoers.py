import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ccdc.fixes.sudoers import FixSudoersGrant  # noqa: E402
from ccdc.scanners.sudoers import SudoersScanner, SudoersUnexpectedNopasswd, SudoersWorldGrant  # noqa: E402
from ccdc.target import Target  # noqa: E402
from host import fix_sudoers, scan_sudoers  # noqa: E402
from tests.test_framework import FakeRunner  # noqa: E402

T = Target("h")
FILES = {
    "/etc/sudoers": "Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n"
                    "# ALL ALL=(ALL) NOPASSWD: ALL\nALL ALL=(ALL) NOPASSWD: ALL\n"
                    "#includedir /etc/sudoers.d\n",
    "/etc/sudoers.d/oski": "Defaults:oski !requiretty\noski ALL=(ALL:ALL) NOPASSWD: ALL\n",
    "/etc/sudoers.d/evil": "bob ALL=(ALL) \\\n NOPASSWD: ALL\n",
    "/etc/sudoers.d/skipped.bak": "eve ALL=(ALL) NOPASSWD: ALL\n",
}


def audit():
    result = {"findings": [], "errors": []}
    scan_sudoers.audit("/etc/sudoers", result, read=lambda p: FILES[p],
                       read_dir=lambda d: [n.rsplit("/", 1)[1] for n in FILES if n.startswith(d + "/")])
    return result


class Scan(unittest.TestCase):
    def test_flags_only_unexpected_grants(self):
        result = audit()
        self.assertEqual([(f["kind"], f["file"], f["line"]) for f in result["findings"]],
                         [("world", "/etc/sudoers", 5), ("nopasswd", "/etc/sudoers.d/evil", 1)])
        self.assertEqual(result["errors"], [])

    def test_unreadable_file_is_an_error_not_clean(self):
        result = {"findings": [], "errors": []}
        scan_sudoers.audit("/nonexistent/sudoers", result)
        self.assertTrue(result["errors"])

    def test_include_cycle_terminates(self):
        files = {"/a": "@include /b\n", "/b": "@include /a\nALL ALL=(ALL) ALL\n"}
        result = {"findings": [], "errors": []}
        scan_sudoers.audit("/a", result, read=lambda p: files[p])
        self.assertEqual(len(result["findings"]), 1)

    def test_controller_types_and_fix(self):
        found = list(SudoersScanner(FakeRunner(scan_sudoers=audit())).run(T))
        self.assertIsInstance(found[0], SudoersWorldGrant)
        self.assertIsInstance(found[1], SudoersUnexpectedNopasswd)
        fix = FixSudoersGrant()
        self.assertTrue(all(fix.can_fix(f) for f in found))
        fixer = FakeRunner(fix_sudoers={})
        script = fix.get_fix(found[0])
        script.steps[0].script.runner = fixer
        script.run()
        self.assertEqual(fixer.calls, [("h", "fix_sudoers", ["/etc/sudoers", "ALL ALL=(ALL) NOPASSWD: ALL"])])


class Fix(unittest.TestCase):
    LINE = "ALL ALL=(ALL) NOPASSWD: ALL"

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = os.path.join(self.dir.name, "sudoers")
        Path(self.path).write_text("root ALL=(ALL) ALL\n" + self.LINE + "\n")
        self.evidence = os.path.join(self.dir.name, "ir")
        allow = unittest.mock.patch.object(fix_sudoers, "allowed", lambda p: p == self.path)
        allow.start()
        self.addCleanup(allow.stop)
        chown = unittest.mock.patch("os.chown")
        chown.start()
        self.addCleanup(chown.stop)

    @staticmethod
    def runner(*codes):
        results = iter(codes)
        return lambda argv, **kw: subprocess.CompletedProcess(argv, next(results))

    def test_removes_line_keeps_evidence(self):
        out = fix_sudoers.fix(self.path, self.LINE, self.evidence, self.runner(0, 0, 0), "visudo")
        self.assertEqual(out["removed"], 1)
        self.assertEqual(Path(self.path).read_text(), "root ALL=(ALL) ALL\n")
        self.assertIn("NOPASSWD", Path(out["evidence"], "sudoers").read_text())
        self.assertEqual(os.stat(out["evidence"]).st_mode & 0o777, 0o700)

    def test_restores_when_final_validation_fails(self):
        original = Path(self.path).read_text()
        with self.assertRaises(RuntimeError):
            fix_sudoers.fix(self.path, self.LINE, self.evidence, self.runner(0, 0, 1), "visudo")
        self.assertEqual(Path(self.path).read_text(), original)
        self.assertNotIn("sudoers.ccdc-new", os.listdir(self.dir.name))

    def test_edit_failing_check_leaves_original(self):
        original = Path(self.path).read_text()
        with self.assertRaises(RuntimeError):
            fix_sudoers.fix(self.path, self.LINE, self.evidence, self.runner(0, 1), "visudo")
        self.assertEqual(Path(self.path).read_text(), original)
        self.assertNotIn("sudoers.ccdc-new", os.listdir(self.dir.name))

    def test_refuses_invalid_config_and_foreign_paths(self):
        with self.assertRaises(RuntimeError):
            fix_sudoers.fix(self.path, "x", self.evidence, self.runner(1), "visudo")
        with self.assertRaises(ValueError):
            fix_sudoers.fix("/etc/passwd", "x", self.evidence, self.runner(0), "visudo")


if __name__ == "__main__":
    unittest.main()
