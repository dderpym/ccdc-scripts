"""PAM scanner, fix and gate; offline, temp dirs only."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ccdc import registry  # noqa: E402
from ccdc.fixes.pam import FixPam  # noqa: E402
from ccdc.scanners.pam import PamExecHook, PamMappedModule, PamScanner  # noqa: E402
from ccdc.scripts.pam import PamDirty, PamGate, gated  # noqa: E402
from ccdc.script import Script  # noqa: E402
from ccdc.target import Target  # noqa: E402
from host import fix_pam, scan_pam  # noqa: E402

TARGET = Target("web01")
HOOK = "password optional pam_exec.so quiet expose_authtok /usr/share/locale/en/unicode.so"


class FakeRunner:
    def __init__(self, **entries):
        self.entries, self.calls = entries, []

    def entry(self, target, entry, args=(), **request):
        self.calls.append((entry, list(args)))
        return self.entries[entry]


class HostScan(unittest.TestCase):
    def test_parse_lines(self):
        self.assertIsNone(scan_pam.parse_line("# comment"))
        self.assertIsNone(scan_pam.parse_line("@include common-auth"))
        self.assertEqual(scan_pam.parse_line("auth [success=1 default=ignore] pam_unix.so nullok"),
                         ("auth", "[success=1 default=ignore]", "pam_unix.so", ["nullok"]))

    DIRS = ["/lib/x86_64-linux-gnu/security"]

    def stack(self, files, services=None):
        errors = []
        with tempfile.TemporaryDirectory() as d:
            for name, text in files.items():
                Path(d, name).write_text(text)
            rows = scan_pam.stack_findings(d, services or sorted(files), self.DIRS, errors)
        return rows, errors

    def test_effective_stack_names_every_service_that_runs_the_hook(self):
        rows, errors = self.stack({
            "chpasswd": "@include common-password\n",
            "passwd": "password include common-password\n",
            "sshd": "auth include common-password\n",       # different type: hook is not in sshd's auth stack
            "common-password": "password required pam_unix.so\n" + HOOK + "\n",
        })
        self.assertEqual(errors, [])
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["kind"], rows[0]["line_no"]), ("pam-exec", 2))
        self.assertEqual(rows[0]["services"], ["chpasswd", "common-password", "passwd"])
        self.assertTrue(rows[0]["file"].endswith("common-password"))
        self.assertTrue(rows[0]["expose_authtok"])
        self.assertEqual(rows[0]["payload"], "/usr/share/locale/en/unicode.so")

    def test_substack_and_foreign_module(self):
        rows, _ = self.stack({"login": "auth substack extra\n", "extra": "auth required /tmp/evil.so\n"
                              "auth required /lib/x86_64-linux-gnu/security/pam_deny.so\n"})
        self.assertEqual([(r["kind"], r["module"]) for r in rows], [("pam-foreign-module", "/tmp/evil.so")])

    def test_unreachable_type_is_not_flagged_for_other_services(self):
        rows, _ = self.stack({"sshd": "auth include common-password\n", "common-password": HOOK + "\n"},
                             services=["sshd"])
        self.assertEqual(rows, [])

    def test_missing_include_and_loops_are_errors_not_clean(self):
        rows, errors = self.stack({"a": "@include missing\n"})
        self.assertEqual(rows, [])
        self.assertIn("cannot read PAM service missing", errors[0])
        _, errors = self.stack({"a": "@include b\n", "b": "@include a\n"}, services=["a"])
        self.assertTrue(any("loop" in e for e in errors))

    def test_mapped_modules(self):
        with tempfile.TemporaryDirectory() as d:
            security = Path(d, "security")
            security.mkdir()
            (security / "pam_unix.so").write_text("x")
            for pid, path in (("10", security / "pam_unix.so"), ("11", "/tmp/pam_evil.so"),
                              ("12", f"{security}/pam_gone.so (deleted)")):
                Path(d, pid).mkdir()
                Path(d, pid, "maps").write_text(f"7f00-7f10 r-xp 00000000 08:01 5 {path}\n")
            Path(d, "self").mkdir()
            rows, unreadable = scan_pam.mapped_modules(d, [str(security)], lambda p: "evil" not in p)
        self.assertEqual(unreadable, 0)
        self.assertEqual([(r["path"].rsplit("/", 1)[1], r["reason"]) for r in rows],
                         [("pam_evil.so", "outside the system security dirs"),
                          ("pam_gone.so", "mapped from a deleted file")])

    def test_stray_files(self):
        with tempfile.TemporaryDirectory() as d:
            for name in ("pam_deny.so", "pam_deny.so.bak", "pam_evil.so"):
                (Path(d) / name).write_text("x")
            rows = scan_pam.stray_files([d], owner=lambda p: not p.endswith("evil.so"))
        self.assertEqual({(Path(r["path"]).name, r["reason"][:7]) for r in rows},
                         {("pam_deny.so.bak", "backup "), ("pam_evil.so", "unowned")})

    def test_verify_modules_filters_to_security_so(self):
        class R:
            returncode, stdout = 1, "missing   c /etc/security/x.conf\nS.5....T.    /lib/x86_64-linux-gnu/security/pam_deny.so\n"
        orig = scan_pam._has
        scan_pam._has = lambda tool: tool == "rpm"
        try:
            rows = scan_pam.verify_modules(lambda *a, **k: R())
        finally:
            scan_pam._has = orig
        self.assertEqual([r["path"] for r in rows], ["/lib/x86_64-linux-gnu/security/pam_deny.so"])


class HostFix(unittest.TestCase):
    def test_remove_line_backs_up_deletes_payload_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            pam_dir, base = Path(d, "pam.d"), Path(d, "ir")
            pam_dir.mkdir()
            payload = Path(d, "unicode.so")
            payload.write_text("elf")
            f = pam_dir / "common-password"
            f.write_text("password required pam_unix.so\n" + HOOK + "\n")
            result = fix_pam.remove_line(str(f), HOOK, str(payload), str(pam_dir), str(base))
            self.assertEqual((result["removed"], result["payload"]), (1, True))
            self.assertEqual(f.read_text(), "password required pam_unix.so\n")
            self.assertFalse(payload.exists())
            self.assertTrue(any(base.rglob("*common-password")))
            self.assertEqual(fix_pam.remove_line(str(f), HOOK, "", str(pam_dir), str(base))["removed"], 0)

    def test_refuses_files_outside_pam_dir(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                fix_pam.remove_line(str(Path(d, "x")), "l", "", str(Path(d, "pam.d")), d)


class Controller(unittest.TestCase):
    ROWS = {"findings": [{"kind": "pam-exec", "file": "/etc/pam.d/common-password", "line_no": 3, "line": HOOK,
                          "module": "pam_exec.so", "payload": "/usr/share/locale/en/unicode.so",
                          "expose_authtok": True, "services": ["chpasswd", "common-password"]},
                         {"kind": "pam-mapped-module", "path": "/tmp/pam_evil.so", "pids": [11],
                          "reason": "outside the system security dirs"}], "errors": []}

    def test_scanner_and_registry(self):
        found = PamScanner(FakeRunner(scan_pam=self.ROWS)).run(TARGET)
        self.assertIsInstance(found[0], PamExecHook)
        self.assertIn("plaintext", found[0].summary)
        self.assertIn("chpasswd (via common-password) run pam_exec", found[0].summary)
        self.assertIsInstance(found[1], PamMappedModule)
        self.assertFalse(FixPam().can_fix(found[1]))  # report-only
        self.assertIn(PamScanner, [type(s) for s in registry.scanners()])
        self.assertTrue(registry.global_autofix().can_fix(found[0]))

    def test_fix_sequence(self):
        finding = PamScanner(FakeRunner(scan_pam=self.ROWS)).run(TARGET)[0]
        fix = FixPam().get_fix(finding)
        runner = FakeRunner(fix_pam={}, detect_os={"id": "ubuntu", "id_like": "debian", "version": "24",
                                                      "family": "debian"}, scan_pam={"findings": [], "errors": []})
        for step in fix.steps:
            step.script.runner = runner
            if hasattr(step.script, "scanner"):
                step.script.scanner.runner = runner
        fix.run()
        fixes = [c for c in runner.calls if c[0] == "fix_pam"]
        self.assertEqual(fixes[0][1][:3], ["remove-line", "/etc/pam.d/common-password", HOOK])
        self.assertEqual(fixes[0][1][3:], ["--payload", "/usr/share/locale/en/unicode.so"])
        self.assertEqual(fixes[1][1], ["reinstall", "apt"])
        self.assertEqual(runner.calls[-1][0], "scan_pam")  # re-verified last

    def test_gate_blocks_dirty_and_passes_clean(self):
        with self.assertRaises(PamDirty):
            PamGate(FakeRunner(scan_pam=self.ROWS)).run(TARGET)
        self.assertEqual(list(PamGate(FakeRunner(scan_pam={"findings": [], "errors": []})).run(TARGET)), [])

    def test_gate_blocks_on_unresolvable_stack(self):
        runner = FakeRunner(scan_pam={"findings": [], "errors": ["cannot read PAM service x (included via a): no"]})
        with self.assertRaises(PamDirty) as caught:
            PamGate(runner).run(TARGET)
        self.assertIn("unresolved", str(caught.exception))
        PamGate(FakeRunner(scan_pam={"findings": [], "errors": ["no dpkg or rpm"]})).run(TARGET)

    def test_gated_script_does_not_run_when_dirty(self):
        ran = []

        class Rotate(Script):
            def run(self, target, password="x"):
                ran.append(password)
        with self.assertRaises(PamDirty):
            gated(Rotate(), FakeRunner(scan_pam=self.ROWS)).run(target=TARGET, password="p")
        self.assertEqual(ran, [])
        gated(Rotate(), FakeRunner(scan_pam={"findings": [], "errors": []})).run(target=TARGET, password="p")
        self.assertEqual(ran, ["p"])


if __name__ == "__main__":
    unittest.main()
