"""PAM scanner, fix and gate; offline, temp dirs only."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ccdc import registry  # noqa: E402
from ccdc.fixes.pam import FixPam  # noqa: E402
from ccdc.scanners.pam import PamExecHook, PamScanner  # noqa: E402
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

    def test_audit_flags_exec_and_foreign(self):
        rows = scan_pam.audit_rules("/etc/pam.d/common-password", [
            "password [success=1 default=ignore] pam_unix.so obscure\n", HOOK + "\n",
            "auth required /tmp/evil.so\n", "auth required pam_deny.so\n"], lambda m: False)
        self.assertEqual([r["kind"] for r in rows], ["pam-exec", "pam-foreign-module"])
        self.assertTrue(rows[0]["expose_authtok"])
        self.assertEqual(rows[0]["payload"], "/usr/share/locale/en/unicode.so")

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
                          "expose_authtok": True}], "errors": []}

    def test_scanner_and_registry(self):
        found = PamScanner(FakeRunner(scan_pam=self.ROWS)).run(TARGET)
        self.assertIsInstance(found[0], PamExecHook)
        self.assertIn("plaintext", found[0].summary)
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
