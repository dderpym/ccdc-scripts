"""Distilled LSE scanners, the integrity scanner, and permission autofixes (offline)."""
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from ccdc import registry, scan  # noqa: E402
from ccdc.fixes.permissions import RestorePermissions  # noqa: E402
from ccdc.fixes.userns import DisableUserNamespaces  # noqa: E402
from ccdc.scanners.accounts import AccountScanner, ExtraUidZeroAccount  # noqa: E402
from ccdc.scanners.integrity import IntegrityFinding, IntegrityScanner  # noqa: E402
from ccdc.scanners.lse import LSEScanner  # noqa: E402
from ccdc.scanners.permissions import PermissionDrift  # noqa: E402
from ccdc.scanners.userns import UnprivilegedUserNamespaces, UserNamespaceScanner  # noqa: E402
from ccdc.scanners.writable_paths import WritableCriticalPath, WritablePathScanner  # noqa: E402
from ccdc.target import Target  # noqa: E402
from host import fix_permissions  # noqa: E402
from test_framework import FakeRunner  # noqa: E402

T = Target("web01")
FIX = {"path": "/etc/cron.d/x", "mode": 0o644, "uid": 0, "gid": 0, "tier": "simple",
       "was": {"mode": 0o666, "uid": 0, "gid": 0}}
LSE_ROW = {"id": "fst160", "severity": "critical", "summary": "Writable critical files", "fixes": [FIX],
           "context": [{"summary": "s", "evidence": ["-rw-rw-rw- root root /etc/cron.d/x"]}]}
INTEGRITY_ROW = {"id": "policy-1", "path": "/etc/cron.d/x", "severity": "critical", "source": "policy",
                 "summary": "Critical-path security policy: group/other writable",
                 "fix": dict(FIX)}


class LSEScanners(unittest.TestCase):
    def test_writable_path_and_drift(self):
        runner = FakeRunner(discover_lse={"findings": [LSE_ROW], "errors": []})
        result = WritablePathScanner(runner).run(T)
        self.assertEqual(runner.calls[0][2], ["--only", "fst160,fst170,fst180,usr080"])
        self.assertEqual(result[0], WritableCriticalPath(T, "/etc/cron.d/x", "-rw-rw-rw-", "fst160"))
        self.assertIsInstance(result[1], PermissionDrift)
        self.assertEqual(result[1].summary, "/etc/cron.d/x: mode 0666 -> 0644")

    def test_lse_and_integrity_overlap_dedupes(self):
        lse = WritablePathScanner(FakeRunner(discover_lse={"findings": [LSE_ROW]}))
        integrity = IntegrityScanner(FakeRunner(discover_integrity={"findings": [INTEGRITY_ROW]}))
        findings, errors = scan.scan_target(T, [lse, integrity])
        self.assertEqual(sum(isinstance(f, PermissionDrift) for f in findings), 1)
        self.assertEqual(errors, [])

    def test_uid_zero_account(self):
        row = {"id": "sys040", "severity": "critical", "summary": "x",
               "context": [{"summary": "s", "evidence": ["toor:x:0:0:r:/root:/bin/sh"]}]}
        result = AccountScanner(FakeRunner(discover_lse={"findings": [row]})).run(T)
        self.assertEqual(list(result), [ExtraUidZeroAccount(T, "toor")])

    def test_generic_fallback_and_foreign_rows_ignored(self):
        row = {"id": "sys020", "severity": "critical", "summary": "Password hashes",
               "context": [{"summary": "s", "evidence": ["a:$1$x:0"]}]}
        other = dict(row, id="fst030")
        result = AccountScanner(FakeRunner(discover_lse={"findings": [row, other]})).run(T)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].summary, "sys020: Password hashes")

    def test_coverage_gap_becomes_error(self):
        gap = {"id": "scanner-find", "severity": "warning", "summary": "find missing"}
        result = WritablePathScanner(FakeRunner(discover_lse={"findings": [gap]})).run(T)
        self.assertEqual((list(result), result.errors), ([], ["find missing"]))

    def test_userns_scanner_and_fix(self):
        row = {"id": "ns-unprivileged-userns", "severity": "review", "summary": "s",
               "fixes": [{"kind": "sysctl", "settings": {"user.max_user_namespaces": "0"}, "was": {}, "tier": "all"}]}
        result = UserNamespaceScanner(FakeRunner(discover_lse={"findings": [row]})).run(T)
        self.assertEqual(list(result), [UnprivilegedUserNamespaces(T, ("user.max_user_namespaces",))])
        fixer = FakeRunner(fix_sysctl={"disabled": []})
        script = DisableUserNamespaces().get_fix(result[0])
        script.steps[0].script.runner = fixer
        script.run()
        self.assertEqual(fixer.calls, [("web01", "fix_sysctl", ["user.max_user_namespaces"])])

    def test_registry(self):
        classes = [type(s) for s in registry.scanners()]
        self.assertIn(WritablePathScanner, classes)
        self.assertIn(IntegrityScanner, classes)
        self.assertNotIn(LSEScanner, classes)
        self.assertTrue(registry.global_autofix().can_fix(PermissionDrift(T, "/a", 0o644, 0, 0, (0o666, 0, 0))))


class IntegrityAndFix(unittest.TestCase):
    def test_integrity_rows(self):
        gap = {"id": "scanner-1", "path": "", "severity": "warning", "summary": "rpm unavailable", "scanner_error": True}
        runner = FakeRunner(discover_integrity={"findings": [INTEGRITY_ROW, gap], "errors": []})
        result = IntegrityScanner(runner).run(T)
        self.assertIsInstance(result[0], IntegrityFinding)
        self.assertEqual(result[0].severity, "critical")
        self.assertEqual(result.errors, ["rpm unavailable"])
        self.assertEqual(len(result), 2)

    def test_restore_permissions_arguments(self):
        drift = PermissionDrift(T, "/etc/cron.d/x", 0o644, 0, 0, (0o666, 0, 0))
        runner = FakeRunner(fix_permissions={})
        script = RestorePermissions().get_fix(drift)
        script.steps[0].script.runner = runner
        script.run()
        self.assertEqual(runner.calls[0][2], ["/etc/cron.d/x", "--clear", "0", "--mode", "644", "--uid", "0", "--gid", "0"])

    def test_host_fix_permissions_exact_mode_and_clear(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "f")
            open(path, "w").close()
            os.chmod(path, 0o666)
            fix_permissions.fix(path, mode=0o755)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o755)
            os.chmod(path, 0o666)
            fix_permissions.fix(path, clear=0o022)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o644)
            link = os.path.join(directory, "l")
            os.symlink(path, link)
            with self.assertRaises(OSError):
                fix_permissions.fix(link, mode=0o600)


if __name__ == "__main__":
    unittest.main()
