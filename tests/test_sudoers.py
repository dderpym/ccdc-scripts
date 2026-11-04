"""Sudo scanner (live `sudo -l`/`visudo -c`) and its validated fix; offline, fake commands."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ccdc.fixes.sudoers import FixSudoGrant  # noqa: E402
from ccdc.registry import scanners  # noqa: E402
from ccdc.scanners.sudoers import (SudoersInvalid, SudoersScanner, SudoGrantsEveryone,  # noqa: E402
                                   UnexpectedSudoGrant)
from ccdc.target import Target  # noqa: E402
from host import fix_sudoers, scan_sudoers as scan_mod  # noqa: E402
from tests.test_framework import FakeRunner  # noqa: E402

T = Target("h")
OUT_ALL = """Matching Defaults entries for bob on web01:
    env_reset, mail_badpass

User bob may run the following commands on web01:
    (ALL : ALL) ALL
"""
OUT_NOPASSWD = """User eve may run the following commands on web01:
    (root) NOPASSWD: /usr/bin/vim, /usr/bin/less
    (ALL) PASSWD: /usr/bin/id
"""
OUT_NOAUTH = """Matching Defaults entries for amy on web01:
    !authenticate

User amy may run the following commands on web01:
    (root) /usr/bin/id
"""
OUT_LONG = """User bob may run the following commands on web01:

Sudoers entry: /etc/sudoers.d/evil:1
    RunAsUsers: ALL
    Commands:
\tALL
"""
NOT_ALLOWED = "User nobody is not allowed to run sudo on web01.\n"


class Entry:
    def __init__(self, name, uid, shell="/bin/bash"):
        self.pw_name, self.pw_uid, self.pw_shell = name, uid, shell


class Result:
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout, self.returncode, self.stderr = stdout, returncode, stderr


class Parse(unittest.TestCase):
    def test_all_commands(self):
        self.assertEqual(scan_mod.parse(OUT_ALL), [{"rule": "(ALL : ALL) ALL", "nopasswd": False, "all": True}])

    def test_nopasswd_specific_commands_not_all(self):
        rules = scan_mod.parse(OUT_NOPASSWD)
        self.assertEqual([(r["nopasswd"], r["all"]) for r in rules], [(True, False), (False, False)])

    def test_defaults_not_authenticate_makes_everything_passwordless(self):
        self.assertTrue(scan_mod.parse(OUT_NOAUTH)[0]["nopasswd"])

    def test_negated_all_is_not_blanket(self):
        out = "User x may run the following commands on h:\n    (ALL) !ALL\n"
        self.assertFalse(scan_mod.parse(out)[0]["all"])

    def test_sources(self):
        self.assertEqual(scan_mod.parse_sources(OUT_LONG), [("/etc/sudoers.d/evil", 1)])

    def test_candidates(self):
        entries = [Entry("oski", 1001), Entry("daemon", 1), Entry("svc", 1002, "/usr/sbin/nologin"),
                   Entry("bob", 1003), Entry("nobody", 65534, "/usr/sbin/nologin")]
        self.assertEqual(scan_mod.candidate_users(entries), ["bob", "nobody", "oski", "root"])


class Scan(unittest.TestCase):
    ENTRIES = [Entry("oski", 1001), Entry("bob", 1003), Entry("eve", 1004)]

    def run_with(self, table, visudo=Result("/etc/sudoers: parsed OK\n")):
        def run(argv, **kwargs):
            if argv[0] == "visudo":
                return visudo
            self.assertEqual(argv[:2], ["sudo", "-n"])
            if "-l" in argv[2:3] and argv[3] == "-l":  # long listing
                return Result(OUT_LONG)
            return table[argv[4]]
        return scan_mod.scan(self.ENTRIES, run)

    def test_flags_everyone_but_oski_and_root_with_location(self):
        result = self.run_with({"oski": Result(OUT_ALL.replace("bob", "oski")),
                                "root": Result(OUT_ALL.replace("bob", "root")),
                                "bob": Result(OUT_ALL), "eve": Result(OUT_NOPASSWD),
                                "nobody": Result(NOT_ALLOWED, 1)})
        self.assertEqual([(f["kind"], f["user"]) for f in result["findings"]], [("grant", "bob"), ("grant", "eve")])
        bob = result["findings"][0]
        self.assertEqual((bob["file"], bob["line"]), ("/etc/sudoers.d/evil", 1))
        # eve has two rules in short form but this sudo reported one source: no location is invented
        self.assertEqual(result["findings"][1]["file"], "")
        self.assertEqual(result["errors"], [])

    def test_canary_grant_means_world_grant(self):
        table = {u: Result(NOT_ALLOWED) for u in ("oski", "root", "bob", "eve")}
        table["nobody"] = Result(OUT_ALL.replace("bob", "nobody"))
        result = self.run_with(table)
        self.assertEqual([(f["kind"], f["user"]) for f in result["findings"]], [("world", "nobody")])

    def test_invalid_config_is_a_finding(self):
        table = {u: Result(NOT_ALLOWED) for u in ("oski", "root", "bob", "eve", "nobody")}
        result = self.run_with(table, visudo=Result("/etc/sudoers:3:1: syntax error\n", 1))
        self.assertEqual(result["findings"][0]["kind"], "invalid")
        self.assertIn("syntax error", result["findings"][0]["detail"])

    def test_sudo_failure_is_error_not_clean(self):
        table = {u: Result(NOT_ALLOWED) for u in ("oski", "root", "bob", "nobody")}
        table["eve"] = Result("", 1, "sudo: a password is required")
        result = self.run_with(table)
        self.assertEqual(result["findings"], [])
        self.assertIn("eve", result["errors"][0])

    def test_missing_tools_are_errors(self):
        def run(argv, **kwargs):
            raise FileNotFoundError(argv[0])
        self.assertEqual(len(scan_mod.scan(self.ENTRIES, run)["errors"]), 6)  # visudo + 5 accounts


class Controller(unittest.TestCase):
    ROWS = {"findings": [
        {"kind": "world", "user": "nobody", "rule": "(ALL) NOPASSWD: ALL", "nopasswd": True, "all": True,
         "file": "/etc/sudoers", "line": 5},
        {"kind": "grant", "user": "bob", "rule": "(ALL : ALL) ALL", "nopasswd": False, "all": True},
        {"kind": "invalid", "detail": "syntax error"}], "errors": ["x"]}

    def test_types_and_registration(self):
        result = SudoersScanner(FakeRunner(scan_sudoers=self.ROWS)).run(T)
        self.assertIsInstance(result[0], SudoGrantsEveryone)
        self.assertIsInstance(result[1], UnexpectedSudoGrant)
        self.assertIsInstance(result[2], SudoersInvalid)
        self.assertIn("/etc/sudoers:5", result[0].summary)
        self.assertEqual(result.errors, ["x"])
        self.assertIn(SudoersScanner, [type(s) for s in scanners()])

    def test_fix_arguments_carry_location(self):
        found = list(SudoersScanner(FakeRunner(scan_sudoers=self.ROWS)).run(T))
        fix = FixSudoGrant()
        self.assertTrue(fix.can_fix(found[0]) and fix.can_fix(found[1]))
        self.assertFalse(fix.can_fix(found[2]))
        fixer = FakeRunner(fix_sudoers={})
        script = fix.get_fix(found[0])
        script.steps[0].script.runner = fixer
        script.run()
        self.assertEqual(fixer.calls, [("h", "fix_sudoers", ["--locate", "nobody", "(ALL) NOPASSWD: ALL",
                                                             "--file", "/etc/sudoers", "--line", "5"])])


class Locate(unittest.TestCase):
    FILES = {"/etc/sudoers": ["Defaults env_reset", "root ALL=(ALL:ALL) ALL", "%sudo ALL=(ALL:ALL) ALL",
                              "ALL ALL=(ALL) NOPASSWD: ALL"],
             "/etc/sudoers.d/evil": ["bob ALL=(ALL) \tNOPASSWD:  ALL", "eve ALL=(ALL) NOPASSWD: ALL"]}

    @staticmethod
    def fake(argv, **kw):
        if argv[0] == "id":
            return Result("bob sudo\n")
        return Result("/etc/sudoers: parsed OK\n/etc/sudoers.d/evil: parsed OK\n")

    def locate(self, user, rule, path="", number=0):
        return fix_sudoers.locate(user, rule, path, number, "visudo", self.fake, lambda p: self.FILES[p])

    def test_finds_user_and_everyone_lines(self):
        self.assertEqual(self.locate("bob", "(ALL) NOPASSWD: ALL"),
                         [("/etc/sudoers", "ALL ALL=(ALL) NOPASSWD: ALL"),
                          ("/etc/sudoers.d/evil", "bob ALL=(ALL) \tNOPASSWD:  ALL")])

    def test_group_grant_matches_members(self):
        self.assertEqual(self.locate("bob", "(ALL : ALL) ALL"), [("/etc/sudoers", "%sudo ALL=(ALL:ALL) ALL")])

    def test_reported_line_is_preferred(self):
        self.assertEqual(self.locate("eve", "(ALL) NOPASSWD: ALL", "/etc/sudoers.d/evil", 2),
                         [("/etc/sudoers.d/evil", "eve ALL=(ALL) NOPASSWD: ALL")])

    def test_no_match_is_empty_and_fix_refuses(self):
        self.assertEqual(self.locate("bob", "(root) /bin/nothing"), [])
        with unittest.mock.patch.object(fix_sudoers, "locate", return_value=[]):
            with self.assertRaises(RuntimeError):
                fix_sudoers.fix_located("bob", "(root) /bin/nothing")

    def test_main_usage(self):
        self.assertEqual(fix_sudoers.main(["--locate", "bob"]), 2)

    def test_fix_located_removes_via_validated_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "sudoers")
            Path(path).write_text("root ALL=(ALL) ALL\nbob ALL=(ALL) NOPASSWD: ALL\n")
            with unittest.mock.patch.object(fix_sudoers, "allowed", lambda p: p == path), \
                    unittest.mock.patch("os.chown"):
                runs = iter([Result("", 0)] * 3)

                def run(argv, **kw):
                    if argv[0] == "id":
                        return Result("bob\n")
                    return next(runs)
                out = fix_sudoers.fix_located("bob", "(ALL) NOPASSWD: ALL", path, 2, visudo="visudo", run=run,
                                              evidence=os.path.join(directory, "ir"))
            self.assertEqual(out[0]["removed"], 1)
            self.assertEqual(Path(path).read_text(), "root ALL=(ALL) ALL\n")



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
