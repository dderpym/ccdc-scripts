from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ccdc.registry import scanners  # noqa: E402
from ccdc.scanners.sudo_effective import EffectiveSudoGrant, SudoEffectiveScanner  # noqa: E402
from ccdc.target import Target  # noqa: E402
from host import scan_sudo_effective as eff  # noqa: E402
from tests.test_framework import FakeRunner  # noqa: E402

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
NOT_ALLOWED = "User nobody is not allowed to run sudo on web01.\n"


class Entry:
    def __init__(self, name, uid, shell="/bin/bash"):
        self.pw_name, self.pw_uid, self.pw_shell = name, uid, shell


class Result:
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout, self.returncode, self.stderr = stdout, returncode, stderr


class Parse(unittest.TestCase):
    def test_all_commands(self):
        self.assertEqual(eff.parse(OUT_ALL), [{"rule": "(ALL : ALL) ALL", "nopasswd": False, "all": True}])

    def test_nopasswd_specific_commands_not_all(self):
        rules = eff.parse(OUT_NOPASSWD)
        self.assertEqual([(r["nopasswd"], r["all"]) for r in rules], [(True, False), (False, False)])

    def test_defaults_not_authenticate_makes_everything_passwordless(self):
        self.assertTrue(eff.parse(OUT_NOAUTH)[0]["nopasswd"])

    def test_negated_all_is_not_blanket(self):
        out = "User x may run the following commands on h:\n    (ALL) !ALL\n"
        self.assertFalse(eff.parse(out)[0]["all"])

    def test_candidates(self):
        entries = [Entry("oski", 1001), Entry("daemon", 1), Entry("svc", 1002, "/usr/sbin/nologin"),
                   Entry("bob", 1003), Entry("nobody", 65534, "/usr/sbin/nologin")]
        self.assertEqual(eff.candidate_users(entries), ["bob", "nobody", "oski", "root"])


class Scan(unittest.TestCase):
    ENTRIES = [Entry("oski", 1001), Entry("bob", 1003), Entry("eve", 1004)]

    def run_with(self, table):
        def run(argv, **kwargs):
            self.assertEqual(argv[:4], ["sudo", "-n", "-l", "-U"])
            return table[argv[4]]
        return eff.scan(self.ENTRIES, run)

    def test_flags_everyone_but_oski_and_root(self):
        result = self.run_with({"oski": Result(OUT_ALL.replace("bob", "oski")),
                                "root": Result(OUT_ALL.replace("bob", "root")),
                                "bob": Result(OUT_ALL), "eve": Result(OUT_NOPASSWD),
                                "nobody": Result(NOT_ALLOWED, 1)})
        self.assertEqual([f["user"] for f in result["findings"]], ["bob", "eve"])
        self.assertEqual(result["errors"], [])

    def test_canary_grant_means_world_grant(self):
        table = {u: Result(NOT_ALLOWED) for u in ("oski", "root", "bob", "eve")}
        table["nobody"] = Result(OUT_ALL.replace("bob", "nobody"))
        self.assertEqual([f["user"] for f in self.run_with(table)["findings"]], ["nobody"])

    def test_sudo_failure_is_error_not_clean(self):
        table = {u: Result(NOT_ALLOWED) for u in ("oski", "root", "bob", "nobody")}
        table["eve"] = Result("", 1, "sudo: a password is required")
        result = self.run_with(table)
        self.assertEqual(result["findings"], [])
        self.assertIn("eve", result["errors"][0])

    def test_missing_sudo_is_error(self):
        def run(argv, **kwargs):
            raise FileNotFoundError("sudo")
        self.assertEqual(len(eff.scan(self.ENTRIES, run)["errors"]), 5)


class Controller(unittest.TestCase):
    def test_typed_finding_and_registration(self):
        runner = FakeRunner(scan_sudo_effective={"findings": [
            {"user": "bob", "rule": "(ALL : ALL) ALL", "nopasswd": False, "all": True}], "errors": ["x"]})
        result = SudoEffectiveScanner(runner).run(Target("h"))
        self.assertEqual(list(result), [EffectiveSudoGrant(Target("h"), "bob", "(ALL : ALL) ALL", False)])
        self.assertEqual(result.errors, ["x"])
        self.assertIn(SudoEffectiveScanner, [type(s) for s in scanners()])


if __name__ == "__main__":
    unittest.main()
