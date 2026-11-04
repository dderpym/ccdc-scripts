"""Offline checks of the SSH side-door scanner and its fixes."""
import base64
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ccdc import registry  # noqa: E402
from ccdc.scanners.ssh_vectors import (  # noqa: E402
    RogueAuthorizedKey, SSHAllow, SSHStartupScript, SSHVectorScanner, UnexpectedSSHOption, UnownedSSHFile)
from ccdc.target import Target  # noqa: E402
from host import fix_ssh_vectors as fixer, scan_ssh_vectors as scanner  # noqa: E402

TARGET = Target("web01")
BLOB = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519" + b"A" * 40).decode()
OTHER = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519" + b"B" * 40).decode()
TEAM = "ssh-ed25519 %s oski" % BLOB
ROGUE = "ssh-ed25519 %s root@localhost" % OTHER


def fp(blob):
    return "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(blob)).digest()).decode().rstrip("=")


class HostScan(unittest.TestCase):
    def test_key_parsing(self):
        self.assertEqual(scanner.parse_key_line(TEAM), (fp(BLOB), "oski"))
        self.assertEqual(scanner.parse_key_line('command="x",no-pty ' + ROGUE), (fp(OTHER), "root@localhost"))
        self.assertIsNone(scanner.parse_key_line("# comment"))
        self.assertIsNone(scanner.parse_key_line("ssh-ed25519 !!notbase64!!"))

    def test_option_rules(self):
        effective = scanner.parse_effective(
            "permitrootlogin without-password\nauthorizedkeysfile .ssh/authorized_keys /etc/ssh/.ssh/authorized_keys\n"
            "banner /etc/rick\npermituserenvironment no\ntrustedusercakeys none\nauthorizedkeyscommand none\n")
        rows = {(r["option"], r["value"]): r["severity"] for r in scanner.option_rows(effective)}
        self.assertEqual(rows, {("permitrootlogin", "without-password"): "critical",
                                ("authorizedkeysfile", "/etc/ssh/.ssh/authorized_keys"): "critical",
                                ("banner", "/etc/rick"): "warning"})
        allowed = scanner.option_rows(effective, {"banner=/etc/rick"})
        self.assertNotIn("banner", [r["option"] for r in allowed])

    def test_default_authorizedkeysfile_is_clean(self):
        effective = scanner.parse_effective("authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\n"
                                            "permitrootlogin no\npermituserenvironment no\n")
        self.assertEqual(scanner.option_rows(effective), [])

    def test_key_files_and_unknown_keys(self):
        effective = {"authorizedkeysfile": [".ssh/authorized_keys /etc/ssh/.ssh/authorized_keys %h/k_%u"]}
        files = scanner.key_files(effective, [("root", "/root")])
        self.assertEqual(files["/etc/ssh/.ssh/authorized_keys"], "root")
        self.assertIn("/root/k_root", files)
        contents = {"/root/.ssh/authorized_keys": TEAM + "\n", "/etc/ssh/.ssh/authorized_keys": "# x\n" + ROGUE + "\n"}

        def read(path):
            try:
                return contents[path]
            except KeyError:
                raise FileNotFoundError(path)
        rows, errors = scanner.key_rows(files, {fp(BLOB)}, read)
        self.assertEqual(errors, [])
        self.assertEqual([(r["file"], r["line"], r["fingerprint"]) for r in rows],
                         [("/etc/ssh/.ssh/authorized_keys", 2, fp(OTHER))])

    def test_startup_and_unowned(self):
        rows = scanner.startup_rows([("a", "/home/a"), ("b", "/home/b")], lambda p: p in ("/etc/ssh/sshrc", "/home/b/.ssh/rc"))
        self.assertEqual([r["path"] for r in rows], ["/etc/ssh/sshrc", "/home/b/.ssh/rc"])
        with tempfile.TemporaryDirectory() as d:
            for name in ("sshd_config", "ssh_host_ed25519_key", ".ssh", "sshrc", "mystery", "vault-ca.pem"):
                Path(d, name).touch()
            rows, errors = scanner.unowned_rows({d + "/vault-ca.pem"}, d, lambda p: False)
            self.assertEqual(sorted(Path(r["path"]).name for r in rows), [".ssh", "mystery"])
            rows, errors = scanner.unowned_rows((), d, lambda p: None)
            self.assertEqual(len(errors), 2)  # mystery + vault-ca.pem, with no package database


class Controller(unittest.TestCase):
    class Runner:
        def __init__(self, document):
            self.document, self.calls = document, []

        def entry(self, target, entry, args=(), **request):
            self.calls.append((entry, list(args)))
            return self.document

    def test_rows_become_typed_findings_and_allowlist_is_passed(self):
        document = {"errors": ["gap"], "findings": [
            {"kind": "sshd-option", "option": "banner", "value": "/x", "severity": "warning", "why": "w"},
            {"kind": "authorized-key", "file": "/f", "user": "root", "line": 1, "fingerprint": "SHA256:x", "comment": ""},
            {"kind": "ssh-startup", "path": "/etc/ssh/sshrc", "what": "system sshrc"},
            {"kind": "unowned-ssh-file", "path": "/etc/ssh/y"}]}
        runner = self.Runner(document)
        allow = {"web01": SSHAllow(options=("banner=/ok",), paths=("/etc/ssh/ca",), keys=("ssh-ed25519 K",))}
        result = SSHVectorScanner(runner, allow, keys=[TEAM]).run(TARGET)
        self.assertEqual([type(f) for f in result], [UnexpectedSSHOption, RogueAuthorizedKey, SSHStartupScript, UnownedSSHFile])
        self.assertEqual(result.errors, ["gap"])
        self.assertEqual(runner.calls[0], ("scan_ssh_vectors", ["--allow-key", TEAM, "--allow-key", "ssh-ed25519 K",
                                                               "--allow", "banner=/ok", "--allow-path", "/etc/ssh/ca"]))

    def test_registered_with_fixes(self):
        self.assertIn(SSHVectorScanner, [type(s) for s in registry.scanners()])
        autofix = registry.global_autofix()
        self.assertTrue(autofix.can_fix(SSHStartupScript(TARGET, "/etc/ssh/sshrc", "w")))
        self.assertTrue(autofix.can_fix(RogueAuthorizedKey(TARGET, "/f", "root", 1, "SHA256:x")))
        self.assertFalse(autofix.can_fix(UnexpectedSSHOption(TARGET, "permitrootlogin", "yes", "w", "critical")))
        self.assertFalse(autofix.can_fix(UnownedSSHFile(TARGET, "/etc/ssh/y")))

    def test_fix_arguments(self):
        runner = self.Runner({})
        autofix = registry.global_autofix()
        fix = autofix.get_fix(RogueAuthorizedKey(TARGET, "/f", "root", 1, "SHA256:x"))
        fix.steps[0].script.runner = runner
        fix.run()
        self.assertEqual(runner.calls[0][0], "fix_ssh_vectors")
        self.assertEqual(runner.calls[0][1][:3], ["remove-key", "/f", "SHA256:x"])


class HostFix(unittest.TestCase):
    def test_remove_file_backs_up_and_refuses_others(self):
        with tempfile.TemporaryDirectory() as d:
            evidence = Path(d, "ir")
            rc = Path(d, "home", ".ssh", "rc")
            rc.parent.mkdir(parents=True)
            rc.write_text("evil\n")
            self.assertEqual(fixer.remove_file(str(rc), str(evidence))["removed"], True)
            self.assertFalse(rc.exists())
            backups = list(evidence.glob("*/*"))
            self.assertEqual(len(backups), 2)  # copy + SHA256SUMS
            self.assertEqual(oct(next(evidence.iterdir()).stat().st_mode & 0o777), "0o700")
            self.assertEqual(fixer.remove_file(str(rc), str(evidence))["removed"], False)
            with self.assertRaises(ValueError):
                fixer.remove_file("/etc/passwd", str(evidence))

    def test_remove_key_only_matching_lines(self):
        with tempfile.TemporaryDirectory() as d:
            keys = Path(d, "authorized_keys")
            keys.write_text("# c\n%s\n%s\n" % (TEAM, ROGUE))
            with self.assertRaises(ValueError):
                fixer.remove_key(str(keys), fp(BLOB), [TEAM], d + "/ir")
            self.assertEqual(fixer.remove_key(str(keys), fp(OTHER), [TEAM], d + "/ir")["removed"], 1)
            self.assertEqual(keys.read_text(), "# c\n%s\n" % TEAM)
            self.assertEqual(fixer.remove_key(str(keys), fp(OTHER), [TEAM], d + "/ir")["removed"], 0)


if __name__ == "__main__":
    unittest.main()
