"""Offline checks of the SSH side-door scanner and its fixes."""
import base64
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ccdc import registry  # noqa: E402
from ccdc.scanners.ssh_vectors import (  # noqa: E402
    OddSSHListener, RogueAuthorizedKey, SSHAllow, SSHLiveEnvironment, SSHLiveLibrary, SSHStartupScript,
    SSHVectorScanner, StaleSSHConfig, UnexpectedSSHOption, UnownedSSHFile)
from ccdc.target import Target  # noqa: E402
from host import fix_ssh_vectors as fixer, scan_ssh_vectors as scanner  # noqa: E402

TARGET = Target("web01")
BLOB = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519" + b"A" * 40).decode()
OTHER = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519" + b"B" * 40).decode()
BASE = "port 22\nlistenaddress 0.0.0.0:22\npermitrootlogin no\npasswordauthentication no\nauthorizedkeysfile .ssh/authorized_keys\n"
TEAM = "ssh-ed25519 %s oski" % BLOB
ROGUE = "ssh-ed25519 %s root@localhost" % OTHER


class Result:
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout, self.returncode, self.stderr = stdout, returncode, stderr


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
                                            "permitrootlogin no\npermituserenvironment no\npasswordauthentication no\n")
        self.assertEqual(scanner.option_rows(effective), [])

    def test_empty_and_password_rules(self):
        rows = {r["option"]: r["severity"] for r in scanner.option_rows(
            scanner.parse_effective("permitemptypasswords yes\npasswordauthentication yes\n"))}
        self.assertEqual(rows, {"permitemptypasswords": "critical", "passwordauthentication": "warning"})

    def test_keys_come_from_each_users_effective_authorizedkeysfile(self):
        per_user = {"root": [("127.0.0.1", {"authorizedkeysfile": [".ssh/authorized_keys /etc/ssh/.ssh/authorized_keys %h/k_%u"]})],
                    "deploy": [("127.0.0.1", {"authorizedkeysfile": ["none"]})]}
        accounts = [("root", "/root"), ("deploy", "/home/deploy")]
        files = scanner.key_files(per_user, accounts)
        self.assertEqual(files["/etc/ssh/.ssh/authorized_keys"], "root")
        self.assertIn("/root/k_root", files)
        self.assertFalse([f for f in files if f.startswith("/home/deploy")])  # Match says none: sshd reads nothing
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

    def test_startup_files_must_be_live(self):
        accounts = [("a", "/home/a"), ("b", "/home/b")]
        per_user = {"a": [("127.0.0.1", {"permituserrc": ["no"]})], "b": [("127.0.0.1", {"permituserrc": ["yes"]})]}
        present = lambda p: p in ("/etc/ssh/sshrc", "/home/a/.ssh/rc", "/home/b/.ssh/rc")  # noqa: E731
        rows = scanner.startup_rows(per_user, accounts, present)
        self.assertEqual([r["path"] for r in rows], ["/etc/ssh/sshrc", "/home/b/.ssh/rc"])  # a: PermitUserRC no
        self.assertEqual(scanner.startup_rows({}, accounts, present), [])  # nobody can log in

    def test_only_referenced_files_are_checked(self):
        base = {"banner": ["/etc/ssh/.rick"], "trustedusercakeys": ["/etc/ssh/vault-ca.pem"],
                "authorizedkeyscommand": ["/usr/bin/fetch-keys %u"], "hostkey": ["/etc/ssh/ssh_host_ed25519_key"]}
        paths = scanner.referenced_paths({}, base)
        self.assertEqual(paths, ["/etc/ssh/.rick", "/etc/ssh/vault-ca.pem", "/usr/bin/fetch-keys"])
        rows, errors = scanner.unowned_rows(paths, {"/etc/ssh/vault-ca.pem"}, lambda p: p != "/usr/bin/fetch-keys",
                                            lambda p: True)
        self.assertEqual(sorted(r["path"] for r in rows), ["/etc/ssh/.rick", "/usr/bin/fetch-keys"])
        rows, errors = scanner.unowned_rows(["/etc/ssh/mystery"], (), lambda p: None, lambda p: True)
        self.assertEqual((rows, len(errors)), ([], 1))  # no package database: say so
        self.assertEqual(scanner.unowned_rows(["/gone"], (), lambda p: False, lambda p: False), ([], []))

    def test_unreferenced_etc_ssh_files_are_not_reported(self):
        # An unowned file nothing references is not live; the scan never walks /etc/ssh.
        self.assertEqual(scanner.referenced_paths({}, {"port": ["22"]}), [])


class Effective(unittest.TestCase):
    @staticmethod
    def sshd(match_for=None, fail_on=None):
        def run(argv, **kwargs):
            context = argv[argv.index("-C") + 1] if "-C" in argv else ""
            if fail_on and fail_on in context:
                return Result(returncode=1, stderr="bad spec")
            text = BASE
            for key, lines in (match_for or {}).items():
                if key in context:
                    keep = {extra.split()[0] for extra in lines.splitlines()}
                    text = "\n".join(line for line in text.splitlines() if line.split()[0] not in keep) + "\n" + lines
            return Result(text)
        return run

    def test_match_override_surfaces_with_contexts(self):
        run = self.sshd({"user=deploy": "permitrootlogin yes\npasswordauthentication yes\npermitemptypasswords yes\n"})
        accounts = [("root", "/root"), ("deploy", "/home/deploy")]
        per_user, base, errors = scanner.effective_by_user("/usr/sbin/sshd", accounts, run)
        self.assertEqual(errors, [])
        rows = {r["option"]: r for r in scanner.effective_option_rows(per_user, base)}
        self.assertEqual(rows["permitrootlogin"]["contexts"], ["deploy@127.0.0.1", "deploy@192.0.2.1"])
        self.assertEqual(rows["permitrootlogin"]["severity"], "critical")
        self.assertEqual(rows["permitemptypasswords"]["severity"], "critical")

    def test_global_problem_is_reported_once_with_every_context(self):
        run = lambda argv, **kw: Result(BASE.replace("permitrootlogin no", "permitrootlogin yes"))  # noqa: E731
        per_user, base, _ = scanner.effective_by_user("/x", [("root", "/root")], run)
        rows = scanner.effective_option_rows(per_user, base)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["contexts"], ["default", "root@127.0.0.1", "root@192.0.2.1"])

    def test_remote_only_match_is_seen(self):
        run = self.sshd({"addr=192.0.2.1": "authorizedkeysfile /etc/ssh/.ssh/authorized_keys\n"})
        per_user, base, _ = scanner.effective_by_user("/x", [("root", "/root")], run)
        self.assertEqual([(r["option"], r["contexts"]) for r in scanner.effective_option_rows(per_user, base)],
                         [("authorizedkeysfile", ["root@192.0.2.1"])])

    def test_failures_are_errors_not_clean(self):
        per_user, base, errors = scanner.effective_by_user("/x", [("root", "/root")], self.sshd(fail_on="addr=192"))
        self.assertTrue(errors and "bad spec" in errors[0])
        per_user, base, errors = scanner.effective_by_user("/x", [("root", "/root")],
                                                           lambda *a, **k: Result(returncode=1, stderr="no"))
        self.assertEqual((per_user, base, errors), ({}, {}, ["sshd -T unavailable: no"]))

    def test_login_accounts_skip_nologin(self):
        class E:
            def __init__(self, name, shell):
                self.pw_name, self.pw_shell, self.pw_dir = name, shell, "/home/" + name
        accounts = scanner.login_accounts([E("daemon", "/usr/sbin/nologin"), E("bob", "/bin/bash"), E("x", "/bin/false")])
        self.assertEqual([name for name, _ in accounts], ["bob", "root"])

    def test_full_scan_with_fake_proc(self):
        with tempfile.TemporaryDirectory() as temp:
            proc = FakeProc(temp, environ=b"LD_PRELOAD=/usr/lib/libudev-cache.so.1\0",
                            tcp="   0: 00000000:08AE 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 555 1\n").root
            with patch.object(scanner, "sshd_binary", lambda proc="/proc": "/usr/sbin/sshd"):
                result = scanner.scan([TEAM], proc=str(proc), run=self.sshd(), accounts=[("root", "/root")], config=[])
        kinds = sorted(r["kind"] for r in result["findings"])
        self.assertEqual(kinds, ["live-env", "odd-listener"])  # 0x08AE = port 2222, config says 22

    def test_no_running_sshd_is_reported_not_clean(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(scanner, "sshd_binary", lambda proc="/proc": "/usr/sbin/sshd"):
                result = scanner.scan([TEAM], proc=temp, run=self.sshd(), accounts=[("root", "/root")])
        self.assertIn("no running sshd found; live checks skipped", result["errors"])

    def test_missing_sshd_binary_fails_closed(self):
        def missing(proc="/proc"):
            raise RuntimeError("cannot find sshd")
        with patch.object(scanner, "sshd_binary", missing):
            result = scanner.scan([TEAM])
        self.assertEqual(result["findings"], [])
        self.assertIn("cannot find sshd", result["errors"])


class Staleness(unittest.TestCase):
    def test_config_files_follow_include_and_record_directory(self):
        files = {"/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n",
                 "/etc/ssh/sshd_config.d/10.conf": "Include extra/*.conf\n"}

        def read(path):
            if path in files:
                return files[path]
            raise FileNotFoundError(path)
        listing = {"/etc/ssh/sshd_config.d/*.conf": ["/etc/ssh/sshd_config.d/10.conf"],
                   "/etc/ssh/sshd_config.d/extra/*.conf": ["/etc/ssh/sshd_config.d/extra/a.conf"]}
        found = scanner.config_files(read=read, expand_glob=lambda p: listing.get(p, []))
        self.assertEqual(found, ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d", "/etc/ssh/sshd_config.d/10.conf",
                                 "/etc/ssh/sshd_config.d/extra", "/etc/ssh/sshd_config.d/extra/a.conf"])

    def test_ctime_defeats_backdated_mtime(self):
        class Info:
            def __init__(self, m, c):
                self.st_mtime, self.st_ctime = m, c
        stats = {"/old": Info(100, 100), "/stomped": Info(100, 5000)}

        def stat(path):
            if path in stats:
                return stats[path]
            raise OSError("gone")
        rows, errors = scanner.stale_rows(1000, ["/old", "/stomped", "/missing"], stat)
        self.assertEqual([r["path"] for r in rows], ["/stomped"])
        self.assertEqual(rows[0]["edited"], 5000)
        self.assertTrue(errors and "/missing" in errors[0])


class FakeProc:
    """A tiny /proc with a master sshd (pid 100, child 200) listening on socket inode 555."""

    def __init__(self, tmp, environ=b"", maps="", tcp=""):
        self.root = Path(tmp)
        (self.root / "net").mkdir()
        (self.root / "stat").write_text("cpu 1 2 3\nbtime 1000\n")
        header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        (self.root / "net" / "tcp").write_text(header + tcp)
        (self.root / "net" / "tcp6").write_text(header)
        self.process(100, 1, environ, maps)
        self.process(200, 100, b"", "")
        os.symlink("socket:[555]", self.root / "100" / "fd" / "3")

    def process(self, pid, ppid, environ, maps):
        directory = self.root / str(pid)
        (directory / "fd").mkdir(parents=True)
        (directory / "comm").write_text("sshd\n")
        rest = ["S", str(ppid)] + ["0"] * 17 + ["500"] + ["0"] * 5  # starttime is the 20th field after ")"
        (directory / "stat").write_text("%d (sshd) %s\n" % (pid, " ".join(rest)))
        (directory / "environ").write_bytes(environ)
        (directory / "maps").write_text(maps)


class LiveProcess(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def proc(self, **kwargs):
        return FakeProc(self.temp.name, **kwargs).root

    def test_pids_and_start_time(self):
        proc = self.proc()
        self.assertEqual(scanner.sshd_pids(str(proc)), (100, [100, 200]))
        self.assertEqual(scanner.start_time(100, str(proc), clock_ticks=100), 1005.0)

    def test_environment_flags_preload_only(self):
        proc = self.proc(environ=b"PATH=/bin\0LD_PRELOAD=/usr/lib/libudev-cache.so.1\0LD_LIBRARY_PATH=\0")
        rows, errors = scanner.environment_rows([100, 200], str(proc))
        self.assertEqual(rows, [{"kind": "live-env", "pid": 100, "name": "LD_PRELOAD",
                                 "value": "/usr/lib/libudev-cache.so.1"}])
        self.assertEqual(errors, [])

    def test_unreadable_environ_is_an_error(self):
        proc = self.proc()
        (proc / "100" / "environ").unlink()
        os.mkdir(proc / "100" / "environ")  # open() raises IsADirectoryError, an OSError
        rows, errors = scanner.environment_rows([100], str(proc))
        self.assertEqual(rows, [])
        self.assertTrue(errors and "pid 100" in errors[0])

    def test_maps_flag_unowned_and_deleted(self):
        maps = ("7f00-7f10 r-xp 0 08:01 1 /usr/lib/x86_64-linux-gnu/libc.so.6\n"
                "7f10-7f20 r-xp 0 08:01 2 /usr/lib/libudev-cache.so.1\n"
                "7f20-7f30 r-xp 0 08:01 3 /tmp/gone.so (deleted)\n"
                "7f30-7f40 r-xp 0 08:01 4 /usr/sbin/sshd\n")
        proc = self.proc(maps=maps)
        rows, errors = scanner.library_rows([100], str(proc), owner=lambda p: p.endswith("libc.so.6"))
        self.assertEqual({(r["path"], r["why"]) for r in rows},
                         {("/usr/lib/libudev-cache.so.1", "not owned by any package"),
                          ("/tmp/gone.so", "mapped file was deleted")})
        rows, errors = scanner.library_rows([100], str(proc), owner=lambda p: None)
        self.assertTrue(errors)  # no package database: cannot call it clean

    def test_listener_expected_vs_odd(self):
        proc = self.proc(tcp="   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 555 1\n")
        effective = scanner.parse_effective(BASE)
        self.assertEqual(scanner.listener_rows(100, effective, str(proc)), ([], []))
        odd = scanner.parse_effective("port 22\nlistenaddress 127.0.0.1:22\n")
        rows, _ = scanner.listener_rows(100, odd, str(proc))
        self.assertEqual(rows[0]["why"], "address not in ListenAddress")
        other = scanner.parse_effective("port 2222\nlistenaddress 0.0.0.0:2222\n")
        rows, _ = scanner.listener_rows(100, other, str(proc))
        self.assertEqual((rows[0]["port"], rows[0]["why"]), (22, "port not in sshd configuration"))

    def test_address_decoding(self):
        self.assertEqual(scanner.decode_address("0100007F:0016"), ("127.0.0.1", 22))
        self.assertEqual(scanner.decode_address("00000000000000000000000001000000:1F90"), ("::1", 8080))


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
            {"kind": "unowned-ssh-file", "path": "/etc/ssh/y"},
            {"kind": "stale-config", "path": "/etc/ssh/sshd_config", "edited": 9, "started": 1},
            {"kind": "live-env", "pid": 4, "name": "LD_PRELOAD", "value": "/x.so"},
            {"kind": "live-library", "pid": 4, "path": "/x.so", "why": "not owned by any package"},
            {"kind": "odd-listener", "address": "0.0.0.0", "port": 2222, "why": "w"}]}
        runner = self.Runner(document)
        allow = {"web01": SSHAllow(options=("banner=/ok",), paths=("/etc/ssh/ca",), keys=("ssh-ed25519 K",))}
        result = SSHVectorScanner(runner, allow, keys=[TEAM]).run(TARGET)
        self.assertEqual([type(f) for f in result], [UnexpectedSSHOption, RogueAuthorizedKey, SSHStartupScript,
                                                     UnownedSSHFile, StaleSSHConfig, SSHLiveEnvironment,
                                                     SSHLiveLibrary, OddSSHListener])
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
