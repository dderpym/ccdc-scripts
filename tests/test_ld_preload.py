"""LD_PRELOAD scanner/fix against fixture trees and a fake runner; never touches a host."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ccdc import registry  # noqa: E402
from ccdc.fixes.ld_preload import FixLibraryInjection  # noqa: E402
from ccdc.scanners.ld_preload import (LibraryInjection, LibraryInjectionScanner,  # noqa: E402
                                      UnownedMappedLibrary, UnreadableUnit)
from ccdc.target import Target  # noqa: E402
from host import fix_ld_preload, launcher, scan_ld_preload as scan  # noqa: E402

TARGET = Target("web01")
DROPIN = "[Service]\nEnvironment=\"LD_PRELOAD=/usr/lib/libudev-cache.so.1\" FOO=bar\n"


class FakeRunner:
    def __init__(self, document):
        self.document, self.calls = document, []

    def entry(self, target, entry, args=(), **request):
        self.calls.append((entry, list(args)))
        return self.document


class HostScan(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def systemd(self, units, env=None):
        """Fake `systemctl` answering list-unit-files/list-units/show/show-environment."""
        class Result:
            returncode, stderr = 0, ""

            def __init__(self, stdout):
                self.stdout = stdout

        def run(argv, **kwargs):
            args = argv[2:]
            if args[0] == "list-unit-files":
                return Result("".join(f"{u} enabled enabled\n" for u in units))
            if args[0] == "list-units":
                return Result("")
            if args[0] == "show-environment":
                return Result("".join(f"{k}={v}\n" for k, v in (env or {}).items()))
            asked = [a for a in args if "." in a and not a.startswith("-")]
            return Result("\n".join("".join(f"{k}={v}\n" for k, v in units[u].items())
                                    for u in asked if u in units))
        return run

    def test_effective_environment_from_systemd(self):
        dropin = self.write("ssh.service.d/x.conf", DROPIN)
        envfile = self.write("env", "export LD_PRELOAD=/opt/evil.so\nOTHER=1\n")
        units = {
            "ssh.service": {"Id": "ssh.service", "LoadState": "loaded", "FragmentPath": str(self.root / "ssh.service"),
                            "DropInPaths": str(dropin), "Environment": "LANG=C LD_PRELOAD=/usr/lib/libudev-cache.so.1 FOO=bar"},
            "a.service": {"Id": "a.service", "LoadState": "loaded", "Environment": "A=1 LD_LIBRARY_PATH=/tmp/x",
                          "EnvironmentFiles": "%s (ignore_errors=yes)" % envfile},
            "ok.service": {"Id": "ok.service", "LoadState": "loaded", "Environment": "PATH=/usr/bin"},
            "gone.service": {"Id": "gone.service", "LoadState": "not-found"},
            "mask.service": {"Id": "mask.service", "LoadState": "masked"},
            "env.service": {"Id": "env.service", "LoadState": "loaded",
                            "ExecStart": "{ path=/usr/bin/env ; argv[]=/usr/bin/env LD_PRELOAD=/x.so sshd ; }"},
        }
        rows = scan.scan_units(self.systemd(units))
        seen = {(r["unit"], r["variable"], r["value"]) for r in rows if r["kind"] == "unit-env"}
        self.assertEqual(seen, {("ssh.service", "LD_PRELOAD", "/usr/lib/libudev-cache.so.1"),
                                ("a.service", "LD_LIBRARY_PATH", "/tmp/x"),
                                ("a.service", "LD_PRELOAD", "/opt/evil.so"),
                                ("env.service", "LD_PRELOAD", "/x.so")})
        located = {r["unit"]: r["file"] for r in rows if r["variable"] == "LD_PRELOAD" and r["unit"] == "ssh.service"}
        self.assertEqual(located["ssh.service"], str(dropin))  # file is only located, systemd decided

    def test_unit_systemd_cannot_load_fails_closed(self):
        units = {"bad.service": {"Id": "bad.service", "LoadState": "bad-setting"}}
        rows = scan.scan_units(self.systemd(units))
        self.assertEqual([(r["kind"], r["unit"]) for r in rows], [("unreadable", "bad.service")])

    def test_unanswered_unit_fails_closed(self):
        run = self.systemd({"x.service": {"Id": "x.service"}})
        base = run

        def partial(argv, **kw):
            result = base(argv, **kw)
            if argv[2] == "show":
                result.stdout = ""
            return result
        rows = scan.scan_units(partial)
        self.assertEqual([(r["kind"], r["unit"]) for r in rows], [("unreadable", "x.service")])

    def test_systemctl_failure_is_an_error_not_clean(self):
        class Failed:
            returncode, stdout, stderr = 1, "", "no bus"
        with self.assertRaises(OSError):
            scan.scan_units(lambda *a, **k: Failed())

    def test_login_and_manager_environment(self):
        def run(argv, **kwargs):
            class R:
                returncode, stderr = 0, ""
                stdout = "LD_PRELOAD=/x.so\nLANG=C\n" if argv[0] == "bash" else "LANG=C\n"
            return R()
        rows = scan.scan_environment(run)
        self.assertEqual([(r["file"], r["variable"], r["value"]) for r in rows],
                         [("login shell (bash -l)", "LD_PRELOAD", "/x.so")])

    def test_ld_so_preload_reports_whether_loader_applied_it(self):
        path = self.write("ld.so.preload", "# c\n/usr/lib/evil.so\n")
        maps = self.write("maps", "7f00-7f01 r-xp 0 08:01 5 /usr/lib/evil.so\n")
        row = scan.scan_ld_so_preload(str(path), maps=str(maps))[0]
        self.assertEqual((row["libraries"], row["active"]), (["/usr/lib/evil.so"], ["/usr/lib/evil.so"]))
        self.assertEqual(scan.scan_ld_so_preload(str(path), maps=str(self.root / "none"))[0]["active"], [])
        self.assertEqual(scan.scan_ld_so_preload(str(self.root / "none")), [])

    def test_maps_unowned_only(self):
        for pid, lib in (("10", "/usr/lib/libudev-cache.so.1"), ("11", "/usr/lib/libc.so.6")):
            self.write(f"proc/{pid}/maps", f"7f00-7f01 r-xp 0 08:01 5 {lib}\n7f02-7f03 r-xp 0 0 0 [heap]\n")
            self.write(f"proc/{pid}/comm", "sshd\n")
        rows = scan.scan_maps(str(self.root / "proc"), is_owned=lambda p: "libc" in p, exists=lambda p: True)
        self.assertEqual([r["library"] for r in rows], ["/usr/lib/libudev-cache.so.1"])
        self.assertEqual(rows[0]["processes"], [{"pid": 10, "comm": "sshd"}])


class HostFix(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def edit(self, path, variable):
        return fix_ld_preload.edit(str(path), variable, str(self.root / "ir"), allowed=(str(self.root.resolve()),))

    def test_removes_only_the_variable_and_backs_up(self):
        path = self.root / "x.conf"
        path.write_text(DROPIN)
        result = self.edit(path, "LD_PRELOAD")
        self.assertEqual(result["action"], "edited")
        self.assertEqual(path.read_text(), "[Service]\nEnvironment=FOO=bar\n")
        self.assertEqual(result["removed"], ["/usr/lib/libudev-cache.so.1"])
        self.assertEqual(len(list(Path(result["backup"]).iterdir())), 1)

    def test_dropin_with_nothing_else_is_deleted(self):
        directory = self.root / "ssh.service.d"
        directory.mkdir()
        path = directory / "x.conf"
        path.write_text("[Service]\nEnvironment=LD_PRELOAD=/a.so\n")
        self.assertEqual(self.edit(path, "LD_PRELOAD")["action"], "deleted")
        self.assertFalse(path.exists())

    def test_ld_so_preload_emptied(self):
        path = self.root / "ld.so.preload"
        path.write_text("/evil.so\n")
        self.assertEqual(self.edit(path, "")["action"], "emptied")
        self.assertEqual(path.read_text(), "")

    def test_refuses_paths_outside_config(self):
        with self.assertRaises(ValueError):
            fix_ld_preload.edit("/home/x/.bashrc", "LD_PRELOAD")

    def test_still_mapped_matches_by_basename(self):
        proc = self.root / "proc/5"
        proc.mkdir(parents=True)
        (proc / "maps").write_text("1-2 r-xp 0 0 0 /usr/lib/libudev-cache.so.1\n")
        (proc / "comm").write_text("sshd\n")
        self.assertEqual(fix_ld_preload.still_mapped(["/old/libudev-cache.so.1"], str(self.root / "proc")),
                         ["/usr/lib/libudev-cache.so.1"])
        self.assertEqual(fix_ld_preload.still_mapped(["/other.so"], str(self.root / "proc")), [])


class Controller(unittest.TestCase):
    DOC = {"errors": ["gap"], "findings": [
        {"kind": "unit-env", "file": "/etc/systemd/system/ssh.service.d/x.conf", "unit": "ssh.service",
         "variable": "LD_PRELOAD", "value": "/usr/lib/libudev-cache.so.1"},
        {"kind": "ld-so-preload", "file": "/etc/ld.so.preload", "libraries": ["/a.so", "/b.so"]},
        {"kind": "unreadable", "file": "/etc/systemd/system/z.service", "unit": "z.service", "reason": "bad"},
        {"kind": "mapped-unowned", "library": "/l.so", "processes": [{"pid": 3, "comm": "sshd"}]}]}

    def test_typed_findings(self):
        result = LibraryInjectionScanner(FakeRunner(self.DOC)).run(TARGET)
        self.assertEqual([type(f) for f in result],
                         [LibraryInjection, LibraryInjection, UnreadableUnit, UnownedMappedLibrary])
        self.assertEqual(result.errors, ["gap"])
        self.assertEqual(result[1].value, "/a.so:/b.so")

    def test_fix_arguments_and_registry(self):
        result = LibraryInjectionScanner(FakeRunner(self.DOC)).run(TARGET)
        fix = FixLibraryInjection()
        self.assertFalse(fix.can_fix(result[2]))
        runner = FakeRunner({"still_mapped": []})
        script = fix.get_fix(result[0])
        script.steps[0].script.runner = runner
        script.run()
        self.assertEqual(runner.calls, [("fix_ld_preload", ["/etc/systemd/system/ssh.service.d/x.conf",
                                                           "--unit", "ssh.service", "--var", "LD_PRELOAD"])])
        script = fix.get_fix(result[1])
        script.steps[0].script.runner = runner
        script.run()
        self.assertEqual(runner.calls[-1], ("fix_ld_preload", ["/etc/ld.so.preload"]))
        script.steps[0].script.runner = FakeRunner({"still_mapped": ["/a.so"]})
        with self.assertRaises(RuntimeError):
            script.run()
        self.assertTrue(registry.global_autofix().can_fix(result[0]))
        self.assertIn(LibraryInjectionScanner, [type(s) for s in registry.scanners()])

    def test_launcher_accepts_new_entries(self):
        self.assertTrue(launcher.allowed("scan_ld_preload"))
        self.assertTrue(launcher.allowed("fix_ld_preload"))


if __name__ == "__main__":
    unittest.main()
