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

    def test_dropin_and_continuation_and_envfile(self):
        self.write("ssh.service.d/x.conf", DROPIN)
        self.write("a.service", "[Service]\nEnvironment=A=1 \\\n  LD_LIBRARY_PATH=/tmp/x\nEnvironmentFile=-%s\n"
                   % (self.root / "env"))
        self.write("env", "export LD_PRELOAD=/opt/evil.so\nOTHER=1\n")
        rows = scan.scan_units([str(self.root)])
        seen = {(r["unit"], r["variable"], r["value"]) for r in rows if r["kind"] == "unit-env"}
        self.assertEqual(seen, {("ssh.service", "LD_PRELOAD", "/usr/lib/libudev-cache.so.1"),
                                ("a.service", "LD_LIBRARY_PATH", "/tmp/x"),
                                ("a.service", "LD_PRELOAD", "/opt/evil.so")})

    def test_unparseable_unit_fails_closed(self):
        self.write("bad.service", '[Service]\nEnvironment="LD_PRELOAD=/x\n')
        rows = scan.scan_units([str(self.root)])
        self.assertEqual([(r["kind"], r["unit"]) for r in rows], [("unreadable", "bad.service")])

    def test_clean_unit_is_silent(self):
        self.write("ok.service", "[Service]\nEnvironment=PATH=/usr/bin\nExecStart=/bin/true\n")
        self.assertEqual(scan.scan_units([str(self.root)]), [])

    def test_ld_so_preload_and_env_files(self):
        path = self.write("ld.so.preload", "# c\n/usr/lib/evil.so\n")
        self.assertEqual(scan.scan_ld_so_preload(str(path))[0]["libraries"], ["/usr/lib/evil.so"])
        self.assertEqual(scan.scan_ld_so_preload(str(self.root / "none")), [])
        env = self.write("environment", "LD_PRELOAD=\"/x.so\"\nLANG=C\n")
        rows = scan.scan_env_files([str(env)], [])
        self.assertEqual([(r["variable"], r["value"]) for r in rows], [("LD_PRELOAD", "/x.so")])

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
