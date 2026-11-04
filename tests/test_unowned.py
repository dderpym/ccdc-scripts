"""Offline checks for the unowned-file scanner and quarantine."""
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile
import unittest
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ccdc import registry  # noqa: E402
from ccdc.fixes.quarantine import QuarantineUnowned  # noqa: E402
from ccdc.scanners.unowned import (TimestompedFile, UnitRunsUnownedBinary, UnownedExecutable,  # noqa: E402
                                   UnownedScanner)
from ccdc.target import Target  # noqa: E402
from host import fix_quarantine, scan_unowned  # noqa: E402

TARGET = Target("web01")


def st(mode=0o755, mtime=1000, ctime=1000):
    return SimpleNamespace(st_mode=stat.S_IFREG | mode, st_mtime=mtime, st_ctime=ctime)


class Scan(unittest.TestCase):
    def test_exec_paths_from_systemctl_show(self):
        value = ("{ path=/usr/sbin/a ; argv[]=/usr/sbin/a --x ${X} ; ignore_errors=yes ; start_time=[n/a] }"
                 "{ path=/opt/b ; argv[]=/opt/b b ; ignore_errors=no }")
        self.assertEqual(scan_unowned.exec_paths(value), ["/usr/sbin/a", "/opt/b"])
        self.assertEqual(scan_unowned.exec_paths(""), [])

    def systemd(self, units):
        def run(argv, **kw):
            args = argv[2:]
            if args[0] == "list-unit-files":
                out = "".join(f"{u} enabled\n" for u in units)
            elif args[0] == "list-units":
                out = ""
            else:
                asked = [a for a in args if a.endswith(".service")]
                out = "\n".join("".join(f"{k}={v}\n" for k, v in units[u].items()) for u in asked if u in units)
            return SimpleNamespace(stdout=out, stderr="", returncode=0)
        return run

    def test_loaded_units_use_managers_resolved_exec(self):
        run = self.systemd({
            "a.service": {"Id": "a.service", "LoadState": "loaded", "FragmentPath": "/etc/systemd/system/a.service",
                          "ExecStart": "{ path=/usr/sbin/net-pathd ; argv[]=x }"},
            "gone.service": {"Id": "gone.service", "LoadState": "not-found"},
            "bad.service": {"Id": "bad.service", "LoadState": "bad-setting"},
            "mute.service": {"Id": "mute.service"}})
        units, errors = scan_unowned.loaded_units(run)
        self.assertEqual(units, {"/etc/systemd/system/a.service": ["/usr/sbin/net-pathd"]})
        self.assertEqual(len(errors), 2)  # bad-setting and no-answer fail closed, not silent
        self.assertEqual(fix_quarantine.units_for(["/usr/sbin/net-pathd"], units), ["/etc/systemd/system/a.service"])

    def test_scan_reports_unreachable_systemd(self):
        def run(argv, **kw):
            if argv[0] == "systemctl":
                return SimpleNamespace(stdout="", stderr="no bus", returncode=1)
            return SimpleNamespace(stdout="", stderr="", returncode=1)
        with self.assertRaises(OSError):
            scan_unowned.loaded_units(run)

    def test_running_includes_script_path_from_cmdline(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(f"{d}/7")
            os.symlink("/usr/bin/python3", f"{d}/7/exe")
            Path(f"{d}/7/cmdline").write_bytes(b"python3\0/opt/evil.py\0")
            running = scan_unowned.running_executables(d)
            self.assertEqual(running["/opt/evil.py"], [7])

    def test_usrmerge_ownership_uses_realpath(self):
        with tempfile.TemporaryDirectory() as d:
            real = os.path.join(d, "usr/lib/x.so")
            os.makedirs(os.path.dirname(real))
            Path(real).write_text("x")
            os.symlink(os.path.join(d, "usr/lib"), os.path.join(d, "lib"))
            via_link = os.path.join(d, "lib/x.so")
            self.assertTrue(scan_unowned.is_owned(via_link, {os.path.realpath(real)}, d))
            self.assertTrue(scan_unowned.is_owned(real, {via_link}, d))
            self.assertFalse(scan_unowned.is_owned(real, set(), d))

    def test_dpkg_owned_set_parses_diversions(self):
        out = "coreutils: /usr/bin/ls\ndiversion by dash from: /bin/sh\nbash: /bin/bash\n"
        run = lambda *a, **k: SimpleNamespace(stdout=out, returncode=0)  # noqa: E731
        self.assertEqual(scan_unowned.owned_set(["/usr/bin/ls", "/bin/bash", "/x"], "dpkg", run),
                         {"/usr/bin/ls", "/bin/bash"})

    def test_rpm_owned_set(self):
        out = "coreutils\nfile /x is not owned by any package\n"
        run = lambda *a, **k: SimpleNamespace(stdout=out, returncode=1)  # noqa: E731
        self.assertEqual(scan_unowned.owned_set(["/usr/bin/ls", "/x"], "rpm", run), {"/usr/bin/ls"})

    def test_analyze_flags(self):
        stats = {"/usr/sbin/net-pathd": st(ctime=10**9, mtime=1000), "/usr/bin/ls": st(),
                 "/usr/local/bin/tool": st(), "/usr/bin/team": st(), "/etc/ssh/notes": st(mode=0o644)}
        units = {"/etc/systemd/system/bad.service": ["/usr/sbin/net-pathd"],
                 "/usr/lib/systemd/system/ok.service": ["/usr/bin/ls"],
                 "/usr/lib/systemd/system/odd.service": ["/usr/local/bin/tool"],
                 "/usr/lib/systemd/system/gone.service": ["/nonexistent/zz"]}
        rows = scan_unowned.analyze(
            [*stats], units, {"/usr/bin/ls", "/usr/lib/systemd/system/ok.service",
                                    "/usr/lib/systemd/system/odd.service", "/usr/lib/systemd/system/gone.service"},
            {"/usr/sbin/net-pathd": [42]}, ["/usr/bin/team"], lstat=stats.__getitem__,
            opener=lambda p, m: open(os.devnull, m), exists=lambda p: p in stats)
        by = {(r["kind"], r["path"]): r for r in rows}
        net = by[("unowned-exec", "/usr/sbin/net-pathd")]
        self.assertEqual((net["severity"], net["pids"]), ("critical", [42]))
        self.assertIn("timestomped", net["flags"])
        self.assertEqual(by[("unowned-exec", "/usr/local/bin/tool")]["severity"], "warning")
        self.assertNotIn(("unowned-exec", "/usr/bin/team"), by)  # allowlisted
        self.assertNotIn(("unowned-exec", "/etc/ssh/notes"), by)  # not executable
        self.assertEqual(by[("unit-runs-unowned", "/etc/systemd/system/bad.service")]["severity"], "critical")
        self.assertEqual(by[("unit-runs-unowned", "/usr/lib/systemd/system/odd.service")]["severity"], "warning")
        self.assertEqual(by[("unit-missing-binary", "/usr/lib/systemd/system/gone.service")]["severity"], "info")
        self.assertNotIn("/usr/lib/systemd/system/ok.service", {r["path"] for r in rows})

    def test_cap_keeps_critical_and_reports_omission(self):
        rows = [{"severity": "info", "path": str(i)} for i in range(5)] + [{"severity": "critical", "path": "z"}]
        kept, errors = scan_unowned.cap(rows, 3)
        self.assertEqual(kept[0]["path"], "z")
        self.assertEqual(len(kept), 3)
        self.assertEqual(len(errors), 1)


class Controller(unittest.TestCase):
    def test_scanner_types(self):
        class Runner:
            def entry(self, target, entry, args=(), **kw):
                return {"errors": [], "findings": [
                    {"kind": "unowned-exec", "path": "/usr/sbin/x", "flags": ["unowned-exec"], "pids": [1],
                     "severity": "critical"},
                    {"kind": "timestomped", "path": "/y", "flags": ["timestomped"], "pids": [], "severity": "critical"},
                    {"kind": "unit-runs-unowned", "unit": "/etc/systemd/system/u.service", "binary": "/b",
                     "unit_owned": False, "pids": [], "severity": "critical"}]}
        found = UnownedScanner(Runner()).run(TARGET)
        self.assertEqual([type(f) for f in found], [UnownedExecutable, TimestompedFile, UnitRunsUnownedBinary])
        fix = QuarantineUnowned()
        self.assertTrue(all(fix.can_fix(f) for f in found))
        self.assertFalse(fix.can_fix(UnitRunsUnownedBinary(TARGET, "/u", "/b", True, (), "critical")))
        self.assertFalse(fix.can_fix(UnownedExecutable(TARGET, "/z", ())))
        self.assertEqual(fix.get_fix(found[2]).steps[0].prefill["paths"], ["/etc/systemd/system/u.service", "/b"])

    def test_registered(self):
        self.assertIn(UnownedScanner, [type(s) for s in registry.scanners()])
        self.assertTrue(registry.global_autofix().can_fix(TimestompedFile(TARGET, "/y")))


class Quarantine(unittest.TestCase):
    def test_order_and_idempotence(self):
        with tempfile.TemporaryDirectory() as d:
            binary, unit = Path(d, "net-pathd"), Path(d, "net-pathd.service")
            binary.write_text("ELF")
            unit.write_text(f"ExecStart={binary}\n")
            events = []
            run = lambda argv, **k: events.append(("run", *argv[:2]))  # noqa: E731
            kill = lambda pid, sig: events.append(("kill", pid, sig))  # noqa: E731
            args = dict(evidence_root=os.path.join(d, "ir"), run=run, kill=kill, hostname=lambda: "h",
                        units=[str(unit)], pids=[7])
            report = fix_quarantine.quarantine([str(binary)], **args)
            self.assertFalse(binary.exists() or unit.exists())
            self.assertEqual(stat.S_IMODE(os.stat(report["evidence"]).st_mode), 0o700)
            sums = Path(report["evidence"], "SHA256SUMS").read_text()
            self.assertEqual(len(sums.splitlines()), 2)
            self.assertEqual(events[0], ("kill", 7, signal.SIGSTOP))
            self.assertLess(events.index(("run", "systemctl", "stop")), events.index(("kill", 7, signal.SIGKILL)))
            self.assertEqual(events[-2:], [("run", "systemctl", "daemon-reload"), ("run", "systemctl", "reset-failed")])
            events.clear()
            again = fix_quarantine.quarantine([str(binary)], **{**args, "units": [], "pids": []})
            self.assertEqual((again["evidence"], events), (None, []))


if __name__ == "__main__":
    unittest.main()
