"""Process/path scanners against /proc-style fixture trees; never inspects the real host."""
from pathlib import Path
import os
import signal
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ccdc import registry  # noqa: E402
from ccdc.fixes.kill_process import KillSuspiciousProcess  # noqa: E402
from ccdc.scanners.cap_binaries import CapBinaryScanner, UnownedCapabilityBinary  # noqa: E402
from ccdc.scanners.kworker import FakeKernelThread, KworkerScanner  # noqa: E402
from ccdc.scanners.memfd import MemfdProcess, MemfdScanner  # noqa: E402
from ccdc.scanners.path_shadow import PathShadowScanner, PathShadowing  # noqa: E402
from ccdc.scanners.remote_agents import RemoteAccessAgent, RemoteAgentScanner  # noqa: E402
from ccdc.target import Target  # noqa: E402
from host import fix_kill_process, scan_cap_binaries, scan_kworker, scan_memfd  # noqa: E402
from host import scan_path_shadow, scan_remote_agents  # noqa: E402

TARGET = Target("web01")


class FakeRunner:
    def __init__(self, document):
        self.document, self.calls = document, []

    def entry(self, target, entry, args=(), **request):
        self.calls.append((entry, list(args)))
        return self.document


class ProcTree:
    def __init__(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = self.dir.name

    def add(self, pid, comm, exe=None, cmdline="", ppid=1):
        base = Path(self.root, str(pid))
        base.mkdir()
        (base / "comm").write_text(comm + "\n")
        (base / "cmdline").write_text(cmdline.replace(" ", "\0"))
        (base / "status").write_text(f"Name:\t{comm}\nPPid:\t{ppid}\n")
        if exe:
            os.symlink(exe, base / "exe")


class ProcScanTests(unittest.TestCase):
    def setUp(self):
        self.tree = ProcTree()
        self.addCleanup(self.tree.dir.cleanup)
        t = self.tree
        t.add(1, "systemd", "/usr/lib/systemd/systemd")
        t.add(2, "kthreadd", None, ppid=0)
        t.add(10, "secauditd", "/memfd:x (deleted)", "/proc/self/fd/3")
        t.add(11, "tmpbin", "/tmp/evil (deleted)")
        t.add(12, "sshd", "/usr/sbin/sshd (deleted)")  # package upgrade, not suspicious
        t.add(20, "kworker/u8:1", "/usr/local/bin/kworker-ctl")
        t.add(21, "kworker/0:1", None, ppid=2)  # a real kernel thread has no exe
        t.add(22, "kubelet", "/usr/bin/kubelet")  # legitimate k* userland
        t.add(30, "meshagent", "/opt/meshagent/meshagent")
        t.add(31, "bash", "/usr/bin/bash")

    def test_memfd(self):
        rows = scan_memfd.scan(self.tree.root)["findings"]
        self.assertEqual({(r["pid"], r["kind"]) for r in rows}, {(10, "memfd"), (11, "deleted")})

    def test_kworker(self):
        self.assertEqual([r["pid"] for r in scan_kworker.scan(self.tree.root)["findings"]], [20])

    def test_remote_agents(self):
        units = Path(self.tree.root, "units")
        units.mkdir()
        (units / "xrdp.service").write_text("")
        rows = scan_remote_agents.scan(self.tree.root, [str(units)], [str(units / "nope"), str(units)])
        self.assertEqual({(r["kind"], r["name"]) for r in rows["findings"]},
                         {("process", "meshagent"), ("unit", "xrdp"), ("path", "units")})

    def test_kill_reverifies_pid(self):
        sent = []
        send = lambda pid, sig: sent.append((pid, sig))  # noqa: E731
        self.assertEqual(fix_kill_process.kill(10, "memfd", self.tree.root, send)["action"], "killed")
        self.assertEqual(sent, [(10, signal.SIGSTOP), (10, signal.SIGKILL)])
        sent.clear()
        self.assertEqual(fix_kill_process.kill(31, "memfd", self.tree.root, send)["action"], "skipped")
        self.assertEqual(fix_kill_process.kill(999, "memfd", self.tree.root, send)["action"], "gone")
        self.assertEqual(sent, [])
        with self.assertRaises(ValueError):
            fix_kill_process.kill(10, "bogus", self.tree.root, send)


class PathAndCapTests(unittest.TestCase):
    def test_path_shadowing(self):
        with tempfile.TemporaryDirectory() as base:
            first, second, usr = (Path(base, n) for n in ("first", "second", "usr"))
            for d in (first, second, usr):
                d.mkdir()
            for d, name in ((first, "setcap"), (second, "setcap"), (first, "ls"), (second, "ls"), (first, "solo")):
                (d / name).write_text("x")
                (d / name).chmod(0o755)
            os.symlink(usr, Path(base, "bin"))  # usrmerge-style alias must not double count
            (usr / "ls").write_text("x")
            (usr / "ls").chmod(0o755)
            owned = lambda p: p.startswith(str(second)) or p.startswith(str(usr)) or p.endswith("solo")  # noqa: E731
            result = scan_path_shadow.scan([str(first), str(second), str(usr), str(Path(base, "bin"))], owned)
            self.assertEqual([r["name"] for r in result["findings"]], ["ls", "setcap"])
            setcap = result["findings"][1]
            self.assertEqual(setcap["unowned"], [str(first / "setcap")])

    def test_path_shadow_without_package_manager_is_incomplete(self):
        with tempfile.TemporaryDirectory() as base:
            for n in ("a", "b"):
                Path(base, n).mkdir()
                Path(base, n, "x").write_text("x")
                Path(base, n, "x").chmod(0o755)
            result = scan_path_shadow.scan([base + "/a", base + "/b"], lambda p: None)
            self.assertEqual(result["findings"], [])
            self.assertTrue(result["errors"])

    def test_getcap_parsing_and_filtering(self):
        class Out:
            stdout = ("/usr/bin/ping cap_net_raw=ep\n/home/x/corechk cap_setuid=ep\n"
                      "/usr/bin/legit = cap_dac_override+ep\n/tmp/p cap_net_bind_service=ep\n")
        rows = scan_cap_binaries.scan(lambda *a, **k: Out(), lambda p: p == "/usr/bin/legit")["findings"]
        self.assertEqual([r["path"] for r in rows], ["/home/x/corechk"])
        self.assertEqual(rows[0]["dangerous"], ["cap_setuid"])


class ControllerTests(unittest.TestCase):
    def test_scanners_type_rows(self):
        cases = (
            (MemfdScanner, "scan_memfd", {"pid": 1, "exe": "/memfd:x", "comm": "c", "cmdline": "", "kind": "memfd"}, MemfdProcess),
            (KworkerScanner, "scan_kworker", {"pid": 2, "comm": "kworker/u8:1", "exe": "/x"}, FakeKernelThread),
            (RemoteAgentScanner, "scan_remote_agents", {"kind": "unit", "name": "xrdp", "location": "/l", "pid": 0}, RemoteAccessAgent),
            (PathShadowScanner, "scan_path_shadow", {"name": "setcap", "paths": ["/a", "/b"], "unowned": ["/a"]}, PathShadowing),
            (CapBinaryScanner, "scan_cap_binaries", {"path": "/p", "capabilities": "cap_setuid=ep"}, UnownedCapabilityBinary),
        )
        for scanner, entry, row, kind in cases:
            runner = FakeRunner({"findings": [row], "errors": []})
            result = scanner(runner).run(TARGET)
            self.assertEqual(runner.calls[0][0], entry)
            self.assertIsInstance(result[0], kind)
            self.assertTrue(result[0].summary)
        self.assertEqual(RemoteAccessAgent.severity, "warning")
        self.assertEqual(UnownedCapabilityBinary.severity, "critical")

    def test_registered_and_only_process_findings_fixable(self):
        names = {type(s) for s in registry.scanners()}
        self.assertLessEqual({MemfdScanner, KworkerScanner, RemoteAgentScanner, PathShadowScanner, CapBinaryScanner}, names)
        autofix = registry.global_autofix()
        memfd = MemfdProcess(TARGET, 5, "/memfd:x", "c", "", "memfd")
        self.assertTrue(autofix.can_fix(memfd))
        self.assertFalse(autofix.can_fix(RemoteAccessAgent(TARGET, "unit", "xrdp", "/l")))
        self.assertFalse(autofix.can_fix(UnownedCapabilityBinary(TARGET, "/p", "cap_setuid=ep")))

    def test_kill_fix_arguments(self):
        fix = KillSuspiciousProcess().get_fix(FakeKernelThread(TARGET, 7, "kworker/u8:1", "/x"))
        runner = FakeRunner({"action": "killed"})
        fix.steps[0].script.runner = runner
        fix.run()
        self.assertEqual(runner.calls, [("fix_kill_process", ["7", "kworker"])])


if __name__ == "__main__":
    unittest.main()
