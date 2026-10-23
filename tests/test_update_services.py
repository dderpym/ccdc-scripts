"""Offline tests: fake /proc, helper metadata, and native service commands only."""
import copy
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("update_services", ROOT / "scripts/update-services.py")
services = importlib.util.module_from_spec(spec)
spec.loader.exec_module(services)


def completed(stdout="", rc=0, stderr=""):
    return subprocess.CompletedProcess([], rc, stdout, stderr)


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.proc = self.root / "proc"
        self.run = self.root / "run"
        self.proc.mkdir()
        (self.run / "openrc/started").mkdir(parents=True)
        self.info, self.hints = {}, {}
        self.units = {"nginx.service": True, "sshd.service": False}
        self.rc = {}
        self.calls = []
        self.on_restart = lambda: None
        self.addCleanup(patch.stopall)
        patch.object(services, "PROC", self.proc).start()
        patch.object(services, "RUN", self.run).start()
        patch.object(services, "process_info", side_effect=lambda pid: self.info[pid]).start()
        patch.object(services, "service_hints", side_effect=lambda: (self.hints, {})).start()
        patch.object(services.subprocess, "run", side_effect=self.native).start()

    def native(self, argv, **kwargs):
        self.calls.append(argv)
        self.assertEqual(kwargs["timeout"], services.TIMEOUT)
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertNotIn("shell", kwargs)
        if argv[:2] == ["systemctl", "list-units"]:
            return completed("\n".join("%s loaded %s %s Example" % (
                name, "active" if active else "inactive", "running" if active else "dead")
                for name, active in self.units.items()))
        if argv[:2] == ["systemctl", "show"]:
            return completed("loaded\n" if argv[-1] in self.units else "not-found\n")
        if argv[:2] == ["systemctl", "is-active"]:
            return completed(rc=0 if self.units.get(argv[-1]) else 3)
        if argv[:2] == ["systemctl", "restart"]:
            self.units[argv[-1]] = True
            self.on_restart()
            return completed()
        if argv[:2] == ["rc-service", "--exists"]:
            return completed(rc=0 if argv[-1] in self.rc else 1)
        if argv[0] == "rc-service" and argv[-1] == "status":
            return completed(rc=0 if self.rc.get(argv[1]) else 3)
        if argv[0] == "rc-service" and argv[-1] == "restart":
            self.rc[argv[1]] = True
            (self.run / "openrc/started" / argv[1]).touch()
            self.on_restart()
            return completed()
        if argv in (["nginx", "-t"], ["/usr/sbin/sshd", "-t"]):
            return completed()
        raise AssertionError("unexpected command: %r" % argv)

    def process(self, pid=42, unit="nginx.service", parent=1, exe="/usr/sbin/nginx", maps="", group=None):
        path = self.proc / str(pid)
        path.mkdir(exist_ok=True)
        for name in ("stat", "comm", "status"):
            (path / name).write_text("metadata")
        (path / "cgroup").write_text(group if group is not None else "0::/system.slice/" + (unit or "session.scope"))
        (path / "maps").write_text(maps)
        (path / "exe").symlink_to(exe)
        self.info[pid] = dict(parent=parent, process="nginx", executable=exe, service=unit)
        return path

    def stale(self, **kwargs):
        return self.process(exe="/usr/sbin/nginx (deleted)", **kwargs)

    def clear_stale(self, pid=42):
        path = self.proc / str(pid)
        (path / "exe").unlink()
        (path / "exe").symlink_to("/usr/sbin/nginx")
        (path / "maps").write_text("")

    def row(self, state, name="nginx.service"):
        return next(row for row in state["services"] if row["name"] == name)

    def test_snapshot_enumerates_all_active_services_without_reasons(self):
        self.units["empty.service"] = True
        self.process()
        state = services.inspect_services("systemd")
        self.assertEqual(set(state), {"services", "unmanaged", "warnings"})
        self.assertEqual([row["name"] for row in state["services"]], ["empty.service", "nginx.service"])
        self.assertEqual(self.row(state)["pids"], [42])
        self.assertEqual(self.row(state)["reasons"], [])
        self.assertEqual(self.row(state, "empty.service")["pids"], [])
        self.assertEqual(state["warnings"], [])

    def test_deleted_executable_and_real_file_mapping(self):
        self.stale(maps="100-200 r-xp 0000 08:01 123 /usr/lib/libfoo.so (deleted)\n"
                        "200-300 rw-p 0000 00:01 321 /memfd:jit (deleted)\n"
                        "300-400 rw-p 0000 00:01 432 /dev/zero (deleted)\n"
                        "400-500 rw-p 0000 00:00 0 /tmp/anonymous (deleted)\n"
                        "500-600 rw-p 0000 00:00 0 [anon] (deleted)\n"
                        "600-700 r-xp 0000 08:01 123 /usr/lib/current.so\n"
                        "700-800 rw-p 0000 00:01 555 /SYSV00000000 (deleted)\n"
                        "800-900 rw-p 0000 00:01 666 /anon_hugepage (deleted)\n"
                        "900-a00 rw-s 0000 00:0e 777 /[aio] (deleted)\n"
                        "a00-b00 rw-s 0000 00:0e 888 /[io_uring] (deleted)\n")
        row = self.row(services.inspect_services("systemd"))
        self.assertIn(services.STALE, row["reasons"])
        self.assertEqual(sum("deleted library/file mapping" in r for r in row["reasons"]), 1)
        self.assertTrue(any("deleted executable" in r for r in row["reasons"]))
        self.assertEqual(row["confidence"], "high")

    def test_openrc_standard_nested_pidfile_is_advisory_service_evidence(self):
        self.rc['nginx'] = True
        (self.run / 'openrc/started/nginx').touch()
        (self.run / 'nginx').mkdir()
        (self.run / 'nginx/nginx.pid').write_text('42\n')
        self.stale(unit=None)
        row = self.row(services.inspect_services('openrc'), 'nginx')
        self.assertEqual(row['pids'], [42])
        self.assertEqual(row['confidence'], 'low')
        self.assertIn(services.STALE, row['reasons'])

    def test_library_only_is_stale(self):
        self.process(maps="100-200 r--p 0000 08:01 123 /lib/libfoo.so (deleted)\n")
        self.assertIn(services.STALE, self.row(services.inspect_services("systemd"))["reasons"])

    def test_all_stale_processes_include_unmanaged_and_pid1(self):
        self.stale(pid=1, unit="init.service")
        self.stale(pid=20, unit=None)
        self.stale(pid=30, unit="not-known.service")
        state = services.inspect_services("systemd")
        self.assertEqual([row["pid"] for row in state["unmanaged"]], [1, 20, 30])
        self.assertEqual(self.row(state)["reasons"], [])
        self.assertTrue(any("reboot may be pending" in w for w in state["warnings"]))
        self.assertTrue(any("do not blindly kill" in w for w in state["warnings"]))
        self.assertFalse(any(argv[1] == "restart" for argv in self.calls))

    def test_user_session_unit_is_not_system_manager_unit(self):
        self.stale(group="0::/user.slice/user-1000.slice/user@1000.service/app.slice/nginx.service")
        state = services.inspect_services("systemd")
        self.assertEqual(state["unmanaged"][0]["pid"], 42)
        self.assertEqual(self.row(state)["pids"], [])

    def test_nested_container_manager_unit_is_not_host_unit(self):
        self.stale(group="0::/machine.slice/container.service/system.slice/nginx.service")
        state = services.inspect_services("systemd")
        self.assertEqual(state["unmanaged"][0]["pid"], 42)
        self.assertEqual(self.row(state)["pids"], [])

    def test_repeated_v1_cgroup_unit_is_still_attributed(self):
        self.stale(group="1:name=systemd:/system.slice/nginx.service\n"
                         "2:memory:/system.slice/nginx.service\n")
        self.assertEqual(self.row(services.inspect_services("systemd"))["pids"], [42])

    def test_inactive_native_unit_cannot_claim_stale_process(self):
        self.units["nginx.service"] = False
        self.stale()
        state = services.inspect_services("systemd")
        self.assertEqual(state["services"], [])
        self.assertEqual(len(state["unmanaged"]), 1)
        with self.assertRaisesRegex(RuntimeError, "was not active"):
            services.restart_service("systemd", "nginx.service", state)

    def test_stopped_since_update_is_listed_but_previously_inactive_is_not(self):
        self.process()
        before = services.inspect_services("systemd")
        self.units["nginx.service"] = False
        row = self.row(services.inspect_services("systemd", before))
        self.assertFalse(row["active"])
        self.assertEqual(row["pids"], [])
        self.assertIn("stopped since update", row["reasons"][0])
        self.assertFalse(any(row["name"] == "sshd.service" for row in before["services"]))

    def test_preexisting_and_new_evidence_are_distinguished(self):
        path = self.stale()
        before = services.inspect_services("systemd")
        (path / "maps").write_text("100-200 r--p 0000 08:01 123 /lib/new.so (deleted)\n")
        reasons = self.row(services.inspect_services("systemd", before))["reasons"]
        self.assertIn(services.STALE, reasons)
        self.assertTrue(any("already present before" in r for r in reasons))
        self.assertTrue(any("new stale file evidence" in r for r in reasons))
        self.assertTrue(any("causation unknown" in r for r in reasons))

    def test_before_does_not_hide_new_stale_unmanaged_process(self):
        self.stale(pid=20, unit=None)
        before = services.inspect_services("systemd")
        self.stale(pid=21, unit=None)
        after = services.inspect_services("systemd", before)
        self.assertEqual([row["pid"] for row in after["unmanaged"]], [20, 21])
        self.assertTrue(any("already present before" in r for r in after["unmanaged"][0]["reasons"]))
        self.assertTrue(any("new stale file evidence" in r for r in after["unmanaged"][1]["reasons"]))

    def test_openrc_pidfile_ancestry_not_basename_guess(self):
        self.rc = {"web": True}
        (self.run / "openrc/started/web").touch()
        self.process(pid=40, unit=None)
        self.stale(pid=42, unit=None, parent=40)
        self.stale(pid=43, unit=None)
        self.hints = {40: [("web", True)], 43: [("nginx", False)]}
        state = services.inspect_services("openrc")
        self.assertEqual(self.row(state, "web")["pids"], [40, 42])
        self.assertEqual(self.row(state, "web")["confidence"], "low")
        self.assertEqual([row["pid"] for row in state["unmanaged"]], [43])
        self.assertTrue(any("no known config validator" in w for w in state["warnings"]))

    def test_ambiguous_openrc_hint_remains_unmanaged(self):
        self.rc = {"web": True, "other": True}
        for name in self.rc:
            (self.run / "openrc/started" / name).touch()
        self.stale(unit=None)
        self.hints = {42: [("web", True), ("other", True)]}
        self.assertEqual(len(services.inspect_services("openrc")["unmanaged"]), 1)

    def test_openrc_started_marker_requires_live_status(self):
        self.rc = {"web": False}
        (self.run / "openrc/started/web").touch()
        self.stale(unit=None)
        self.hints = {42: [("web", True)]}
        state = services.inspect_services("openrc")
        self.assertEqual(state["services"], [])
        self.assertEqual(len(state["unmanaged"]), 1)

    def test_restart_only_explicit_name_and_verify(self):
        self.stale()
        self.on_restart = self.clear_stale
        result = services.restart_service("systemd", "nginx.service")
        self.assertEqual(result["status"], "restarted")
        self.assertEqual([argv for argv in self.calls if argv[1] == "restart"],
                         [["systemctl", "restart", "--", "nginx.service"]])
        self.assertIn(["nginx", "-t"], self.calls)
        self.assertIn(["systemctl", "is-active", "--quiet", "--", "nginx.service"], self.calls)

    def test_stopped_previously_active_service_can_be_restarted(self):
        self.process()
        before = services.inspect_services("systemd")
        self.units["nginx.service"] = False
        self.assertEqual(services.restart_service("systemd", "nginx.service", before)["status"], "restarted")

    def test_openrc_stopped_service_restart_and_unknown_validator_warning(self):
        self.rc = {"web": True}
        marker = self.run / "openrc/started/web"
        marker.touch()
        before = services.inspect_services("openrc")
        marker.unlink()
        self.rc["web"] = False
        result = services.restart_service("openrc", "web", before)
        self.assertEqual(result["status"], "restarted")
        self.assertIn(["rc-service", "web", "restart"], self.calls)
        self.assertTrue(any("no known config validator" in w for w in result["warnings"]))

    def test_native_hooks_already_fixed_service(self):
        self.process()
        result = services.restart_service("systemd", "nginx.service")
        self.assertEqual(result["status"], "already-current")
        self.assertNotIn(["nginx", "-t"], self.calls)
        self.assertNotIn(["systemctl", "restart", "--", "nginx.service"], self.calls)

    def test_reinspect_after_validator_avoids_stale_prompt(self):
        self.stale()
        def native(argv, **kwargs):
            if argv == ["nginx", "-t"]:
                self.clear_stale()
            return self.native(argv, **kwargs)
        with patch.object(services.subprocess, "run", side_effect=native):
            result = services.restart_service("systemd", "nginx.service")
        self.assertEqual(result["status"], "already-current")
        self.assertFalse(any(argv[1] == "restart" for argv in self.calls))

    def test_sshd_validator_is_fixed_argv(self):
        self.units["sshd.service"] = True
        self.stale(unit="sshd.service")
        self.on_restart = self.clear_stale
        services.restart_service("systemd", "sshd.service")
        self.assertIn(["/usr/sbin/sshd", "-t"], self.calls)

    def test_config_failure_refuses_restart(self):
        self.stale()
        def native(argv, **kwargs):
            if argv == ["nginx", "-t"]:
                return completed(rc=1, stderr="invalid config")
            return self.native(argv, **kwargs)
        with patch.object(services.subprocess, "run", side_effect=native), self.assertRaisesRegex(RuntimeError, "invalid config"):
            services.restart_service("systemd", "nginx.service")
        self.assertFalse(any(argv[1] == "restart" for argv in self.calls))

    def test_still_stale_after_restart_is_failure(self):
        self.stale()
        with self.assertRaisesRegex(RuntimeError, "active, current"):
            services.restart_service("systemd", "nginx.service")

    def test_deferred_native_status_failure_is_not_success(self):
        self.stale()
        def native(argv, **kwargs):
            if argv[:2] == ["systemctl", "is-active"]:
                return completed(rc=3, stderr="inactive")
            return self.native(argv, **kwargs)
        with patch.object(services.subprocess, "run", side_effect=native), self.assertRaisesRegex(RuntimeError, "inactive"):
            services.restart_service("systemd", "nginx.service")
        self.assertIn(["systemctl", "restart", "--", "nginx.service"], self.calls)

    def test_timeout_and_missing_commands_warn_then_refuse_restart(self):
        for error in (subprocess.TimeoutExpired("systemctl", 30), FileNotFoundError("systemctl")):
            with self.subTest(error=error), patch.object(services.subprocess, "run", side_effect=error):
                state = services.inspect_services("systemd")
                self.assertTrue(any(w.startswith(services.INCOMPLETE) for w in state["warnings"]))
                with self.assertRaises(RuntimeError):
                    services.restart_service("systemd", "nginx.service")

    def test_native_discovery_failure_does_not_invent_stopped_services(self):
        before = services.inspect_services("systemd")
        with patch.object(services.subprocess, "run", return_value=completed(rc=1, stderr="manager unavailable")):
            state = services.inspect_services("systemd", before)
        self.assertEqual(state["services"], [])
        self.assertTrue(any("manager unavailable" in w for w in state["warnings"]))

    def test_restart_timeout_is_failure_not_success(self):
        self.stale()
        def native(argv, **kwargs):
            if argv[:2] == ["systemctl", "restart"]:
                self.assertEqual(kwargs["timeout"], services.TIMEOUT)
                raise subprocess.TimeoutExpired(argv, services.TIMEOUT)
            return self.native(argv, **kwargs)
        with patch.object(services.subprocess, "run", side_effect=native), self.assertRaisesRegex(RuntimeError, "timed out"):
            services.restart_service("systemd", "nginx.service")

    def test_openrc_status_errors_are_discovery_warnings(self):
        self.rc = {"web": True}
        (self.run / "openrc/started/web").touch()
        def native(argv, **kwargs):
            if argv == ["rc-service", "web", "status"]:
                return completed(rc=2, stderr="status unavailable")
            return self.native(argv, **kwargs)
        with patch.object(services.subprocess, "run", side_effect=native):
            state = services.inspect_services("openrc")
            self.assertTrue(any(w.startswith(services.INCOMPLETE) for w in state["warnings"]))
            with self.assertRaisesRegex(RuntimeError, "incomplete discovery"):
                services.restart_service("openrc", "web")

    def test_pid_change_is_informational_not_a_restart_reason(self):
        self.process(pid=40)
        before = services.inspect_services("systemd")
        import shutil
        shutil.rmtree(self.proc / "40")
        self.process(pid=42)
        state = services.inspect_services("systemd", before)
        self.assertEqual(self.row(state)["reasons"], [])
        self.assertTrue(any("running PIDs changed" in w for w in state["warnings"]))
        self.assertEqual(services.restart_service("systemd", "nginx.service", before)["status"], "already-current")

    def test_explicitly_previously_inactive_service_is_not_started(self):
        before = {"services": [{"name": "sshd.service", "active": False, "pids": [],
                                "reasons": [], "confidence": "high"}],
                  "unmanaged": [], "warnings": []}
        with self.assertRaisesRegex(RuntimeError, "was not active"):
            services.restart_service("systemd", "sshd.service", before)
        self.assertFalse(any(argv[1] == "restart" for argv in self.calls))

    def test_proc_permission_failure_warns_and_blocks_restart(self):
        path = self.stale()
        original = Path.read_text
        def read(path_arg, *args, **kwargs):
            if path_arg == path / "maps":
                raise PermissionError("maps denied")
            return original(path_arg, *args, **kwargs)
        with patch.object(Path, "read_text", read):
            state = services.inspect_services("systemd")
            self.assertTrue(any("maps denied" in w for w in state["warnings"]))
            with self.assertRaisesRegex(RuntimeError, "incomplete discovery"):
                services.restart_service("systemd", "nginx.service")

    def test_process_disappearing_is_benign(self):
        self.process()
        with patch.object(services.os, "readlink", side_effect=FileNotFoundError()):
            self.assertEqual(services.inspect_services("systemd")["warnings"], [])

    def test_helper_process_race_is_benign(self):
        self.process()
        with patch.object(services, "process_info", side_effect=ProcessLookupError()):
            self.assertEqual(services.inspect_services("systemd")["warnings"], [])

    def test_removed_service_cannot_restart_from_old_snapshot(self):
        before = services.inspect_services("systemd")
        del self.units["nginx.service"]
        with self.assertRaisesRegex(RuntimeError, "not a current managed"):
            services.restart_service("systemd", "nginx.service", before)

    def test_invalid_names_init_and_snapshot_are_rejected_before_commands(self):
        before = services.inspect_services("systemd")
        self.calls.clear()
        for name in ("--all", "nginx.service;reboot", "../nginx.service", "nginx\n.service", "nginx", "a\0.service", None):
            with self.subTest(name=name), self.assertRaises(ValueError):
                services.restart_service("systemd", name)
        with self.assertRaises(ValueError):
            services.inspect_services("runit")
        bad = [[], {}, dict(before, warnings="no"), dict(before, unmanaged=[{}])]
        for field, value in (("active", 1), ("pids", [True]), ("pids", [-1]), ("pids", [42, 42]),
                             ("confidence", "guess"), ("reasons", "stale"), ("name", "--all")):
            altered = copy.deepcopy(before)
            altered["services"][0][field] = value
            bad.append(altered)
        duplicate = copy.deepcopy(before)
        duplicate["services"].append(copy.deepcopy(duplicate["services"][0]))
        bad.append(duplicate)
        for snapshot in bad:
            with self.subTest(snapshot=snapshot), self.assertRaises(ValueError):
                services.restart_service("systemd", "nginx.service", snapshot)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
