"""Offline permission fixtures only: no host scans, commands or socket connections."""
import errno
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "lse_extras", Path(__file__).resolve().parents[1] / "host/lse_extras.py")
extras = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(extras)


def block(body="", status="yes!", marker="i"):
    return "[%s] sec010 List files with capabilities....... %s\n---\n%s\n---\n" % (marker, status, body)


def by_id(result):
    return {f["id"]: f for f in result["findings"]}


class ExtrasTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.allowed, self.owners = {}, {}
        self.real_stat, self.real_lstat = os.stat, os.lstat
        self.real_open, self.real_scandir = os.open, os.scandir
        # Outside ancestors have synthetic metadata; no real host configs,
        # sockets, metadata or directory listings are consulted by these tests.
        self.start_patch("geteuid", return_value=1000)
        self.start_patch("getegid", return_value=-1)
        self.start_patch("getgroups", return_value=[])
        self.start_patch("access", side_effect=self.access)
        self.start_patch("stat", side_effect=lambda p, **kw: self.metadata(p, self.real_stat, **kw))
        self.start_patch("lstat", side_effect=lambda p, **kw: self.metadata(p, self.real_lstat, **kw))
        self.start_patch("open", side_effect=self.open_fixture)
        self.start_patch("scandir", side_effect=self.scandir_fixture)

    def start_patch(self, name, **kwargs):
        patcher = patch.object(extras.os, name, **kwargs)
        mock = patcher.start()
        self.addCleanup(patcher.stop)
        return mock

    def inside(self, path):
        return os.path.commonpath((os.path.abspath(path), str(self.root))) == str(self.root)

    def metadata(self, path, native, **kwargs):
        if not self.inside(path):
            return os.stat_result((stat.S_IFDIR | 0o555, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        result = list(native(path, **kwargs))
        result[4] = self.owners.get(os.fspath(path), 0)
        return os.stat_result(result)

    def access(self, path, mode, *, effective_ids):
        self.assertTrue(effective_ids)
        return self.allowed.get(os.fspath(path), 0) & mode == mode

    def open_fixture(self, path, flags, *args, **kwargs):
        self.assertTrue(self.inside(path), "host file read: " + str(path))
        self.assertTrue(flags & os.O_NONBLOCK)
        return self.real_open(path, flags, *args, **kwargs)

    def scandir_fixture(self, path):
        self.assertTrue(self.inside(path), "host traversal: " + str(path))
        return self.real_scandir(path)

    def file(self, name, text=""):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def allow(self, path, mode=os.W_OK):
        self.allowed[str(path)] = mode
        return path

    def unix_socket(self, name):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(path))
        self.addCleanup(sock.close)
        return path

    def loader(self, conf=None, preload=None, **kwargs):
        return extras.inspect_loader(conf or self.root / "ld.so.conf",
                                     preload or self.root / "ld.so.preload", **kwargs)

    def assert_gap(self, result, name):
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["incomplete_ids"], ["extra-" + name])
        finding = by_id(result)["scanner-extra-" + name]
        self.assertEqual(finding["severity"], "warning")
        self.assertTrue(finding["context"])

    def test_capabilities_vendor_body_spaces_per_capability_flags_and_names(self):
        entries = [
            ("with spaces/python3.11", "cap_setuid=ep cap_net_raw+i", True),
            ("p/python", "cap_dac_read_search=p", True),
            ("e/perl", "cap_sys_ptrace=e", True),
            ("i/ruby", "cap_setuid=i cap_net_raw=ep", False),
            ("cp", "cap_dac_override=ep", True),
            ("dd", "cap_dac_read_search=p", True),
            ("tar", "cap_dac_override=e", True),
            ("wrong/cp", "cap_setuid=ep", False),
            ("ping", "cap_net_raw=ep", False),
            ("service", "cap_net_bind_service=ep", False),
            ("python-custom", "cap_setuid=ep", False),
            ("mixed/php8.2", "cap_setuid=i cap_sys_admin=p", True),
            ("grouped/lua5.4", "cap_setuid,cap_setgid=i cap_sys_admin,cap_sys_module=ep", True),
            ("reset/bash", "cap_setuid=p cap_setuid=i", False),
        ]
        lines, expected = [], set()
        for name, caps, flagged in entries:
            path = self.allow(self.file(name), os.X_OK)
            lines.append(str(path) + " " + caps)
            if flagged:
                expected.add(str(path))
        raw = "User ID: 0\n" + block("\n".join(lines)) + block(lines[0])
        raw = raw.replace("[i]", "\x1b[32m[i]\x1b[0m")
        result = extras.inspect_capabilities(raw)
        finding = by_id(result)["extra-capabilities"]
        self.assertEqual(set(by_id(result)), {"extra-capabilities"})
        self.assertEqual(finding["severity"], "warning")
        self.assertEqual({c["evidence"][0] for c in finding["context"]}, expected)
        self.assertEqual(len(finding["context"]), len(expected))
        self.assertNotIn("cap_net_raw", json.dumps(finding))
        self.assertNotIn("incomplete_ids", result)
        self.assertEqual(result["raw"], raw)
        self.assertEqual(result["errors"], [])

    def test_capabilities_regular_executable_only_old_format_and_other_sections(self):
        valid = self.allow(self.file("old/python"), os.X_OK)
        noexec = self.file("noexec/python")
        directory = self.root / "directory/python"
        directory.mkdir(parents=True)
        fifo = self.root / "fifo/python"
        fifo.parent.mkdir()
        os.mkfifo(fifo)
        for path in (directory, fifo):
            self.allow(path, os.X_OK)
        outside_body = self.allow(self.file("other/python"), os.X_OK)
        raw = block(str(valid) + " = cap_setuid+ep [rootid=0]\n" +
                    "\n".join(str(p) + " cap_setuid=ep" for p in (noexec, directory, fifo)))
        raw += "[!] sec020 Other check....... yes!\n---\n" + str(outside_body) + " cap_setuid=ep\n---\n"
        contexts = by_id(extras.inspect_capabilities(raw))["extra-capabilities"]["context"]
        self.assertEqual([c["evidence"][0] for c in contexts], [str(valid)])

    def test_capabilities_gaps_and_malformed_never_echo_contents(self):
        for raw in ("", block(status="skip"), block(status="nope"), block(),
                    block("WARNING: SECRET_TOKEN=do-not-echo"),
                    block("/malformed/python cap_setuid=ep trailing garbage")):
            with self.subTest(raw=raw):
                result = extras.inspect_capabilities(raw)
                self.assert_gap(result, "capabilities")
                self.assertEqual(set(by_id(result)), {"scanner-extra-capabilities"})
                self.assertNotIn("SECRET_TOKEN", json.dumps(result["findings"]))
        path = self.allow(self.file("python"), os.X_OK)
        result = extras.inspect_capabilities(block(str(path) + " cap_setuid=ep") + block(status="skip"))
        self.assert_gap(result, "capabilities")
        self.assertIn("extra-capabilities", by_id(result))

    def test_successful_empty_getcap_resolves_while_failed_inventory_stays_incomplete(self):
        self.assertEqual(extras.inspect_capabilities(block(status='nope'), 0),
                         {'findings': [], 'raw': block(status='nope'), 'errors': []})
        for status in (None, 1, 7):
            self.assert_gap(extras.inspect_capabilities(block(status='nope'), status), 'capabilities')
        path = self.allow(self.file('python'), os.X_OK)
        result = extras.inspect_capabilities(block(str(path) + ' cap_setuid=ep'), 1)
        self.assertIn('extra-capabilities', by_id(result))
        self.assert_gap(result, 'capabilities')

    def test_capability_permission_error_is_scoped(self):
        path = self.file("python")
        native = extras.os.stat.side_effect
        def denied(p, **kwargs):
            if os.fspath(p) == str(path):
                raise PermissionError(errno.EACCES, "denied")
            return native(p, **kwargs)
        with patch.object(extras.os, "stat", side_effect=denied):
            self.assert_gap(extras.inspect_capabilities(block(str(path) + " cap_setuid=p")), "capabilities")

    def test_runtime_real_root_sockets_only_no_connections(self):
        good = self.allow(self.unix_socket("docker.sock"))
        rootless = self.allow(self.unix_socket("containerd.sock"))
        self.owners[str(rootless)] = 1000
        readonly = self.unix_socket("readonly.sock")
        spoof = self.allow(self.file("docker.socket"))
        paths = (good, rootless, readonly, spoof, self.root / "absent")
        with patch.object(socket.socket, "connect", side_effect=AssertionError("no connections")):
            result = extras.inspect_runtime_sockets(paths)
        self.assertEqual(set(by_id(result)), {"extra-runtime-sockets"})
        finding = by_id(result)["extra-runtime-sockets"]
        self.assertEqual([c["evidence"][0] for c in finding["context"]], [str(good)])
        self.assertIn("NOT prove API authorization or daemon mode", finding["context"][0]["summary"])
        self.assertNotIn("incomplete_ids", result)

    def test_runtime_defaults_remapped_and_bounded_traversal_ignores_symlink_dirs(self):
        expected = []
        for name in extras.RUNTIME_PATHS:
            expected.append(self.allow(self.unix_socket(name)))
        outside = self.root / "outside"
        hidden = self.allow(self.unix_socket("outside/docker.sock"))
        (self.root / "linked").symlink_to(outside, target_is_directory=True)
        with patch.object(extras, "LXD_PATHS", (str(self.root / "absent-lxd"),)):
            result = extras.inspect_runtime_sockets(run_root=str(self.root))
        self.assertEqual({c["evidence"][0] for c in by_id(result)["extra-runtime-sockets"]["context"]}, set(map(str, expected)))
        run = self.root / "bounded"
        run.mkdir()
        (run / "linked").symlink_to(outside, target_is_directory=True)
        discovered = self.allow(self.unix_socket("bounded/nested/docker.socket"))
        self.allow(self.unix_socket("bounded/unrelated/unix.socket"))
        result = extras.inspect_runtime_sockets([], run_root=run, traverse=True)
        contexts = by_id(result)["extra-runtime-sockets"]["context"]
        self.assertEqual([c["evidence"][0] for c in contexts], [str(discovered)])
        self.assertNotIn(str(hidden), json.dumps(result))
        for bounds in ({"max_entries": 0}, {"max_depth": 0}):
            self.assert_gap(extras.inspect_runtime_sockets([], run_root=run, traverse=True, **bounds), "runtime-sockets")

    def test_runtime_non_enoent_errors_are_gaps_absence_is_normal(self):
        result = extras.inspect_runtime_sockets([self.root / "missing"])
        self.assertEqual(result, {"findings": [], "raw": "", "errors": []})
        with patch.object(extras.os, "stat", side_effect=PermissionError(errno.EACCES, "denied")):
            self.assert_gap(extras.inspect_runtime_sockets([self.root / "denied"]), "runtime-sockets")
        with patch.object(extras.os, "scandir", side_effect=PermissionError(errno.EACCES, "denied")):
            self.assert_gap(extras.inspect_runtime_sockets([], run_root=self.root, traverse=True), "runtime-sockets")

    def test_loader_benign_relative_includes_comments_cycles_symlinks_and_missing(self):
        self.file("ld.so.conf", "# ignored\ninclude conf.d/*.conf\n")
        self.file("conf.d/a.conf", "# comment\n" + str(self.root / 'lib') + " # library directory\ninclude ../ld.so.conf\ninclude alias.conf\n")
        self.file("conf.d/alias.conf", "include a.conf\n")
        (self.root / "conf.d/alias.conf").unlink()
        (self.root / "conf.d/alias.conf").symlink_to("a.conf")
        (self.root / "lib").mkdir()
        result = self.loader()
        self.assertEqual(result, {"findings": [], "raw": "", "errors": []})
        self.assertEqual(self.loader(self.root / "missing.conf", self.root / "missing.preload"), result)
        self.assertEqual(self.loader(self.file("one.conf", ""), max_files=1), result)

    def test_loader_grouped_writable_configs_empty_includes_search_and_preload(self):
        conf = self.allow(self.file("ld.so.conf", "include empty/*.conf\ninclude conf.d/*.conf\n" + str(self.root / 'lib') + '\n'))
        empty = self.root / "empty"
        empty.mkdir()
        self.allow(empty, os.W_OK | os.X_OK)
        included = self.allow(self.file("conf.d/a.conf", "# SECRET_DO_NOT_ECHO\n"))
        libdir = self.root / "lib"
        libdir.mkdir()
        self.allow(libdir, os.W_OK | os.X_OK)
        first = self.allow(self.file("libs/one.so", "secret binary contents"))
        second = self.allow(self.file("libs/two.so"))
        preload = self.allow(self.file("ld.so.preload", str(first) + "\t" + str(second) + " # ignore\n" + str(first)))
        result = self.loader()
        self.assertEqual(set(by_id(result)), {"extra-loader"})
        contexts = by_id(result)["extra-loader"]["context"]
        evidence = {c["evidence"][0] for c in contexts}
        self.assertEqual(evidence, set(map(str, (conf, empty, included, libdir, first, second, preload))))
        self.assertEqual(len(contexts), len(evidence))
        self.assertEqual(result["raw"], "")
        for secret in ("SECRET_DO_NOT_ECHO", "secret binary contents", "# ignore"):
            self.assertNotIn(secret, json.dumps(result))
        self.assertNotIn("incomplete_ids", result)

    def test_loader_parent_replacement_sticky_ownership_and_execute_requirement(self):
        conf = self.file("ld.so.conf", "")
        self.root.chmod(0o1777)
        self.allow(self.root, os.W_OK | os.X_OK)
        # A sticky root-owned fixture parent cannot replace root-owned entries.
        self.assertEqual(self.loader()["findings"], [])
        self.owners[str(conf)] = 1000
        contexts = by_id(self.loader())["extra-loader"]["context"]
        self.assertEqual([c["evidence"][0] for c in contexts], [str(self.root)])
        self.owners[str(conf)] = 0
        self.owners[str(self.root)] = 1000
        self.assertIn("extra-loader", by_id(self.loader()))  # sticky directory owner
        self.owners[str(self.root)] = 0
        self.root.chmod(0o777)
        self.allowed[str(self.root)] = os.W_OK  # no search permission
        self.assertEqual(self.loader()["findings"], [])
        self.allowed[str(self.root)] |= os.X_OK
        self.assertIn("extra-loader", by_id(self.loader()))

    def test_loader_symlink_config_target_parent_is_inspected(self):
        target = self.file("target/config", "")
        conf = self.root / "ld.so.conf"
        conf.symlink_to(target)
        self.allow(target.parent, os.W_OK | os.X_OK)
        contexts = by_id(self.loader())["extra-loader"]["context"]
        self.assertEqual([c["evidence"][0] for c in contexts], [str(target.parent)])
        self.allowed.clear()
        self.root.chmod(0o1777)
        self.allow(self.root, os.W_OK | os.X_OK)
        self.assertEqual(self.loader()["findings"], [])
        native = extras.os.lstat.side_effect
        def owned_link(path, **kwargs):
            result = list(native(path, **kwargs))
            if os.fspath(path) == str(conf):
                result[4] = 1000  # The link, not its root-owned referent, is ours.
            return os.stat_result(result)
        with patch.object(extras.os, "lstat", side_effect=owned_link):
            contexts = by_id(self.loader())["extra-loader"]["context"]
        self.assertEqual([c["evidence"][0] for c in contexts], [str(self.root)])

    def test_loader_fifo_directory_and_read_bounds_are_scoped_no_hang(self):
        for name, make in (("fifo", lambda p: os.mkfifo(p)), ("dir", lambda p: p.mkdir())):
            path = self.root / name
            make(path)
            self.assert_gap(self.loader(path), "loader")
        alias = self.root / "fifo-link"
        alias.symlink_to(self.root / "fifo")
        self.assert_gap(self.loader(alias), "loader")
        huge = self.file("huge", "SECRET" * (extras.READ_LIMIT // 6 + 1))
        result = self.loader(huge)
        self.assert_gap(result, "loader")
        self.assertNotIn("SECRET", json.dumps(result))
        self.assert_gap(self.loader(self.file("small", "12345"), read_limit=4), "loader")

    def test_loader_inaccessible_present_config_and_glob_gaps(self):
        conf = self.file("ld.so.conf", "include conf.d/*.conf\n")
        self.file("conf.d/a.conf", "")
        native = extras.os.open.side_effect
        def denied(path, *args, **kwargs):
            if str(path) == str(conf):
                raise PermissionError(errno.EACCES, "denied")
            return native(path, *args, **kwargs)
        with patch.object(extras.os, "open", side_effect=denied):
            self.assert_gap(self.loader(), "loader")
        with patch.object(extras.os, "scandir", side_effect=PermissionError(errno.EACCES, "denied")):
            self.assert_gap(self.loader(), "loader")

    def test_loader_file_depth_glob_bounds_and_relative_preload(self):
        self.file("ld.so.conf", "include conf.d/*.conf\n")
        self.file("conf.d/a.conf", "include next.conf\n")
        self.file("conf.d/next.conf", "")
        for bounds in ({"max_files": 1}, {"max_depth": 0}, {"max_glob_entries": 0}):
            with self.subTest(bounds=bounds):
                self.assert_gap(self.loader(**bounds), "loader")
        self.file("ld.so.preload", "relative.so\n")
        self.assert_gap(self.loader(), "loader")
        self.file("ld.so.preload", "")
        (self.root / "empty").mkdir()
        self.file("ld.so.conf", "include empty/*.conf\n" * 20)
        self.assert_gap(self.loader(max_glob_entries=10), "loader")

    def test_root_suppression_uses_actual_effective_uid_and_scoped_gaps(self):
        path = self.allow(self.file("python"), os.X_OK)
        with patch.object(extras.os, "geteuid", return_value=0), \
                patch.object(extras.os, "stat", side_effect=AssertionError("root must not inspect")), \
                patch.object(extras.os, "open", side_effect=AssertionError("root must not read")):
            parts = (("capabilities", extras.inspect_capabilities("User ID: 1000\n" + block(str(path) + " cap_setuid=ep"))),
                     ("runtime-sockets", extras.inspect_runtime_sockets([self.root / "socket"])),
                     ("loader", self.loader()))
        for name, result in parts:
            self.assert_gap(result, name)
            self.assertEqual(set(by_id(result)), {"scanner-extra-" + name})

    def sudo(self, policy, account='oski', rc=0):
        self.allow('/usr/bin/sudo', os.X_OK)
        output = subprocess.CompletedProcess(['/usr/bin/sudo', '-n', '-l'], rc, policy, '')
        with patch('subprocess.run', return_value=output) as command, \
                patch('pwd.getpwuid', return_value=SimpleNamespace(pw_name=account)):
            result = extras.inspect_sudo()
        self.assertEqual(command.call_args.args[0], ['/usr/bin/sudo', '-n', '-l'])
        self.assertEqual(command.call_args.kwargs['stdin'], subprocess.DEVNULL)
        self.assertEqual(command.call_args.kwargs['env']['LC_ALL'], 'C')
        return result

    def test_loader_preserves_symlink_dotdot_and_rejects_relative_search_paths(self):
        actual = self.root / 'vendor/conf.d'
        actual.mkdir(parents=True)
        alias = self.root / 'etc/conf.d/current'
        alias.parent.mkdir(parents=True)
        alias.symlink_to(actual, target_is_directory=True)
        target = self.allow(self.file('vendor/custom.conf', ''))
        self.file('etc/conf.d/custom.conf', '')  # Lexical normalization would inspect this wrong file.
        conf = self.file('ld.so.conf', 'include ' + str(alias) + '/../custom.conf\n')
        result = self.loader(conf)
        evidence = {c['evidence'][0] for c in by_id(result)['extra-loader']['context']}
        self.assertTrue(any('vendor/custom.conf' in path for path in evidence))
        self.assertFalse(any(str(self.root / 'etc/conf.d/custom.conf') == path for path in evidence))
        conf.write_text('relative-library-dir\n')
        result = self.loader(conf)
        self.assert_gap(result, 'loader')
        self.assertNotIn('extra-loader', by_id(result))

    def test_bad_loader_metadata_keeps_other_checks_and_scoped_gap(self):
        self.file('ld.so.conf', '/missing\0library\n')
        self.assert_gap(self.loader(), 'loader')
        raw = block(status='nope')
        sockets = extras._result('runtime-sockets', [{'summary': 'fixture', 'evidence': ['/fixture/socket']}])
        sudo = {'findings': [], 'raw': '', 'errors': []}
        with patch.object(extras, 'inspect_capabilities', return_value=extras.inspect_capabilities(raw, 0)), \
                patch.object(extras, 'inspect_runtime_sockets', return_value=sockets), \
                patch.object(extras, 'inspect_loader', side_effect=ValueError('embedded null byte')), \
                patch.object(extras, 'inspect_sudo', return_value=sudo) as inspect_sudo, \
                patch.object(extras, 'inspect_process_capabilities', return_value=sudo), \
                patch.object(extras, 'inspect_sgid', return_value=sudo), \
                patch.object(extras, 'inspect_doas', return_value=sudo):
            result = extras.scan(raw, 0)
        inspect_sudo.assert_called_once_with()
        self.assertIn('extra-runtime-sockets', by_id(result))
        self.assert_gap(result, 'loader')
        self.assertEqual(result['errors'], [])

    def test_sudo_unrestricted_root_interpreters_and_secure_path(self):
        directory = self.root / 'bin with spaces'
        directory.mkdir()
        self.allow(directory, os.W_OK | os.X_OK)
        policy = f'Matching Defaults entries:\n    secure_path="{directory}:/usr/bin"\n'
        policy += 'User may run:\n    (root) NOPASSWD: /usr/bin/python3.11\n    (ALL : ALL) PASSWD: /bin/bash\n'
        result = self.sudo(policy)
        finding = by_id(result)['extra-sudo']
        self.assertEqual(len(finding['context']), 3)
        self.assertIn('secure_path', finding['context'][-1])
        self.assertEqual(result['raw'], 'sudo -n -l:\n' + policy)
        self.assertNotIn('incomplete_ids', result)

    def test_sudo_expected_oski_all_nonroot_negated_and_restricted_rules_quiet(self):
        for rule in ('(ALL : ALL) NOPASSWD: ALL', '(ALL : ALL) ALL',
                     '(postgres) NOPASSWD: /usr/bin/python3', '(ALL,!root) NOPASSWD: /bin/bash',
                     '(ALL,!#0) NOPASSWD: /bin/bash',
                     '(root) NOPASSWD: /bin/bash\n    (root) NOPASSWD: !/bin/bash',
                     '(root) NOPASSWD: /usr/bin/python3 /opt/fixed.py', '(root) NOPASSWD: /usr/bin/python3 ""',
                     '(root) NOPASSWD: !/usr/bin/python3', '(root) NOPASSWD: /usr/bin/python3, !/usr/bin/python3',
                     '(root) NOPASSWD: /usr/bin/python3\n        /opt/fixed.py'):
            with self.subTest(rule=rule):
                self.assertEqual(self.sudo('    ' + rule + '\n')['findings'], [])
        result = self.sudo('    (ALL : ALL) ALL\n', account='someone-else')
        self.assertIn('extra-sudo', by_id(result))
        self.assertEqual(self.sudo('    (ALL : ALL) NOPASSWD: ALL\n', account='someone-else')['findings'], [])
        # oski's unrelated dangerous policy details are not blanket-suppressed.
        self.assertIn('extra-sudo', by_id(self.sudo('    (root) NOPASSWD: /bin/bash\n')))

    def test_sudo_unavailable_root_refusal_and_timeout_are_scoped(self):
        with patch('subprocess.run', side_effect=AssertionError('must not run')):
            self.assert_gap(extras.inspect_sudo(), 'sudo')
            with patch.object(extras.os, 'geteuid', return_value=0):
                self.assert_gap(extras.inspect_sudo(), 'sudo')
        self.assert_gap(self.sudo('policy requires authentication\n', rc=1), 'sudo')
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired('sudo', 10)):
            self.assert_gap(extras.inspect_sudo(), 'sudo')

    def process_status(self, name, uid=1000, eff=0, ambient=0, bounding=(1 << 41) - 1):
        return self.file(name + '/status', f'Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n'
                         f'CapEff:\t{eff:016x}\nCapAmb:\t{ambient:016x}\nCapBnd:\t{bounding:016x}\n')

    def test_process_capabilities_effective_ambient_not_bounding_or_other_accounts(self):
        self.process_status('self', eff=1 << 7)
        self.process_status('42', ambient=1 << 21)
        result = extras.inspect_process_capabilities(self.root, parent=42)
        self.assertEqual(set(by_id(result)), {'extra-process-capabilities'})
        contexts = by_id(result)['extra-process-capabilities']['context']
        self.assertEqual({c['evidence'][0] for c in contexts}, {'cap_setuid', 'cap_sys_admin'})
        self.process_status('self')
        self.process_status('42', uid=0, eff=(1 << 41) - 1)
        self.assertEqual(extras.inspect_process_capabilities(self.root, parent=42)['findings'], [])
        self.process_status('42', eff=1 << 13)  # NET_RAW alone is not the dangerous set.
        self.assertEqual(extras.inspect_process_capabilities(self.root, parent=42)['findings'], [])

    def test_process_capability_incomplete_metadata_does_not_erase_positive_evidence(self):
        self.process_status('self', eff=1 << 7)
        path = self.process_status('42')
        for text in ('Uid: bad\n', 'Uid: 1000 1000 1000 1000\nCapEff: garbage\n',
                     'Uid: 1000 1000 1000 1000\nCapEff: 0\n'):
            path.write_text(text)
            result = extras.inspect_process_capabilities(self.root, parent=42)
            self.assert_gap(result, 'process-capabilities')
            self.assertIn('extra-process-capabilities', by_id(result))
        path.unlink()
        self.assert_gap(extras.inspect_process_capabilities(self.root, parent=42), 'process-capabilities')
        with patch.object(extras.os, 'geteuid', return_value=0), \
                patch.object(extras, '_read_regular', side_effect=AssertionError('root must not read')):
            self.assert_gap(extras.inspect_process_capabilities(self.root, parent=42), 'process-capabilities')

    def test_sgid_only_executable_interpreters_or_writable_other_group_files(self):
        interpreter = self.allow(self.file('bin/python3'), os.X_OK)
        writable = self.allow(self.file('bin/custom'), os.X_OK | os.W_OK)
        ordinary = self.allow(self.file('bin/ordinary'), os.X_OK)
        noexec = self.allow(self.file('bin/bash'), os.W_OK)
        for path in (interpreter, writable, ordinary, noexec):
            path.chmod(0o2755)
        normal = self.allow(self.file('bin/perl'), os.X_OK | os.W_OK)
        normal.chmod(0o755)
        result = extras.inspect_sgid([self.root / 'bin'])
        self.assertEqual(set(by_id(result)), {'extra-sgid'})
        contexts = by_id(result)['extra-sgid']['context']
        self.assertEqual({c['evidence'][0] for c in contexts}, {str(interpreter), str(writable)})
        with patch.object(extras.os, 'getgroups', return_value=[self.real_stat(interpreter).st_gid]):
            self.assertEqual(extras.inspect_sgid([self.root / 'bin'])['findings'], [])

    def test_sgid_bounded_symlink_roots_but_not_entry_links_and_scoped_errors(self):
        self.allow(self.file('bin/nested/python'), os.X_OK).chmod(0o2755)
        hidden = self.allow(self.file('outside/bash'), os.X_OK)
        hidden.chmod(0o2755)
        (self.root / 'bin/linked').symlink_to(self.root / 'outside', target_is_directory=True)
        (self.root / 'root-link').symlink_to(self.root / 'bin', target_is_directory=True)
        result = extras.inspect_sgid([self.root / 'root-link'])
        self.assertNotIn(str(hidden), json.dumps(result))
        for bounds in ({'max_entries': 0}, {'max_depth': 0}):
            self.assert_gap(extras.inspect_sgid([self.root / 'bin'], **bounds), 'sgid')
        with patch.object(extras.os, 'scandir', side_effect=PermissionError('denied')):
            self.assert_gap(extras.inspect_sgid([self.root / 'bin']), 'sgid')
        self.assertEqual(extras.inspect_sgid([self.root / 'missing'])['findings'], [])
        with patch.object(extras.os, 'geteuid', return_value=0):
            self.assert_gap(extras.inspect_sgid([self.root / 'bin']), 'sgid')

    def doas_files(self):
        binary = self.allow(self.file('bin/doas'), os.X_OK)
        binary.chmod(0o4755)
        conf = self.file('doas.conf', 'permit nopass oski as root\ndeny oski as root cmd sh\n')
        conf.chmod(0o600)
        command = self.allow(self.file('bin/sh'), os.X_OK)
        command.chmod(0o700)  # Executable by synthetic root, not necessarily this account.
        return binary, conf, command

    def test_doas_native_configuration_only_verdicts_no_delegated_execution(self):
        binary, conf, command = self.doas_files()
        for verdict, rc, expected in (('permit nopass', 0, True), ('permit', 0, True),
                                      ('deny', 0, False), ('deny', 1, False)):
            with self.subTest(verdict=verdict, rc=rc), \
                    patch('subprocess.run', return_value=subprocess.CompletedProcess([], rc, verdict, '')) as run:
                result = extras.inspect_doas(conf, [binary], [command])
            self.assertEqual('extra-doas' in by_id(result), expected)
            self.assertNotIn('incomplete_ids', result)
            self.assertEqual([call.args[0] for call in run.call_args_list],
                             [[binary, '-C', str(conf), '-u', 'root', str(command)],
                              [binary, '-C', str(conf), '-u', 'root', 'sh']])
            self.assertEqual(run.call_args.kwargs['stdin'], subprocess.DEVNULL)
            self.assertEqual(run.call_args.kwargs['timeout'], 5)
            self.assertEqual(run.call_args.kwargs['env']['LC_ALL'], 'C')
        self.assertNotIn('permit nopass oski', json.dumps(result))

    def test_doas_basename_grants_and_root_only_executables_are_not_missed(self):
        binary, conf, command = self.doas_files()
        self.allowed.pop(str(command))  # The account itself cannot execute it.
        replies = [subprocess.CompletedProcess([], 1, 'deny', ''),
                   subprocess.CompletedProcess([], 0, 'permit nopass', '')]
        with patch('subprocess.run', side_effect=replies):
            result = extras.inspect_doas(conf, [binary], [command])
        contexts = by_id(result)['extra-doas']['context']
        self.assertEqual(contexts[0]['evidence'][0], 'sh')
        self.assertNotIn('incomplete_ids', result)
        with patch('subprocess.run', side_effect=AssertionError('no executable to check')):
            command.chmod(0o600)
            self.assert_gap(extras.inspect_doas(conf, [binary], [command]), 'doas')

    def test_doas_runtime_config_guards_setuid_presence_and_failures(self):
        binary, conf, command = self.doas_files()
        with patch('subprocess.run', side_effect=AssertionError('must not execute')):
            conf.chmod(0o666)
            self.allow(conf)
            result = extras.inspect_doas(conf, [binary], [command])
            self.assert_gap(result, 'doas')
            self.assertIn('extra-doas', by_id(result))
            self.allowed.pop(str(conf))
            conf.chmod(0o600)
            self.owners[str(conf)] = 1000
            self.assert_gap(extras.inspect_doas(conf, [binary], [command]), 'doas')
            self.owners[str(conf)] = 0
            binary.chmod(0o755)
            self.assertEqual(extras.inspect_doas(conf, [binary], [command])['findings'], [])
            binary.chmod(0o4755)
            self.owners[str(binary)] = 1000
            self.assertEqual(extras.inspect_doas(conf, [binary], [command])['findings'], [])
            self.owners[str(binary)] = 0
            with patch.object(extras.os, 'geteuid', return_value=0):
                self.assert_gap(extras.inspect_doas(conf, [binary], [command]), 'doas')
        for failure in (subprocess.CompletedProcess([], 1, '', 'permission denied SECRET'),
                        subprocess.CompletedProcess([], 0, 'unsupported', '')):
            with patch('subprocess.run', return_value=failure):
                result = extras.inspect_doas(conf, [binary], [command])
            self.assert_gap(result, 'doas')
            self.assertNotIn('SECRET', json.dumps(result))
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired('doas', 5)):
            self.assert_gap(extras.inspect_doas(conf, [binary], [command]), 'doas')

    def test_aggregator_preserves_scoped_results_without_duplicate_lse_raw(self):
        raw = "fixture raw"
        parts = [extras._result("capabilities", gaps=["fixture"], raw=raw),
                 extras._result("runtime-sockets"), extras._result("loader", gaps=["fixture"]),
                 {'findings': [], 'raw': 'sudo policy fixture', 'errors': []}]
        with patch.object(extras, "inspect_capabilities", return_value=parts[0]) as caps, \
                patch.object(extras, "inspect_runtime_sockets", return_value=parts[1]) as sockets, \
                patch.object(extras, "inspect_loader", return_value=parts[2]) as loader, \
                patch.object(extras, "inspect_sudo", return_value=parts[3]) as sudo, \
                patch.object(extras, 'inspect_process_capabilities', return_value=parts[1]), \
                patch.object(extras, 'inspect_sgid', return_value=parts[1]), \
                patch.object(extras, 'inspect_doas', return_value=parts[1]):
            result = extras.scan(raw)
        caps.assert_called_once_with(raw, None)
        sockets.assert_called_once_with()
        loader.assert_called_once_with()
        sudo.assert_called_once_with()
        self.assertEqual(result["raw"], 'sudo policy fixture\n')
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["incomplete_ids"], ["extra-capabilities", "extra-loader"])
        self.assertEqual(result["findings"], parts[0]["findings"] + parts[2]["findings"])


if __name__ == "__main__":
    unittest.main()
