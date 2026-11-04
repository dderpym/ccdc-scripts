from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ccdc.scripts.harden import DisableUnneededServices, Harden, HardenSSHD  # noqa: E402
from ccdc.target import Target  # noqa: E402
from host import fix_services, fix_sshd_hardening as sshd  # noqa: E402

T = Target("web01")


class Fake:
    def __init__(self, fail_fresh=False):
        self.calls, self.fail_fresh = [], fail_fresh

    def entry(self, target, entry, args=(), **kw):
        self.calls.append((entry, list(args), target.auth.variables().get("ansible_ssh_args", "")))
        if entry == "detect_os" and self.fail_fresh:
            raise RuntimeError("denied")
        return {}


class HostSide(unittest.TestCase):
    def test_render_has_all_options(self):
        text = sshd.render()
        for line in ("MaxAuthTries 3", "LoginGraceTime 30", "PermitUserEnvironment no", "ClientAliveCountMax 2"):
            self.assertIn(line, text)

    def test_include_detection(self):
        self.assertTrue(sshd.includes_dropins("Include /etc/ssh/sshd_config.d/*.conf\n"))
        self.assertFalse(sshd.includes_dropins("# Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n"))

    def test_watchdog_reverts_unless_confirmed(self):
        self.assertIn("-f " + sshd.ok_flag(), sshd.watchdog_command())
        self.assertIn("rm -f " + sshd.DROPIN, sshd.watchdog_command())

    def test_services_skip_absent_and_invalid(self):
        class R:
            def __init__(s, rc=0, out=""):
                s.returncode, s.stdout, s.stderr = rc, out, ""

        def run(argv, **kw):
            if argv[1] == "list-unit-files":
                return R(0, argv[2] + " enabled\n") if argv[2] == "cups.service" else R(0, "")
            return R(0)
        result = fix_services.disable(["cups.service", "bluetooth.service", "--bad"], run)
        self.assertEqual(result, {"disabled": ["cups.service"], "absent": ["bluetooth.service"],
                                  "failed": {"--bad": "invalid unit name"}})


class Controller(unittest.TestCase):
    def test_allowlist(self):
        args = DisableUnneededServices(Fake()).arguments(allow=["cups.service"])
        self.assertNotIn("cups.service", args)
        self.assertIn("avahi-daemon.service", args)

    def test_sshd_confirmed_after_fresh_login(self):
        fake = Fake()
        HardenSSHD(fake).run(T)
        self.assertEqual([c[:2] for c in fake.calls],
                         [("fix_sshd_hardening", ["apply"]), ("detect_os", []), ("fix_sshd_hardening", ["confirm"])])
        self.assertIn("ControlMaster=no", fake.calls[1][2])

    def test_failed_fresh_login_reverts_and_never_confirms(self):
        fake = Fake(fail_fresh=True)
        with self.assertRaises(RuntimeError):
            HardenSSHD(fake).run(T)
        self.assertEqual([c[1] for c in fake.calls if c[0] == "fix_sshd_hardening"], [["apply"], ["revert"]])

    def test_harden_composes_both(self):
        fake = Fake()
        Harden(fake, allow=["cups.service"]).run(target=T)
        self.assertEqual(fake.calls[-1][0], "fix_services")
        self.assertNotIn("cups.service", fake.calls[-1][1])


if __name__ == "__main__":
    unittest.main()
