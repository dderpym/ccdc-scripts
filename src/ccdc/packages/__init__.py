"""OS package layer.

InstallApt/InstallDnf/... install named packages with one manager. InstallPackage
subclasses (InstallNftables) hold a table of what each OS family calls the package,
detect the OS on every run and delegate. Nothing is remembered between runs: the
host script asks the package database each time.
"""
from ccdc.ansible import AnsibleScript
from ccdc.osinfo import DetectOS
from ccdc.runner import RemoteError, failure_message
from ccdc.script import HostScript


class InstallWith(AnsibleScript):
    """Install packages with one specific package manager (remote.py asks the package database first)."""
    source = "remote.py"
    manager = None

    def arguments(self, packages=(), **kwargs):
        return [self.manager, *packages]

    def parse(self, result, **kwargs):
        if result["rc"] != 0:
            raise RemoteError("%s: %s" % (self.name, failure_message(result)))
        return super().parse(result, **kwargs)


class InstallApt(InstallWith):
    manager = "apt"


class InstallDnf(InstallWith):
    manager = "dnf"


class InstallApk(InstallWith):
    manager = "apk"


class InstallPacman(InstallWith):
    manager = "pacman"


class InstallXbps(InstallWith):
    manager = "xbps"


class InstallZypper(InstallWith):
    manager = "zypper"


MANAGER_FOR_FAMILY = {"debian": InstallApt, "rhel": InstallDnf, "alpine": InstallApk,
                      "arch": InstallPacman, "void": InstallXbps, "suse": InstallZypper}


class UnsupportedOS(RuntimeError):
    pass


class InstallPackage(HostScript):
    """Install `packages[family]` on whatever the target runs."""
    packages = {}

    def __init__(self, runner=None):
        self.runner = runner

    def run(self, target):
        info = DetectOS(self.runner).run(target)
        names = self.packages.get(info.family)
        manager = MANAGER_FOR_FAMILY.get(info.family)
        if not names or not manager:
            raise UnsupportedOS(f"{self.name}: no recipe for {info.id or 'unknown'} ({info.family})")
        return manager(self.runner).run(target, packages=names)


class InstallNftables(InstallPackage):
    packages = {family: ["nftables"] for family in MANAGER_FOR_FAMILY}


class InstallAuditd(InstallPackage):
    packages = {"debian": ["auditd"], "rhel": ["audit"], "suse": ["audit"],
                "arch": ["audit"], "alpine": ["audit"]}
