"""OS package layer.

InstallApt/InstallDnf/... install named packages with one manager. InstallPackage
subclasses (InstallNftables) hold what each package manager calls the package, detect the OS
on every run, pick the manager from its lineage and delegate. Nothing is remembered between runs: the
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

    def arguments(self, packages=(), reinstall=False, **kwargs):
        return [self.manager, *(["--reinstall"] if reinstall else []), *packages]

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


# The only place distro names map to anything: first lineage entry found here wins.
MANAGER_FOR_DISTRO = {
    "debian": InstallApt, "ubuntu": InstallApt,
    "rhel": InstallDnf, "fedora": InstallDnf, "centos": InstallDnf, "rocky": InstallDnf,
    "almalinux": InstallDnf, "ol": InstallDnf, "amzn": InstallDnf,
    "alpine": InstallApk, "arch": InstallPacman, "void": InstallXbps,
    "suse": InstallZypper, "opensuse": InstallZypper, "sles": InstallZypper,
}
MANAGERS = (InstallApt, InstallDnf, InstallApk, InstallPacman, InstallXbps, InstallZypper)


def package_manager(info):
    """The InstallWith class for this OS, found by walking its lineage; None when unknown."""
    for name in info.lineage:
        for known, manager in MANAGER_FOR_DISTRO.items():
            if name == known or name.startswith(known + "-"):  # opensuse-leap, opensuse-tumbleweed
                return manager
    return None


class UnsupportedOS(RuntimeError):
    pass


class InstallPackage(HostScript):
    """Install `packages[manager name]` using the manager the target's OS lineage selects."""
    packages = {}

    def __init__(self, runner=None, reinstall=False):
        """reinstall=True also reinstalls the packages that are already present."""
        self.runner = runner
        self.reinstall = reinstall

    def run(self, target):
        info = DetectOS(self.runner).run(target)
        manager = package_manager(info)
        names = self.packages.get(manager.manager) if manager else None
        if not names:
            raise UnsupportedOS(f"{self.name}: no recipe for {info.name or info.id or 'unknown'} (lineage {'/'.join(info.lineage) or '?'})")
        return manager(self.runner).run(target, packages=names, reinstall=self.reinstall)


class InstallNftables(InstallPackage):
    packages = {manager.manager: ["nftables"] for manager in MANAGERS}


class InstallAuditd(InstallPackage):
    packages = {"apt": ["auditd"], "dnf": ["audit"], "zypper": ["audit"],
                "pacman": ["audit"], "apk": ["audit"]}


class InstallPam(InstallPackage):
    """The distribution's PAM modules. `InstallPam(reinstall=True)` restores tampered ones."""
    packages = {"apt": ["libpam-modules", "libpam-modules-bin", "libpam-runtime"],
                "dnf": ["pam"], "zypper": ["pam"]}
