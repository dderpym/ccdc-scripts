from ccdc.ansible import BundleScript


class SetPermissions(BundleScript):
    """Clear mode bits (octal string), set an exact mode/owner, optionally chown to root:root."""
    entry = "fix_permissions"

    def arguments(self, path, clear="0", root=False, mode=None, uid=None, gid=None, **kwargs):
        extra = [] if mode is None else ["--mode", mode]
        extra += [] if uid is None else ["--uid", str(uid)]
        extra += [] if gid is None else ["--gid", str(gid)]
        return [path, "--clear", clear, *extra, *(["--root"] if root else [])]


class DisableSysctls(BundleScript):
    """Set allow-listed sysctls to 0, live and persisted."""
    entry = "fix_sysctl"

    def arguments(self, names=(), **kwargs):
        return list(names)
