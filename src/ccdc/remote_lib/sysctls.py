"""Allow-listed sysctls the fixes may turn off: set live and persisted in our own drop-in."""
import os


SYSCTLS = {"kernel.unprivileged_userns_clone", "user.max_user_namespaces"}
SYSCTL_DROPIN = "/etc/sysctl.d/99-ccdc-userns.conf"


def apply_sysctl(fix, dropin=SYSCTL_DROPIN, proc="/proc/sys"):
    settings = fix["settings"]
    if not isinstance(settings, dict) or not settings or any(
            name not in SYSCTLS or value != "0" for name, value in settings.items()):
        raise ValueError("invalid sysctl fix")
    for name in sorted(settings):
        with open(os.path.join(proc, *name.split(".")), "w") as handle:
            handle.write("0\n")
    # Keep earlier entries of our own drop-in; replace atomically.
    try:
        with open(dropin) as handle:
            known = dict(line.strip().split(" = ", 1) for line in handle if " = " in line)
    except FileNotFoundError:
        known = {}
    known = {name: value for name, value in {**known, **settings}.items() if name in SYSCTLS}
    os.makedirs(os.path.dirname(dropin), mode=0o755, exist_ok=True)
    temporary = dropin + ".tmp"
    with open(temporary, "w") as handle:
        handle.write("# Managed by CCDC: disable unprivileged user namespaces\n"
                     + "".join("%s = %s\n" % item for item in sorted(known.items())))
    os.chmod(temporary, 0o644)
    os.replace(temporary, dropin)
