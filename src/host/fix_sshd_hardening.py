#!/usr/bin/env python3
"""fix_sshd_hardening apply|confirm|revert: harden sshd with a self-reverting safety net.

apply   writes sshd_config.d/00-hardening.conf (first value wins, so it beats
        distro drop-ins), validates with `sshd -t`, reloads, and starts a detached
        watchdog that reverts unless `confirm` runs within the timeout.
confirm cancels the watchdog (run only after a fresh key login worked).
revert  removes the drop-in and reloads.
Prints one JSON object.
"""
import json
import os
import re
import shutil
import subprocess
import sys

DROPIN_DIR = "/etc/ssh/sshd_config.d"
DROPIN = DROPIN_DIR + "/00-hardening.conf"
MAIN = "/etc/ssh/sshd_config"
TIMEOUT = 90
OPTIONS = (
    ("MaxAuthTries", "3"), ("LoginGraceTime", "30"), ("X11Forwarding", "no"),
    ("AllowAgentForwarding", "no"), ("AllowTcpForwarding", "no"),
    ("PermitEmptyPasswords", "no"), ("PermitUserEnvironment", "no"),
    ("ClientAliveInterval", "300"), ("ClientAliveCountMax", "2"),
)


def render(options=OPTIONS):
    return "# Managed by CCDC: sshd hardening\n" + "".join(f"{k} {v}\n" for k, v in options)


def includes_dropins(main_text):
    """The drop-in only works if the main file includes sshd_config.d."""
    return bool(re.search(r"^\s*Include\s+.*sshd_config\.d/", main_text, re.M | re.I))


def sshd_binary():
    return shutil.which("sshd") or next((p for p in ("/usr/sbin/sshd", "/usr/local/sbin/sshd") if os.path.exists(p)), None)


def reload_sshd():
    for unit in ("sshd", "ssh"):
        if subprocess.run(["systemctl", "reload", unit], stderr=subprocess.DEVNULL).returncode == 0:
            return True
    return False


def ok_flag():
    return DROPIN + ".ok"


def watchdog_command(timeout=TIMEOUT):
    return ("sleep %d; [ -f %s ] && { rm -f %s; exit 0; }; rm -f %s; "
            "systemctl reload sshd 2>/dev/null || systemctl reload ssh" % (timeout, ok_flag(), ok_flag(), DROPIN))


def _restore(previous):
    if previous is None:
        if os.path.exists(DROPIN):
            os.unlink(DROPIN)
    else:
        with open(DROPIN, "w") as handle:
            handle.write(previous)


def apply():
    sshd = sshd_binary()
    if not sshd:
        raise RuntimeError("sshd not found")
    with open(MAIN) as handle:
        if not includes_dropins(handle.read()):
            raise RuntimeError("sshd_config has no Include of sshd_config.d; refusing to guess")
    previous = None
    if os.path.exists(DROPIN):
        with open(DROPIN) as handle:
            previous = handle.read()
    os.makedirs(DROPIN_DIR, exist_ok=True)
    with open(DROPIN, "w") as handle:
        handle.write(render())
    os.chmod(DROPIN, 0o644)
    if subprocess.run([sshd, "-t"], stderr=subprocess.PIPE, text=True).returncode:
        _restore(previous)
        raise RuntimeError("sshd -t rejected the hardened configuration; reverted")
    if os.path.exists(ok_flag()):
        os.unlink(ok_flag())
    if not reload_sshd():
        _restore(previous)
        raise RuntimeError("could not reload sshd; reverted")
    subprocess.Popen(["sh", "-c", watchdog_command()], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True)
    return {"applied": True, "watchdog_seconds": TIMEOUT}


def confirm():
    with open(ok_flag(), "w"):
        pass
    return {"confirmed": True}


def revert():
    _restore(None)
    return {"reverted": reload_sshd()}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    actions = {"apply": apply, "confirm": confirm, "revert": revert}
    if len(argv) != 1 or argv[0] not in actions:
        print("usage: fix_sshd_hardening apply|confirm|revert", file=sys.stderr)
        return 2
    try:
        print(json.dumps(actions[argv[0]]()))
    except (OSError, RuntimeError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
