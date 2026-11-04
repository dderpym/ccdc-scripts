"""Persistence paths watched by auditd: (path, key)."""
WATCHES = (
    ("/etc/pam.d", "ccdc-pam"),
    ("/etc/ssh", "ccdc-ssh"),
    ("/etc/sudoers", "ccdc-sudo"),
    ("/etc/sudoers.d", "ccdc-sudo"),
    ("/etc/systemd/system", "ccdc-systemd"),
    ("/usr/lib/systemd/system", "ccdc-systemd"),
    ("/etc/ld.so.preload", "ccdc-preload"),
)


def rules_text():
    return "# Managed by CCDC: who/when/pid for writes to persistence paths\n" + "".join(
        f"-w {path} -p wa -k {key}\n" for path, key in WATCHES)


def missing_watches(listing):
    """Watched paths absent from `auditctl -l` output."""
    return [path for path, key in WATCHES
            if not any(line.startswith(f"-w {path} ") and f"-k {key}" in line for line in listing.splitlines())]
