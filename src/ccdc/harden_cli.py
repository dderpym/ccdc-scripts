"""`ccdcctl harden [HOST] [--allow UNIT ...]`: show -> confirm -> apply per host."""
from scripts.harden.full import Harden
from scripts.harden.services import UNNEEDED_SERVICES
from ccdc.target import Target


def harden(hosts, allow=(), assume_yes=False, ask=input, out=print):
    failed = False
    for host in hosts:
        out(f"{host}: sshd drop-in (MaxAuthTries 3, no forwarding, ...) and disable "
            + ", ".join(s for s in UNNEEDED_SERVICES if s not in allow))
        if not assume_yes and ask(f"Harden {host}? [y/N] > ").strip().lower() != "y":
            continue
        try:
            Harden(allow=allow).run(target=Target(host))
            out(f"{host}: hardened")
        except Exception as exc:
            failed = True
            out(f"{host}: FAILED: {exc}")
    return failed
