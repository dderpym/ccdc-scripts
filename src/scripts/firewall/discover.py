"""Read-only discovery of what a host exposes. Each class runs the script beside this module on the target.

DiscoverSSH is an internal helper: the firewall paths read sshd's listening ports from it so
SSH is never locked out. SSH policy itself is a scanner (ccdc.scanners.ssh_vectors).
"""
from ccdc.ansible import AnsibleScript
from ccdc.runner import RemoteError, failure_message


class Discovery(AnsibleScript):
    """Prints one JSON document; a failure is reported with the script's own {"error": ...} text."""

    def parse(self, result, **kwargs):
        if result["rc"] != 0:
            raise RemoteError("%s: %s" % (self.name, failure_message(result)))
        return super().parse(result, **kwargs)


class DiscoverListeners(Discovery):
    """TCP listeners and unconnected UDP bindings with process attribution (ss/netstat/lsof//proc, as root)."""
    source = "discover_listeners.py"
    support = ("procinfo.py",)


class DiscoverFirewall(Discovery):
    """The effective firewall policy. snapshot=True prints the full pre-change snapshot instead."""
    source = "discover_firewall.py"

    def arguments(self, snapshot=False, **kwargs):
        return ["--snapshot"] if snapshot else []


class DiscoverSSH(Discovery):
    """sshd's effective settings (sshd -T); `context` is sshd -C syntax."""
    source = "discover_ssh.py"

    def arguments(self, context=None, **kwargs):
        return ["--context", context] if context else []
