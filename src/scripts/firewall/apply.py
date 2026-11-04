"""Firewall phase: apply the approved inbound policy, or restore the saved snapshot."""
import json

from ccdc.ansible import BundleScript


class ApplyFirewall(BundleScript):
    """run(target, tcp, udp): approved port lists. Returns success."""
    entry = "discover_firewall"
    live = True
    connection = True

    def arguments(self, tcp, udp, **kwargs):
        return ["--apply", json.dumps({"tcp": tcp, "udp": udp})]


class RestoreFirewall(BundleScript):
    """run(target, payload=snapshot file). Returns success."""
    entry = "discover_firewall"
    live = True
    connection = True

    def arguments(self, **kwargs):
        return ["--restore", "-"]
