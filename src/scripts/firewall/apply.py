"""Firewall phase: apply the approved inbound policy, or restore the saved snapshot.

Both run discover_firewall.py (beside this module) in its mutating modes, with the progress UI.
"""
import json

from ccdc.ansible import AnsibleScript


class ApplyFirewall(AnsibleScript):
    """run(target, tcp, udp): approved port lists. Returns success."""
    source = "discover_firewall.py"
    live = True
    connection = True  # the login running this must stay reachable: its server port has to be approved

    def arguments(self, tcp, udp, **kwargs):
        return ["--apply", json.dumps({"tcp": tcp, "udp": udp})]


class RestoreFirewall(AnsibleScript):
    """run(target, payload=snapshot file). Returns success."""
    source = "discover_firewall.py"
    live = True
    connection = True
    stdin = True  # the snapshot file arrives as standard input

    def arguments(self, **kwargs):
        return ["--restore", "-"]
