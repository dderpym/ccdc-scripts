"""Firewall phase: find what a host exposes, let a human approve it, record it in inventory.yml."""
from ccdc.ansible import EntryScript
from ccdc.inventory_edit import INVENTORY, set_services
from ccdc.script import HostScript
from ccdc.services import declared, exposed


class DiscoverServices(EntryScript):
    """Non-loopback listeners (ss -tulpn as root, via discover_listeners) as {(proto, port): info}."""
    entry = "discover_listeners"

    def parse(self, document, **kwargs):
        return exposed(document)


class ApproveServices(HostScript):
    """run(target, ask=input, out=print, inventory=INVENTORY): review each unapproved listener.

    Approved services are written back to inventory.yml under the host as
    `services: [{port, proto, name}]`; approved ones that no longer listen are offered for removal.
    Returns the final list. Nothing is written when nothing changed.
    """

    def __init__(self, runner=None):
        self.discover = DiscoverServices(runner)

    def run(self, target, ask=input, out=print, inventory=INVENTORY):
        live = self.discover.run(target)
        current = declared(target.vars) or []
        approved = {(proto, port): name for proto, port, name in current}
        out(f"\n{target}: {len(live)} non-loopback service(s), {len(approved)} approved in inventory")
        everything = False
        for (proto, port), info in sorted(live.items(), key=lambda item: (item[0][1], item[0][0])):
            if (proto, port) in approved:
                continue
            name = info["name"] or info["process"] or "unknown"
            line = f"  {proto}/{port}  {name}  (process {info['process'] or 'unknown'}; bound {', '.join(info['addresses'])})"
            if everything:
                answer = "y"
            else:
                answer = self._ask(ask, line + "\n  approve? [y]es / [N]o / [a]ll remaining / [q]uit")
            if answer == "q":
                break
            if answer == "a":
                everything, answer = True, "y"
            if answer == "y":
                approved[(proto, port)] = name
        for (proto, port), name in sorted(approved.items()):
            if (proto, port) in live:
                continue
            if self._ask(ask, f"  approved {name} ({proto}/{port}) is NOT listening; remove it from the inventory? [y/N]") == "y":
                del approved[(proto, port)]
        result = [{"port": port, "proto": proto, "name": name} for (proto, port), name in sorted(approved.items())]
        if sorted(current) != sorted((proto, port, name) for (proto, port), name in approved.items()):
            changed = set_services(target.host, result, inventory)
            out(f"{target}: inventory.yml updated" if changed else f"{target}: inventory unchanged")
        else:
            out(f"{target}: no change")
        return result

    @staticmethod
    def _ask(ask, prompt):
        while True:
            answer = ask(prompt + " > ").strip().lower() or "n"
            if answer[0] in "ynaq":
                return answer[0]
