"""The declared service list (inventory `services:`) and what the host is actually exposing.

inventory.yml, per host or group:
    services:
      - {port: 22, proto: tcp, name: sshd}
"""

NOT_DECLARED = "no services declared in inventory; run ccdcctl services"


def declared(variables):
    """[(proto, port, name)] from hostvars, or None when no `services` key exists at all.

    An empty list is a valid declaration ("nothing is approved"); a malformed one raises.
    """
    if "services" not in variables or variables["services"] is None:
        return None
    items = variables["services"]
    if not isinstance(items, list):
        raise ValueError("inventory `services` must be a list of {port, proto, name}")
    result = []
    for item in items:
        if not isinstance(item, dict):
            raise ValueError(f"inventory service entry is not a mapping: {item!r}")
        port, proto = item.get("port"), str(item.get("proto", "")).lower()
        if type(port) is not int or not 1 <= port <= 65535 or proto not in ("tcp", "udp"):
            raise ValueError(f"inventory service needs an integer port and proto tcp|udp: {item!r}")
        result.append((proto, port, str(item.get("name") or "unknown")))
    return sorted(set(result))


def exposed(rows):
    """{(proto, port): {name, process, addresses}} for non-loopback listeners (IPv4/IPv6 merged)."""
    found = {}
    for row in rows:
        if not row.get("external"):
            continue
        key = (row["protocol"], row["port"])
        entry = found.setdefault(key, {"name": None, "process": None, "addresses": []})
        entry["name"] = entry["name"] or row.get("service") or row.get("process")
        entry["process"] = entry["process"] or row.get("process")
        if row["address"] not in entry["addresses"]:
            entry["addresses"].append(row["address"])
    return found


def policy_ports(services):
    """({tcp ports}, {udp ports}) of a declared list, always including tcp/22 (the host refuses without it)."""
    tcp = {port for proto, port, _ in services if proto == "tcp"} | {22}
    udp = {port for proto, port, _ in services if proto == "udp"}
    return sorted(tcp), sorted(udp)
