#!/usr/bin/env python3
"""Runtime-only firewall operations (root, Python 3 stdlib).

No args: deterministic effective state; --snapshot: separate restorable JSON.
--apply '{"tcp":[22],"udp":[]}': enforce and verify, restoring on failure.
--restore FILE: restore the controller's snapshot (FILE - reads stdin), never stop a manager.

State keys: backend (nftables/iptables/none/mixed/ambiguous), rules (complete
normalized rules plus active manager names), default_inbound (accept/drop/null),
allowed_tcp/allowed_udp (unconditional new-connection ports, or null if unknown
or unrestricted), source_rules (source-conditional rules), ssh22 (bool/null).
Unknown is deliberate: arbitrary firewall programs cannot be summarized safely.
For our owned policy these fields are exact for both IP families; established
flows, loopback and IPv6 ICMP are exceptions to the inbound default.

nft replaces the ENTIRE ruleset in one transaction. Nontrivial non-input hooks
(including NAT, forwarding and output) are refused; see the Ansible notice.
iptables changes filter/INPUT only, preserving NAT, forwarding and output.
Extra INPUT/PREROUTING programs outside filter are refused: their effect on
approved ports cannot be proven (ordinary POSTROUTING NAT is supported).
Apply commits one atomic filter transaction per IP family, not both together.
Full legacy rollback commits per table; a failure attempts BOTH family restores.
Neither backend installs boot persistence.
"""
import argparse
import copy
import json
import os
import re
import shlex
import shutil
import subprocess
import sys

CHAIN = "CCDC_INPUT"
ICMP6_TYPES = (133, 134, 135, 136)  # Router/neighbor discovery; not echo requests.
ICMP6_NAMES = ('nd-router-solicit', 'nd-router-advert', 'nd-neighbor-solicit', 'nd-neighbor-advert')


class Refusal(Exception):
    pass


def run(argv, data=None, check=True):
    try:
        result = subprocess.run(argv, input=data, universal_newlines=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Refusal("Cannot run %s: %s" % (argv[0], exc)) from exc
    if check and result.returncode:
        raise Refusal("%s failed: %s" % (" ".join(argv), result.stderr.strip()))
    return result


def clean(value, parent=None):
    """Remove dynamic metadata; sort sets, never rules/expressions/tuples."""
    if isinstance(value, dict):
        dynamic = {"handle", "expires", "metainfo"}
        if parent == "counter":
            dynamic.update(("packets", "bytes"))
        if parent == "quota":
            dynamic.update(("used", "used_unit"))
        return {k: clean(v, k) for k, v in value.items() if k not in dynamic}
    if isinstance(value, list):
        values = [clean(v) for v in value]
        if parent in ("elem", "set", "flags"):
            values.sort(key=lambda v: json.dumps(v, sort_keys=True))
        return values
    return value


def normalize_nft(document):
    entries = [clean(e) for e in document.get("nftables", []) if "metainfo" not in e]
    # Stable sorting groups objects/chains, while retaining rule order per chain.
    def key(entry):
        kind, obj = next(iter(entry.items()))
        return (obj.get("family", ""), obj.get("table", obj.get("name", "")),
                kind, obj.get("chain", obj.get("name", "")))
    return sorted(entries, key=key)


def parse_save(text):
    tables = {}
    current = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            current = {"chains": {}, "rules": []}
            tables[line[1:]] = current
        elif line == "COMMIT":
            current = None
        elif current is not None and line.startswith(":"):
            name, policy, _ = line[1:].split()
            current["chains"][name] = policy
        elif current is not None:
            tokens = shlex.split(line)
            # We invoke save without -c, so only chain headers have counters.
            # Do not mistake literal option names inside --comment for options.
            for index in range(2, len(tokens) - 1):
                if tokens[index] == "--ctstate" and tokens[index - 1] != "--comment":
                    tokens[index + 1] = ",".join(sorted(tokens[index + 1].split(",")))
            current["rules"].append(tokens)
        else:
            raise Refusal("Unexpected iptables-save line: " + line)
    return tables


def active_tables(tables):
    return any(table["rules"] or any(p not in ("ACCEPT", "-")
                                    for p in table["chains"].values())
               for table in tables.values())


def active_nft(entries):
    return any("rule" in e or "set" in e or "map" in e or "flowtable" in e or
               e.get("chain", {}).get("policy", "accept") != "accept" for e in entries)


def implementation(binary):
    output = run([binary, "--version"]).stdout
    if "nf_tables" in output:
        return "nf_tables"
    if "legacy" in output:
        return "legacy"
    raise Refusal("Unknown iptables implementation: " + output.strip())


def manager_names(entries, saves):
    managers = set()
    namespace = os.stat('/proc/self/ns/net').st_ino
    try:
        host_namespace = namespace == os.stat('/proc/1/ns/net').st_ino
    except OSError:
        host_namespace = False
    # A namespace-local test/container must not query a parent's system bus/config.
    if host_namespace and shutil.which("systemctl") and os.path.isdir('/run/systemd/system'):
        for name in ("firewalld", "ufw"):
            result = run(["systemctl", "is-active", name], check=False)
            if result.stdout.strip() in ("active", "activating", "reloading"):
                managers.add(name)
    # Works with non-systemd hosts, and catches ufw's persistent kernel rules.
    if host_namespace and shutil.which("ufw"):
        result = run(["ufw", "status"], check=False)
        if re.search(r"^Status:\s*active\s*$", result.stdout, re.M):
            managers.add("ufw")
        elif result.returncode:
            raise Refusal("Cannot determine ufw status: " + result.stderr.strip())
    for pid in os.listdir("/proc"):
        if pid.isdigit():
            try:
                with open("/proc/%s/comm" % pid) as handle:
                    name = handle.read().strip()
                if name in ("firewalld", "ufw") and os.stat('/proc/%s/ns/net' % pid).st_ino == namespace:
                    managers.add(name)
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                pass
    for entry in entries:
        obj = next(iter(entry.values()))
        name = obj.get("name", "")
        if name == "firewalld":
            managers.add("firewalld")
        if name.lower().startswith("ufw"):
            managers.add("ufw")
    for text in saves.values():
        if re.search(r"^:ufw(?:6)?[-_]", text, re.M):
            managers.add("ufw")
        if re.search(r"^:(?:IN|OUT|FWDI|FWDO)_.*(?:direct|allow|deny)", text, re.M):
            managers.add("firewalld")
    return sorted(managers)


def nft_is_compat(entries, saves):
    """Only regard nft tables as iptables if saves account for EVERY object."""
    hooks = {"PREROUTING": "prerouting", "INPUT": "input", "FORWARD": "forward",
             "OUTPUT": "output", "POSTROUTING": "postrouting"}
    priorities = {"filter": 0, "nat": None, "mangle": -150, "raw": -300, "security": 50}
    builtins = {"filter": {"INPUT", "FORWARD", "OUTPUT"},
                "nat": {"PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"},
                "mangle": set(hooks), "raw": {"PREROUTING", "OUTPUT"},
                "security": {"INPUT", "FORWARD", "OUTPUT"}}
    actual = {}
    for entry in entries:
        kind, obj = next(iter(entry.items()))
        family = obj.get("family")
        if family not in ("ip", "ip6") or kind not in ("table", "chain", "rule"):
            return False
        table = obj.get("table", obj.get("name"))
        if table not in builtins:
            return False
        if kind == "table" and set(obj) != {"family", "name"}:
            return False  # e.g. dormant tables do not enforce their chains.
        if kind == "chain" and "hook" in obj:
            name = obj.get("name")
            priority = (-100 if name in ("PREROUTING", "OUTPUT") else 100) if table == "nat" else priorities[table]
            if (name not in builtins[table] or obj["hook"] != hooks[name] or
                    obj.get("type") != ("nat" if table == "nat" else "filter") or
                    obj.get("prio") != priority):
                return False
        key = (family, table)
        item = actual.setdefault(key, {"chains": {}, "counts": {}})
        if kind == "chain":
            item["chains"][obj["name"]] = obj.get("policy", "-").upper()
        if kind == "rule":
            chain = obj["chain"]
            item["counts"][chain] = item["counts"].get(chain, 0) + 1
    expected = {}
    for family, tables in saves.items():
        for table, data in tables.items():
            counts = {}
            for rule in data["rules"]:
                if rule[:1] != ["-A"]:
                    return False
                counts[rule[1]] = counts.get(rule[1], 0) + 1
            if table not in builtins:
                return False
            # iptables-nft-save invents empty ACCEPT builtin chains which nft
            # need not have materialized. No other missing object is acceptable.
            present = actual.get((family, table), {}).get("chains", {})
            chains = {name: policy for name, policy in data["chains"].items()
                      if name in present or name not in builtins[table] or
                      policy != "ACCEPT" or counts.get(name)}
            if chains or counts or (family, table) in actual:
                expected[(family, table)] = {"chains": chains, "counts": counts}
    return actual == expected


def collect():
    info = {"nft": [], "saves": {}, "tables": {}, "impl": {}, "extra_legacy": {},
            "uninspected_legacy": []}
    if shutil.which("nft"):
        info["nft"] = normalize_nft(json.loads(run(["nft", "-j", "list", "ruleset"]).stdout))
    for family, prefix in (("ip", "iptables"), ("ip6", "ip6tables")):
        if shutil.which(prefix) and shutil.which(prefix + "-save"):
            info["impl"][family] = implementation(prefix)
            info["saves"][family] = run([prefix + "-save"]).stdout
            info["tables"][family] = parse_save(info["saves"][family])
        if info["impl"].get(family) != "legacy":
            if shutil.which(prefix + "-legacy-save"):
                info["extra_legacy"][family] = run([prefix + "-legacy-save"]).stdout
            else:
                # Legacy tables are invisible to nft. Never assume that missing
                # legacy tools mean a missing legacy firewall.
                try:
                    with open("/proc/net/%s_tables_names" % ("ip" if family == "ip" else "ip6")) as handle:
                        if handle.read().strip():
                            info["uninspected_legacy"].append(family)
                except FileNotFoundError:
                    pass
    info["managers"] = manager_names(info["nft"], {**info["saves"], **{
        "legacy_" + k: v for k, v in info["extra_legacy"].items()}})
    info["backend"] = choose_backend(info)
    return info


def choose_backend(info):
    if info.get("uninspected_legacy"):
        return "ambiguous"
    nft_active = active_nft(info["nft"])
    legacy_active = any(active_tables(parse_save(text))
                        for text in info["extra_legacy"].values()) or any(
        active_tables(tables) and info["impl"].get(family) == "legacy"
        for family, tables in info["tables"].items())
    compat_saves = {f: t for f, t in info["tables"].items()
                    if info["impl"].get(f) == "nf_tables"}
    compat_active = any(active_tables(t) for t in compat_saves.values())
    compat = nft_is_compat(info["nft"], compat_saves)
    if legacy_active and nft_active:
        return "mixed"
    if nft_active and compat_active and not compat:
        return "mixed"
    if legacy_active:
        return "iptables"
    if nft_active:
        if compat_active and compat:
            return "iptables"
        return "nftables"
    if compat_active:  # nft view is missing or disagrees with iptables' view.
        return "ambiguous"
    if shutil.which("nft"):
        return "nftables"
    if info["impl"]:
        return "iptables"
    return "none"


def nft_descriptor(rule):
    expressions = rule.get("expr", [])
    if len(expressions) != 2 or expressions[-1] != {"accept": None}:
        return None
    match = expressions[0].get("match", {})
    if match.get("op") not in ("==", "in"):
        return None
    left, right = match.get("left"), match.get("right")
    if left == {"meta": {"key": "iifname"}} and right == "lo":
        return "loopback"
    if left == {"ct": {"key": "state"}}:
        states = right.get("set", []) if isinstance(right, dict) else right
        if isinstance(states, list) and sorted(states) == ["established", "related"]:
            return "established"
    if left == {'payload': {'protocol': 'icmpv6', 'field': 'type'}} and isinstance(right, dict):
        types = right.get('set', [])
        if sorted(types, key=str) in (sorted(ICMP6_TYPES, key=str), sorted(ICMP6_NAMES)):
            return "icmp6"
    if isinstance(left, dict) and "payload" in left:
        payload = left["payload"]
        if payload.get("field") == "dport" and payload.get("protocol") in ("tcp", "udp"):
            if type(right) is int and 1 <= right <= 65535:
                return (payload["protocol"], right)
    return None


def nft_owned(entries):
    tables = [e["table"] for e in entries if "table" in e]
    chains = [e["chain"] for e in entries if "chain" in e]
    if len(tables) != 1 or len(chains) != 1:
        return None
    table, chain = tables[0], chains[0]
    if table != {"family": "inet", "name": "ccdc"}:
        return None
    expected = {"family": "inet", "table": "ccdc", "name": "input", "type": "filter",
                "hook": "input", "prio": 0, "policy": "drop"}
    if chain != expected or any(next(iter(e)) not in ("table", "chain", "rule") for e in entries):
        return None
    rules = [e["rule"] for e in entries if "rule" in e]
    if any((r.get("family"), r.get("table"), r.get("chain")) !=
           ("inet", "ccdc", "input") for r in rules):
        return None
    descriptors = [nft_descriptor(r) for r in rules]
    if descriptors[:3] != ["loopback", "established", "icmp6"]:
        return None
    ports = {"tcp": [], "udp": []}
    for descriptor in descriptors[3:]:
        if not isinstance(descriptor, tuple):
            return None
        ports[descriptor[0]].append(descriptor[1])
    if descriptors[3:] != [(p, n) for p in ("tcp", "udp") for n in sorted(set(ports[p]))]:
        return None
    return ports


def owned_rules(ports, ipv6=False):
    rules = [["-A", CHAIN, "-i", "lo", "-j", "ACCEPT"],
             ["-A", CHAIN, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]]
    if ipv6:
        rules.extend(['-A', CHAIN, '-p', 'ipv6-icmp', '-m', 'icmp6', '--icmpv6-type', str(kind), '-j', 'ACCEPT']
                     for kind in ICMP6_TYPES)
    for protocol in ("tcp", "udp"):
        for port in ports[protocol]:
            rules.append(["-A", CHAIN, "-p", protocol, "-m", protocol,
                          "--dport", str(port), "-j", "ACCEPT"])
    return rules + [["-A", CHAIN, "-j", "DROP"]]


def iptables_ingress_clear(tables):
    # Other hooks can drop or rewrite a port before/after filter/INPUT; a FIRST
    # jump alone cannot prove that an approved port is actually permitted.
    for name, table in tables.items():
        if name == "filter":
            continue
        for chain in ("PREROUTING", "INPUT"):
            if table["chains"].get(chain, "ACCEPT") != "ACCEPT":
                return False
            if any(r[:2] == ["-A", chain] for r in table["rules"]):
                return False
    return True


def iptables_owned(tables, ipv6=False):
    if not iptables_ingress_clear(tables):
        return None
    table = tables.get("filter", {})
    rules = table.get("rules", [])
    inbound = [r for r in rules if r[:2] == ["-A", "INPUT"]]
    if not inbound or inbound[0] != ["-A", "INPUT", "-j", CHAIN]:
        return None
    own = [r for r in rules if r[:2] == ["-A", CHAIN]]
    # Only accept the exact installed program, not a heuristic port summary.
    ports = {"tcp": [], "udp": []}
    for rule in own:
        if len(rule) == 10 and rule[2] == "-p" and rule[3] in ports and rule[6] == "--dport":
            try:
                ports[rule[3]].append(int(rule[7]))
            except ValueError:
                return None
    if any(ports[p] != sorted(set(ports[p])) or any(not 1 <= n <= 65535 for n in ports[p])
           for p in ports):
        return None
    if own != owned_rules(ports, ipv6):
        return None
    return ports


def source_rules(info):
    found = []
    for entry in info["nft"]:
        if "rule" in entry:
            text = json.dumps(entry, sort_keys=True)
            if '"saddr"' in text or '"iif' in text:
                found.append(entry)
    for family, tables in sorted(info["tables"].items()):
        for table, data in sorted(tables.items()):
            for rule in data["rules"]:
                if any(t in rule for t in ("-s", "--source", "--src-range", "--match-set")):
                    found.append({"family": family, "table": table, "rule": rule})
    return found


def inbound_hints(info):
    """Literal ACCEPTs in input-reachable chains, not proof of reachability.

    Preserve conditions and base policies instead of interpreting arbitrary rules.
    """
    policies, accepts = [], []
    for family, tables in sorted(info['tables'].items()):
        for table, data in sorted(tables.items()):
            if 'INPUT' not in data['chains']:
                continue
            policies.append(dict(family=family, table=table, chain='INPUT', policy=data['chains']['INPUT'].lower()))
            reachable = {'INPUT'}
            while True:
                before = set(reachable)
                for rule in data['rules']:
                    if rule[:1] == ['-A'] and rule[1] in reachable:
                        for flag in ('-j', '-g', '--jump', '--goto'):
                            if flag in rule and rule[rule.index(flag) + 1] in data['chains']:
                                reachable.add(rule[rule.index(flag) + 1])
                if before == reachable:
                    break
            for rule in data['rules']:
                if rule[:1] != ['-A'] or rule[1] not in reachable or '-p' not in rule:
                    continue
                if not any(flag in rule and rule[rule.index(flag) + 1] == 'ACCEPT' for flag in ('-j', '--jump')):
                    continue
                protocol = rule[rule.index('-p') + 1]
                for flag in ('--dport', '--destination-port', '--dports'):
                    if protocol in ('tcp', 'udp') and flag in rule:
                        accepts.append(dict(family=family, protocol=protocol,
                                            ports=rule[rule.index(flag) + 1].split(','), rule=rule))
    reachable = set()
    for entry in info['nft']:
        chain = entry.get('chain', {})
        if chain.get('hook') == 'input':
            reachable.add((chain['family'], chain['table'], chain['name']))
            policies.append(dict(family=chain['family'], table=chain['table'], chain=chain['name'], policy=chain.get('policy')))
    rules = [e['rule'] for e in info['nft'] if 'rule' in e]
    while True:
        before = set(reachable)
        for rule in rules:
            if (rule['family'], rule['table'], rule['chain']) in reachable:
                for expression in rule.get('expr', []):
                    target = expression.get('jump', expression.get('goto', {})).get('target')
                    if target:
                        reachable.add((rule['family'], rule['table'], target))
        if before == reachable:
            break
    for rule in rules:
        if (rule['family'], rule['table'], rule['chain']) not in reachable or {'accept': None} not in rule.get('expr', []):
            continue
        for expression in rule['expr']:
            match = expression.get('match', {})
            left = match.get('left', {})
            payload = left.get('payload', {}) if isinstance(left, dict) else {}
            if payload.get('protocol') not in ('tcp', 'udp') or payload.get('field') != 'dport' or match.get('op') not in ('==', 'in'):
                continue
            right = match.get('right')
            ports = right.get('set', [right]) if isinstance(right, dict) else [right]
            accepts.append(dict(family=rule['family'], protocol=payload['protocol'], ports=ports, rule=rule))
    return policies, accepts


def state(info):
    backend = info["backend"]
    ports = None
    if backend == "nftables":
        ports = nft_owned(info["nft"])
    elif backend == "iptables" and set(info["tables"]) == {"ip", "ip6"}:
        v4 = iptables_owned(info["tables"]["ip"])
        v6 = iptables_owned(info["tables"]["ip6"], True)
        if v4 is not None and v4 == v6:
            ports = v4
    default, ssh = None, None
    if ports is not None and not info["managers"]:
        default, ssh = "drop", 22 in ports["tcp"]
    else:
        ports = None
        if backend == "nftables":
            chains = [e["chain"] for e in info["nft"] if "chain" in e
                      and e["chain"].get("hook") == "input"]
            policies = {c.get("policy") for c in chains}
            if policies == {"drop"}:
                default = "drop"
            elif not active_nft(info["nft"]):
                default, ssh = "accept", True
        elif backend == "iptables" and len(info["tables"]) == 2:
            policies = {t.get("filter", {}).get("chains", {}).get("INPUT", "ACCEPT")
                        for t in info["tables"].values()}
            if policies == {"DROP"}:
                default = "drop"
            elif not any(active_tables(t) for t in info["tables"].values()):
                default, ssh = "accept", True
    rules = {"nftables": info["nft"], "iptables": info["tables"],
             "legacy": {k: parse_save(v) for k, v in info["extra_legacy"].items()},
             "managers": info["managers"],
             "uninspected_legacy": info.get("uninspected_legacy", [])}
    policies, accepts = inbound_hints(info)
    return {"backend": backend, "rules": rules, "default_inbound": default,
            "allowed_tcp": ports["tcp"] if ports else None,
            "allowed_udp": ports["udp"] if ports else None,
            "input_policies": policies, "explicit_inbound_accepts": accepts,
            "source_rules": [] if ports is not None else source_rules(info), "ssh22": ssh}


def guard(info):
    if info["managers"]:
        raise Refusal("Active firewall manager(s): %s; no manager was stopped" %
                      ", ".join(info["managers"]))
    if info["backend"] not in ("nftables", "iptables"):
        raise Refusal("Refusing backend: " + info["backend"])
    if info["backend"] == "iptables":
        if set(info["impl"]) != {"ip", "ip6"} or len(set(info["impl"].values())) != 1:
            raise Refusal("Both IPv4 and IPv6 must use the same iptables implementation")
        for name in ("iptables-restore", "ip6tables-restore"):
            if not shutil.which(name):
                raise Refusal("Missing %s; refusing an IPv6 enforcement hole" % name)


def snapshot(info):
    guard(info)
    result = {"version": 1, "backend": info["backend"]}
    if info["backend"] == "nftables":
        result["nft_ruleset"] = run(["nft", "-s", "list", "ruleset"]).stdout
        # xt compatibility expressions (e.g. bridge/ebtables) may be printable
        # but not reloadable by nft. Prove the FULL snapshot is restorable
        # without committing any change, before permitting replacement.
        run(["nft", "--check", "-f", "-"], "flush ruleset\n" + result["nft_ruleset"])
    else:
        # Save output's chain counters and generated date comments aren't
        # needed for restoration (nor useful in a controller snapshot).
        for family, key in (("ip", "iptables_save"), ("ip6", "ip6tables_save")):
            text = "\n".join(line for line in info["saves"][family].splitlines()
                             if not line.startswith("#"))
            result[key] = re.sub(r"^(:\S+\s+\S+\s+)\[\d+:\d+\]$",
                                 r"\1[0:0]", text, flags=re.M) + "\n"
            # restore only flushes tables mentioned in its input. Apply can
            # create filter on a previously untouched family, so snapshot its
            # implicit ACCEPT defaults as well; an empty save is NOT a reset.
            if "filter" not in info["tables"][family]:
                result[key] += ("*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n"
                                ":OUTPUT ACCEPT [0:0]\nCOMMIT\n")
        result["implementation"] = info["impl"]
    return result


def restore(saved):
    if not isinstance(saved, dict) or type(saved.get("version")) is not int or saved["version"] != 1:
        raise Refusal("Unsupported snapshot format")
    info = collect()
    guard(info)
    backend = saved.get("backend")
    # Never load a snapshot while leaving a different active backend in place.
    if backend == "nftables":
        if info["backend"] != backend or not isinstance(saved.get("nft_ruleset"), str):
            raise Refusal("Snapshot/backend mismatch")
        run(["nft", "-f", "-"], "flush ruleset\n" + saved["nft_ruleset"])
    elif backend == "iptables":
        if info["backend"] != backend or saved.get("implementation") != info["impl"]:
            raise Refusal("Snapshot/iptables implementation mismatch")
        errors = []
        for prefix, key in (("iptables", "iptables_save"), ("ip6tables", "ip6tables_save")):
            if not isinstance(saved.get(key), str):
                raise Refusal("Incomplete dual-stack snapshot")
            parse_save(saved[key])  # Validate both before mutating either family.
        for prefix, key in (("iptables", "iptables_save"), ("ip6tables", "ip6tables_save")):
            try:
                family = "ip" if prefix == "iptables" else "ip6"
                data = saved[key]
                missing = set(info["tables"][family]) - set(parse_save(data))
                # Also reset tables which appeared after the snapshot, instead
                # of silently retaining new filtering or NAT on rollback.
                for table in sorted(missing):
                    data += "\n*" + table + "\n"
                    for chain, policy in sorted(info["tables"][family][table]["chains"].items()):
                        if policy != "-":
                            data += ":%s ACCEPT [0:0]\n" % chain
                    data += "COMMIT\n"
                run([prefix + "-restore", "--wait", "10"], data)
            except Refusal as exc:
                errors.append(str(exc))
        if errors:
            raise Refusal("; ".join(errors))
    else:
        raise Refusal("Unsupported snapshot backend")
    return state(collect())


def validate_ports(value):
    if not isinstance(value, dict) or set(value) != {"tcp", "udp"}:
        raise Refusal("Apply expects exactly tcp and udp arrays")
    ports = {}
    for protocol in ("tcp", "udp"):
        items = value[protocol]
        if not isinstance(items, list) or any(type(p) is not int or not 1 <= p <= 65535 for p in items):
            raise Refusal("Ports must be integer arrays in range 1..65535")
        ports[protocol] = sorted(set(items))
    if 22 not in ports["tcp"]:
        raise Refusal("TCP 22 is mandatory to guard the controller connection")
    return ports


def nft_program(ports):
    lines = ["flush ruleset", "table inet ccdc {", " chain input {",
             "  type filter hook input priority 0; policy drop;",
             '  iifname "lo" accept', "  ct state established,related accept",
             "  icmpv6 type { 133,134,135,136 } accept"]
    for protocol in ("tcp", "udp"):
        lines.extend("  %s dport %d accept" % (protocol, port) for port in ports[protocol])
    return "\n".join(lines + [" }", "}", ""])


def check_nft_replacement(entries):
    # Refuse any non-input base chain with meaningful work, even through jumps.
    for entry in entries:
        if "flowtable" in entry:
            raise Refusal("nft replacement would remove flow offload")
        chain = entry.get("chain", {})
        if "hook" not in chain or chain["hook"] == "input" and chain.get("type") == "filter":
            continue
        has_rules = any(e.get("rule", {}).get("family") == chain.get("family") and
                        e.get("rule", {}).get("table") == chain.get("table") and
                        e.get("rule", {}).get("chain") == chain.get("name") for e in entries)
        if chain.get("type") == "nat" or chain.get("policy", "accept") != "accept" or has_rules:
            raise Refusal("nft replacement refuses nontrivial %s/NAT/output/forward rules" % chain["hook"])


def iptables_program(tables, ports, ipv6=False):
    if not iptables_ingress_clear(tables):
        raise Refusal("Unmanaged non-filter INPUT/PREROUTING rules may block/rewrite approved ports")
    table = tables.get("filter", {"chains": {}, "rules": []})
    references = [r for r in table["rules"] if any(
        r[i] in ("-j", "--jump", "-g", "--goto") and r[i + 1] == CHAIN
        for i in range(len(r) - 1))]
    if any(r != ["-A", "INPUT", "-j", CHAIN] for r in references):
        raise Refusal("Owned chain is referenced outside the unconditional INPUT jump")
    if CHAIN in table["chains"] and iptables_owned(tables, ipv6) is None:
        raise Refusal("Existing %s chain is not our verified policy" % CHAIN)
    lines = ["*filter", ":%s - [0:0]" % CHAIN, "-F " + CHAIN]
    lines.extend("-D INPUT -j " + CHAIN for _ in references)
    lines.append("-I INPUT 1 -j " + CHAIN)
    lines.extend(" ".join(rule) for rule in owned_rules(ports, ipv6))
    return "\n".join(lines + ["COMMIT", ""])


def apply(ports):
    info = collect()
    guard(info)
    if info["backend"] == "nftables":
        check_nft_replacement(info["nft"])
        programs = [(["nft", "-f", "-"], nft_program(ports))]
    else:
        programs = [([prefix + "-restore", "--wait", "10", "--noflush"],
                     iptables_program(info["tables"][family], ports, family == "ip6"))
                    for family, prefix in (("ip", "iptables"), ("ip6", "ip6tables"))]
    saved = snapshot(info)
    try:
        for command, program in programs:
            run(command, program)
        result = state(collect())
        if (result["backend"] != info["backend"] or result["ssh22"] is not True or
                result["default_inbound"] != "drop" or
                result["allowed_tcp"] != ports["tcp"] or result["allowed_udp"] != ports["udp"]):
            raise Refusal("Post-apply verification did not confirm the exact dual-stack policy")
        return result
    except Exception as exc:
        try:
            restore(saved)
        except Exception as rollback:
            raise Refusal("Apply failed (%s); ROLLBACK FAILED (%s)" % (exc, rollback)) from exc
        raise Refusal("Apply failed (%s); previous snapshot restored" % exc) from exc


def self_test():
    ports = validate_ports({"tcp": [443, 22, 22], "udp": [53]})
    assert ports == {"tcp": [22, 443], "udp": [53]}
    for bad in ({"tcp": [True, 22], "udp": []}, {"tcp": [80], "udp": []},
                {"tcp": [22], "udp": [65536]}):
        try:
            validate_ports(bad)
        except Refusal:
            pass
        else:
            raise AssertionError("Accepted invalid ports")
    for ipv6 in (False, True):
        text = "*filter\n:INPUT ACCEPT [5:9]\n:%s - [1:3]\n-A INPUT -j %s\n%s\nCOMMIT\n" % (
            CHAIN, CHAIN, "\n".join(" ".join(r) for r in owned_rules(ports, ipv6)))
        tables = parse_save(text)
        assert iptables_owned(tables, ipv6) == ports
        assert parse_save(text.replace("[5:9]", "[10:20]")) == tables
        program = iptables_program(tables, ports, ipv6)
        assert "-D INPUT -j " + CHAIN in program and "-I INPUT 1 -j " + CHAIN in program
        tables["filter"]["rules"].insert(0, ["-A", "INPUT", "-j", "ACCEPT"])
        assert iptables_owned(tables, ipv6) is None
    a = {"nftables": [{"metainfo": {"version": "x"}}, {"rule": {
        "family": "inet", "table": "ccdc", "chain": "input", "handle": 12,
        "expr": [{"counter": {"packets": 12, "bytes": 50}}]}}]}
    b = copy.deepcopy(a)
    b["nftables"][1]["rule"]["handle"] = 99
    b["nftables"][1]["rule"]["expr"][0]["counter"]["packets"] = 100
    assert normalize_nft(a) == normalize_nft(b)
    assert clean({"quota": {"bytes": 1024, "used": 99}}) == {"quota": {"bytes": 1024}}
    assert clean({"set": [443, 22]}) == clean({"set": [22, 443]})
    assert clean({"expr": [1, 2]}) != clean({"expr": [2, 1]})
    # Golden shapes from nft -j: conntrack's RHS is an array, not a set object.
    matches = [({"meta": {"key": "iifname"}}, "lo", "=="),
               ({"ct": {"key": "state"}}, ["established", "related"], "in"),
               ({'payload': {'protocol': 'icmpv6', 'field': 'type'}}, {'set': list(ICMP6_NAMES)}, '==')]
    matches.extend(({"payload": {"protocol": p, "field": "dport"}}, n, "==")
                   for p in ("tcp", "udp") for n in ports[p])
    entries = [{"table": {"family": "inet", "name": "ccdc"}}, {"chain": {
        "family": "inet", "table": "ccdc", "name": "input", "type": "filter",
        "hook": "input", "prio": 0, "policy": "drop"}}]
    for left, right, op in matches:
        entries.append({"rule": {"family": "inet", "table": "ccdc", "chain": "input",
                                 "expr": [{"match": {"left": left, "right": right, "op": op}},
                                          {"accept": None}]}})
    assert nft_owned(entries) == ports
    changed = copy.deepcopy(entries)
    changed[-1]["rule"]["expr"].insert(0, {"drop": None})
    assert nft_owned(changed) is None
    # iptables-nft-save can synthesize absent ACCEPT chains. A mismatched base
    # hook/priority must still be refused, even if all rule counts match.
    compat = [{"table": {"family": "ip", "name": "filter"}}, {"chain": {
        "family": "ip", "table": "filter", "name": "INPUT", "hook": "input",
        "type": "filter", "prio": 0, "policy": "drop"}}]
    tables = {"ip": {"filter": {"chains": {"INPUT": "DROP", "FORWARD": "ACCEPT",
                                            "OUTPUT": "ACCEPT"}, "rules": []}}}
    assert nft_is_compat(compat, tables)
    changed = copy.deepcopy(compat)
    changed[1]["chain"]["hook"] = "output"
    assert not nft_is_compat(changed, tables)
    info = {"nft": entries + compat, "tables": tables, "impl": {"ip": "nf_tables"},
            "extra_legacy": {}}
    assert choose_backend(info) == "mixed"
    assert nft_program(ports).startswith("flush ruleset\ntable inet ccdc")
    try:
        check_nft_replacement([{"chain": {"hook": "forward", "policy": "drop"}}])
    except Refusal:
        pass
    else:
        raise AssertionError("Accepted unsafe forwarding replacement")
    # Failure in the second family must attempt BOTH full restores. No network
    # namespace or root is needed for this error-path regression check.
    from unittest.mock import patch
    raw = "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"
    baseline = {"backend": "iptables", "nft": [], "managers": [], "extra_legacy": {},
                "impl": {"ip": "legacy", "ip6": "legacy"},
                "saves": {"ip": raw, "ip6": raw},
                "tables": {"ip": parse_save(raw), "ip6": parse_save(raw)}}
    untouched_v6 = copy.deepcopy(baseline)
    untouched_v6["saves"]["ip6"] = ""
    untouched_v6["tables"]["ip6"] = {}
    with patch.object(shutil, "which", return_value="/mock"):
        assert "*filter" in snapshot(untouched_v6)["ip6tables_save"]
    commands = []
    def fail_ipv6(argv, data=None, check=True):
        commands.append(argv)
        if argv[0] == "ip6tables-restore" and "--noflush" in argv:
            raise Refusal("injected second-family failure")
        return subprocess.CompletedProcess(argv, 0, "", "")
    with patch.dict(globals(), collect=lambda: baseline, run=fail_ipv6), \
            patch.object(shutil, "which", return_value="/mock"):
        try:
            apply(ports)
        except Refusal as exc:
            assert "previous snapshot restored" in str(exc)
        else:
            raise AssertionError("Ignored second-family failure")
    assert [a[0] for a in commands] == ["iptables-restore", "ip6tables-restore",
                                      "iptables-restore", "ip6tables-restore"]
    assert all("--noflush" not in a for a in commands[-2:])
    with patch.object(shutil, "which", side_effect=lambda n: None if n == "ip6tables-restore" else "/mock"):
        try:
            guard(baseline)
        except Refusal:
            pass
        else:
            raise AssertionError("Accepted missing IPv6 restore")
    print("self-test passed")


def require_connection_port(ports):
    """The login that runs us must stay reachable: its server-side port has to be approved.

    The runner exports SSH_CONNECTION (client addr/port, server addr/port) for SSH
    logins and omits it for local connections; a present-but-unusable value refuses.
    """
    if "SSH_CONNECTION" not in os.environ:
        return
    parts = os.environ["SSH_CONNECTION"].split()
    if len(parts) != 4 or not parts[3].isdigit() or int(parts[3]) not in ports["tcp"]:
        raise Refusal("Approve the actual server-side SSH connection port before firewall application")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--snapshot", action="store_true")
    modes.add_argument("--apply", metavar="JSON")
    modes.add_argument("--restore", metavar="FILE")
    modes.add_argument("--self-test", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            return
        if os.geteuid() != 0:
            raise Refusal("Root is required, including discovery and snapshots")
        # Ensure manager status output is parseable independently of host locale.
        os.environ["LC_ALL"] = "C"
        if args.apply is not None:
            ports = validate_ports(json.loads(args.apply))
            require_connection_port(ports)
            result = apply(ports)
        elif args.restore:
            if args.restore == "-":
                result = restore(json.load(sys.stdin))
            else:
                with open(args.restore) as handle:
                    result = restore(json.load(handle))
        else:
            info = collect()
            result = snapshot(info) if args.snapshot else state(info)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    except (Refusal, ValueError, OSError) as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
