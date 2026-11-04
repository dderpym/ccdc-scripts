#!/usr/bin/env python3
"""Print a deterministic JSON list of TCP listeners and unconnected UDP bindings.

Run locally on each remote Linux host (preferably as root). Only stdlib is needed.
external means a non-loopback binding candidate, NOT firewall reachability.
PID is dynamic ownership metadata: exclude it from listener-state drift keys.
Missing metadata is null; service_confidence is high (cgroup), medium (runit
supervisor), low (live pidfile/ancestry), or unknown. Discovery covers the current
network/PID namespace; permission failures and process races reduce attribution.
"""
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys


def read(path):
    try:
        return Path(path).read_text(errors="replace")
    except OSError:
        return ""


def endpoint(text, family=None):
    address, port = text.rsplit(":", 1)
    address = address.strip("[]")
    if address == "*":
        address = "::" if family == "IPv6" else "0.0.0.0"
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    port = int(port)
    if not 0 < port <= 65535:
        raise ValueError("not a bound port")
    # Preserve IPv6 scope IDs, but normalize numeric spelling.
    scope = "%" + address.split("%", 1)[1] if "%" in address else ""
    return str(ip) + scope, port, "IPv%d" % ip.version


def row(protocol, local, family=None, pid=None, process=None, uid=None):
    address, port, family = endpoint(local, family)
    return dict(protocol=protocol, address=address, port=port, family=family,
                pid=pid, process=process, uid=uid)


def unconnected(peer):
    address, port = peer.rsplit(":", 1)
    address = address.strip("[]").split("%", 1)[0]
    return port in ("*", "0") and (address == "*" or ipaddress.ip_address(address).is_unspecified)


def parse_ss(text):
    result = []
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split(None, 6)
        if len(fields) < 6 or fields[0] not in ("tcp", "udp", "tcp6", "udp6"):
            raise ValueError("malformed ss output")
        proto = fields[0][:3]
        if proto == "tcp" and fields[1] != "LISTEN":
            continue
        if proto == "udp" and (fields[1] != "UNCONN" or not unconnected(fields[5])):
            continue
        # ss uses '*' for unspecified IPv6 on some versions, 0.0.0.0 for IPv4.
        family = "IPv6" if fields[0].endswith("6") or fields[4].startswith("*:") else None
        base = row(proto, fields[4], family)
        owners = re.findall(r'\("((?:[^"\\]|\\.)*)",pid=(\d+),', fields[6] if len(fields) > 6 else "")
        if owners:
            result.extend(dict(base, pid=int(pid), process=name) for name, pid in owners)
        else:
            result.append(base)
    return result


def parse_netstat(text):
    result = []
    for line in text.splitlines():
        fields = line.split()
        if not fields or line.startswith("Active ") or fields[0] == "Proto":
            continue
        if fields[0] not in ("tcp", "tcp6", "udp", "udp6") or len(fields) < 6:
            raise ValueError("malformed netstat output")
        proto = fields[0][:3]
        if proto == "tcp" and fields[5] != "LISTEN":
            continue
        if proto == "udp" and not unconnected(fields[4]):
            continue
        owner = fields[6] if proto == "tcp" and len(fields) > 6 else fields[5]
        match = re.match(r"^(\d+)/(.*)$", owner)
        result.append(row(proto, fields[3], "IPv6" if fields[0].endswith("6") else "IPv4",
                          int(match[1]) if match else None, match[2] if match else None))
    return result


def parse_lsof(text):
    result, process, sock = [], {}, {}

    def flush():
        if sock.get("t") not in ("IPv4", "IPv6"):
            return
        proto, name = sock.get("P", "").lower(), sock.get("n", "")
        if proto == "tcp" and sock.get("state") != "LISTEN":
            return
        if proto not in ("tcp", "udp") or not name or "->" in name:
            return
        result.append(row(proto, name, sock["t"], process.get("pid"),
                          process.get("c"), process.get("u")))

    for line in text.splitlines():
        if not line:
            continue
        key, value = line[0], line[1:]
        if key == "p":
            flush()
            process, sock = {"pid": int(value)}, {}
        elif key == "f":
            flush()
            sock = {}
        elif key in ("c", "u"):
            process[key] = value
        elif key in ("t", "P", "n"):
            sock[key] = value
        elif key == "T" and value.startswith("ST="):
            sock["state"] = value[3:]
        elif key not in ("a", "D", "i", "o", "s", "T"):
            raise ValueError("malformed lsof output")
    flush()
    if text.strip() and not process:
        raise ValueError("malformed lsof output")
    return result


def proc_address(hex_address):
    # /proc represents each 32-bit address word in host byte order.
    raw = b"".join(int(hex_address[i:i + 8], 16).to_bytes(4, sys.byteorder)
                   for i in range(0, len(hex_address), 8))
    return str(ipaddress.ip_address(raw))


def proc_listeners():
    result = []
    for table in ("tcp", "tcp6", "udp", "udp6"):
        for line in read("/proc/net/" + table).splitlines()[1:]:
            fields = line.split()
            try:
                if fields[3] != ("0A" if table.startswith("tcp") else "07"):
                    continue
                peer, peer_port = fields[2].split(":")
                if table.startswith("udp") and (int(peer, 16) or int(peer_port, 16)):
                    continue
                address, port = fields[1].split(":")
                item = row(table[:3], "%s:%d" % (proc_address(address), int(port, 16)),
                           uid=fields[7])
                item["inode"] = fields[9]
                result.append(item)
            except (IndexError, ValueError):
                continue  # A socket can disappear while proc is being read.
    return result


def process_info(pid):
    base = Path("/proc") / str(pid)
    stat = read(base / "stat")
    try:
        parent = int(stat.rsplit(")", 1)[1].split()[1])
    except (ValueError, IndexError):
        parent = 0
    status = read(base / "status")
    uid = re.search(r"^Uid:\s+(\d+)", status, re.M)
    try:
        exe = os.readlink(base / "exe")
    except OSError:
        exe = None
    units = [part for line in read(base / "cgroup").splitlines()
             for part in line.split(":", 2)[-1].split("/") if part.endswith(".service")]
    return dict(parent=parent, process=read(base / "comm").strip() or None,
                executable=exe, uid=uid[1] if uid else None,
                service=units[-1] if units else None)


def username(uid):
    if uid is None:
        return None
    try:
        return pwd.getpwuid(int(uid)).pw_name
    except (KeyError, ValueError):
        return str(uid)


def service_hints():
    """Only associate live pidfiles; OpenRC names and runit cwd add evidence."""
    hints, runit = {}, {}
    started = {p.name for p in Path("/run/openrc/started").glob("*")}
    for path in sorted(Path("/run").glob("*.pid")):
        value = read(path).strip()
        if value.isdigit() and int(value) > 1 and Path("/proc", value).exists():
            name = path.stem
            # pidfiles can be stale/reused: never claim high confidence.
            hints.setdefault(int(value), []).append((name, name in started))
    for root in ("/var/service", "/etc/service", "/run/runit/service"):
        for path in sorted(Path(root).glob("*")):
            if path.is_dir():
                runit.setdefault(os.path.realpath(path), path.name)
    return hints, runit


def discover():
    proc_rows = proc_listeners()
    selected = []
    for command, parser in ((["ss", "-H", "-lntup"], parse_ss),
                            (["netstat", "-lntup"], parse_netstat),
                            (["lsof", "-nP", "-iTCP", "-iUDP", "-FpcuftnPT"], parse_lsof)):
        try:
            output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    universal_newlines=True, timeout=10,
                                    env=dict(os.environ, LC_ALL="C"))
            if output.returncode:
                continue
            selected = parser(output.stdout)
            # An empty command result cannot hide listeners visible through proc.
            if selected or not proc_rows:
                break
        except (OSError, subprocess.TimeoutExpired, ValueError):
            continue

    needed = {item["inode"] for item in proc_rows}
    owners, info = {}, {}
    # Read fd links only once; many sockets may have multiple owning processes.
    for path in Path("/proc").glob("[0-9]*") if needed else ():
        if not path.name.isdigit():
            continue
        try:
            for fd in (path / "fd").iterdir():
                try:
                    link = os.readlink(fd)
                except OSError:
                    continue
                if link.startswith("socket:[") and link[8:-1] in needed:
                    owners.setdefault(link[8:-1], set()).add(int(path.name))
        except OSError:
            continue
    for item in proc_rows:
        pids = owners.get(item["inode"], ())
        selected.extend(dict(item, pid=pid) for pid in sorted(pids))
        if not pids:
            selected.append(item)
    hints, runit = service_hints()

    def get_info(pid):
        if pid not in info:
            info[pid] = process_info(pid)
        return info[pid]

    def service(pid):
        current, seen = pid, set()
        own = get_info(pid)
        if own["service"]:
            return own["service"], "high"
        while current and current not in seen and current > 1:
            seen.add(current)
            details = get_info(current)
            if details["process"] == "runsv":
                try:
                    name = runit.get(os.path.realpath(os.readlink("/proc/%d/cwd" % current)))
                except OSError:
                    name = None
                if name:
                    return name, "medium"
            for name, openrc in hints.get(current, ()):
                executable = os.path.basename(details["executable"] or "")
                if executable.endswith(" (deleted)"):
                    executable = executable[:-10]
                if openrc or name in (details["process"], executable):
                    return name, "low"
            current = details["parent"]
        return None, "unknown"

    records = {}
    for item in selected:
        pid = item["pid"]
        details = get_info(pid) if pid else {}
        unit, confidence = service(pid) if pid else (None, "unknown")
        ip = ipaddress.ip_address(item["address"].split("%", 1)[0])
        loopback = ip.is_loopback or bool(getattr(ip, "ipv4_mapped", None) and ip.ipv4_mapped.is_loopback)
        record = {key: item[key] for key in ("protocol", "address", "port", "family", "pid")}
        record.update(process=details.get("process") or item.get("process"),
                      executable=details.get("executable"),
                      user=username(details.get("uid") or item.get("uid")),
                      service=unit, service_confidence=confidence,
                      loopback_only=loopback, external=not loopback)
        key = (record["protocol"], record["family"], record["address"], record["port"], pid or 0)
        previous = records.get(key)
        if previous:
            # Supplement sparse tool metadata, rather than overwriting it with null.
            record = {k: v if v is not None else previous[k] for k, v in record.items()}
        records[key] = record
    owned = {key[:4] for key in records if key[4]}
    return [records[key] for key in sorted(records)
            if key[4] or key[:4] not in owned]


def self_check():
    assert endpoint("[::1]:22") == ("::1", 22, "IPv6")
    assert endpoint("fe80::1%eth0:53") == ("fe80::1%eth0", 53, "IPv6")
    assert endpoint("*:53", "IPv6") == ("::", 53, "IPv6")
    assert unconnected("[0:0:0:0:0:0:0:0]:*")
    assert proc_address("0100007F" if sys.byteorder == "little" else "7F000001") == "127.0.0.1"
    assert proc_address("0" * 24 + ("01000000" if sys.byteorder == "little" else "00000001")) == "::1"
    ss = 'tcp LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=42,fd=3),("sshd",pid=43,fd=3))\n'
    assert [r["pid"] for r in parse_ss(ss)] == [42, 43]
    assert len(parse_ss("udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:*")) == 1
    assert not parse_ss("udp ESTAB 0 0 127.0.0.1:53 127.0.0.1:99")
    assert not parse_ss("udp UNCONN 0 0 127.0.0.1:53 127.0.0.1:99")
    ns = 'Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address Foreign Address State PID/Program name\ntcp6 0 0 :::22 :::* LISTEN 42/sshd\nudp 0 0 0.0.0.0:53 0.0.0.0:* 43/dns\n'
    assert [r["family"] for r in parse_netstat(ns)] == ["IPv6", "IPv4"]
    ls = 'p42\ncsshd\nu0\nf3\ntIPv6\nPTCP\nn*:22\nTST=LISTEN\nf4\ntIPv4\nPUDP\nn127.0.0.1:53->127.0.0.1:99\nf5\ntIPv4\nPUDP\nn*:53\n'
    assert [r["protocol"] for r in parse_lsof(ls)] == ["tcp", "udp"]
    for parser in (parse_ss, parse_netstat, parse_lsof):
        try:
            parser("garbage")
        except ValueError:
            pass
        else:
            raise AssertionError("malformed command output accepted")
    print("self-check OK")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-check"]:
        self_check()
    elif sys.argv[1:]:
        sys.exit("usage: discover-listeners [--self-check]")
    else:
        print(json.dumps(discover(), sort_keys=True, separators=(",", ":")))
