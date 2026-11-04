#!/usr/bin/env python3
"""Print this host's distribution as JSON: {"id", "id_like", "version", "family"}."""
import json

# Families are named after the package manager that matters for them.
FAMILIES = {
    "debian": ("debian", "ubuntu", "raspbian", "kali", "linuxmint"),
    "rhel": ("rhel", "centos", "rocky", "fedora", "almalinux", "ol", "amzn"),
    "alpine": ("alpine",),
    "arch": ("arch", "manjaro"),
    "void": ("void",),
    "suse": ("suse", "opensuse", "sles"),
}


def parse_os_release(text):
    values = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() and not key.startswith("#"):
            values[key.strip()] = value.strip().strip("\"'")
    return values


def family(distro_id, id_like=""):
    """First family matching the distro itself, then its declared parents."""
    for candidate in [distro_id, *id_like.split()]:
        for name, members in FAMILIES.items():
            if any(candidate == m or candidate.startswith(m + "-") for m in members):
                return name
    return "unknown"


def detect(path="/etc/os-release"):
    try:
        with open(path) as handle:
            values = parse_os_release(handle.read())
    except OSError:
        values = {}
    distro_id = values.get("ID", "").lower()
    id_like = values.get("ID_LIKE", "").lower()
    return {"id": distro_id, "id_like": id_like, "version": values.get("VERSION_ID", ""),
            "family": family(distro_id, id_like)}


def main():
    print(json.dumps(detect(), sort_keys=True))


if __name__ == "__main__":
    main()
