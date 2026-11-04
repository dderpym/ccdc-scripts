#!/usr/bin/env python3
"""Print this host's distribution as JSON: {"id", "id_like", "version", "name"}."""
import json

def parse_os_release(text):
    values = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() and not key.startswith("#"):
            values[key.strip()] = value.strip().strip("\"'")
    return values


def detect(path="/etc/os-release"):
    try:
        with open(path) as handle:
            values = parse_os_release(handle.read())
    except OSError:
        values = {}
    distro_id = values.get("ID", "").lower()
    id_like = values.get("ID_LIKE", "").lower()
    return {"id": distro_id, "id_like": id_like, "version": values.get("VERSION_ID", ""),
            "name": values.get("PRETTY_NAME") or values.get("NAME", "")}


def main():
    print(json.dumps(detect(), sort_keys=True))


if __name__ == "__main__":
    main()
