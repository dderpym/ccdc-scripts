#!/usr/bin/env python3
"""install MANAGER PACKAGE...: install only what is missing; JSON {"installed": [...], "already": [...]}.

Never assumes an earlier run: each call asks the package database first.
"""
import json
import os
import subprocess
import sys

# manager -> (installed? argv template, install argv, refresh argv or None)
MANAGERS = {
    "apt": (["dpkg-query", "-W", "-f=${Status}", "{}"], ["apt-get", "install", "-y", "--no-install-recommends"],
            ["apt-get", "update"]),
    "dnf": (["rpm", "-q", "{}"], ["dnf", "install", "-y"], None),
    "yum": (["rpm", "-q", "{}"], ["yum", "install", "-y"], None),
    "apk": (["apk", "info", "-e", "{}"], ["apk", "add", "--no-cache"], None),
    "pacman": (["pacman", "-Q", "{}"], ["pacman", "-S", "--noconfirm", "--needed"], ["pacman", "-Sy"]),
    "xbps": (["xbps-query", "{}"], ["xbps-install", "-y"], ["xbps-install", "-S"]),
    "zypper": (["rpm", "-q", "{}"], ["zypper", "--non-interactive", "install"], None),
}


def installed(manager, package, run=subprocess.run):
    argv = [part.replace("{}", package) for part in MANAGERS[manager][0]]
    result = run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    if result.returncode:
        return False
    # dpkg-query reports removed-but-configured packages with rc 0.
    return manager != "apt" or result.stdout.strip().endswith("install ok installed")


def install(manager, packages, run=subprocess.run):
    if manager not in MANAGERS:
        raise ValueError("unsupported package manager: " + manager)
    missing = [p for p in packages if not installed(manager, p, run)]
    if missing:
        _, command, refresh = MANAGERS[manager]
        env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
        if refresh:
            run(refresh, env=env, check=False, stdout=sys.stderr)
        run([*command, *missing], env=env, check=True, stdout=sys.stderr)
    return {"installed": missing, "already": [p for p in packages if p not in missing]}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) < 2:
        print("usage: remote.py MANAGER PACKAGE...", file=sys.stderr)
        return 2
    try:
        print(json.dumps(install(argv[0], argv[1:])))
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
