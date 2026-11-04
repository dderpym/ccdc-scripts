#!/usr/bin/env python3
"""fix_ld_preload FILE [--unit UNIT] [--var NAME]: remove library injection from FILE, then restart UNIT.

Backs the file up under /root/ir/ first. With --var, only that variable is removed from
Environment=/env-file lines (a drop-in left with nothing else is deleted); without it the
whole file is emptied (ld.so.preload). The unit is RESTARTED (a reload leaves the library
mapped), then /proc/*/maps is rechecked. Prints JSON; nonzero exit if still mapped.
"""
import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import time

from host import scan_ld_preload as scan

ALLOWED = ("/etc/", "/usr/lib/systemd/", "/lib/systemd/", "/run/systemd/")
EVIDENCE = "/root/ir"


def strip_variable(text, variable):
    """(text without `variable` in Environment= or KEY=VALUE lines, removed values)."""
    removed, out = [], []
    for line in text.splitlines():
        stripped = line.strip()
        comment = stripped[:1] in ("#", ";")
        key, sep, value = stripped.partition("=")
        if not comment and sep and key.strip() == "Environment":
            kept = []
            for item in shlex.split(value):
                if item.partition("=")[0] == variable:
                    removed.append(item.partition("=")[2])
                else:
                    kept.append(item)
            if kept:
                out.append("Environment=" + " ".join(shlex.quote(i) for i in kept))
            continue
        if not comment and sep and stripped.removeprefix("export ").partition("=")[0].strip() == variable:
            removed.append(stripped.partition("=")[2].strip("\"'"))
            continue
        out.append(line)
    return "\n".join(out) + ("\n" if out else ""), removed


def only_boilerplate(text):
    return not [line for line in scan.logical_lines(text) if line != "[Service]"]


def backup(path, root=EVIDENCE):
    directory = os.path.join(root, f"ld-preload-{int(time.time())}")
    os.makedirs(directory, mode=0o700, exist_ok=True)
    shutil.copy2(path, os.path.join(directory, path.strip("/").replace("/", "__")))
    return directory


def edit(path, variable, evidence=EVIDENCE, allowed=ALLOWED):
    if not os.path.isabs(path) or not os.path.realpath(path).startswith(allowed):
        raise ValueError("refusing path outside system configuration: " + path)
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    saved = backup(path, evidence)
    if variable:
        new, removed = strip_variable(text, variable)
        action = "deleted" if only_boilerplate(new) and ".d/" in path else "edited"
    else:
        new, removed = "", [text.strip()]
        action = "emptied" if os.path.basename(path) == "ld.so.preload" else "deleted"
    if action == "deleted":
        os.unlink(path)
    else:
        temporary = path + ".ccdc-tmp"
        with open(temporary, "w") as handle:
            handle.write(new)
        shutil.copymode(path, temporary)
        os.replace(temporary, path)
    return {"action": action, "backup": saved, "removed": removed}


def still_mapped(values, proc="/proc"):
    names = {os.path.basename(lib) for value in values for lib in value.replace(":", " ").split()}
    return sorted(lib for lib in scan.mapped_libraries(proc) if os.path.basename(lib) in names)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    parser.add_argument("--unit")
    parser.add_argument("--var")
    args = parser.parse_args(argv)
    try:
        result = edit(args.file, args.var)
        if args.unit:
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            subprocess.run(["systemctl", "restart", args.unit], check=True)
        result["still_mapped"] = still_mapped(result["removed"])
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    print(json.dumps(result))
    return 1 if result["still_mapped"] else 0


if __name__ == "__main__":
    sys.exit(main())
