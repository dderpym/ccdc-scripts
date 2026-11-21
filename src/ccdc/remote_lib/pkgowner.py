"""Is this path owned by an installed package? The ONE ownership test every scanner and fix uses.

Package databases record files under whichever spelling the package shipped: Debian lists
/lib/x86_64-linux-gnu/libc.so.6 while the file is reached (and mapped) as /usr/lib/...; newer
releases list /usr/lib/.... So a path is owned if ANY of its spellings is: the path itself, its
realpath, and the usrmerge counterpart of each (/usr/lib/x <-> /lib/x, same for bin, sbin,
lib32, lib64). Asking about a spelling that does not exist is harmless.
"""
import os
import shutil
import subprocess

MERGED = ("bin", "sbin", "lib", "lib32", "lib64")
BATCH = 200


def aliases(path, root="/"):
    """Every spelling of `path` a package database might use, the given path first."""
    forms = list(dict.fromkeys((path, os.path.realpath(path))))
    usr = os.path.join(root, "usr")
    out = list(forms)
    for form in forms:
        if form.startswith(usr + "/"):
            relative = form[len(usr) + 1:]
            if relative.split("/")[0] in MERGED:
                out.append(os.path.join(root, relative))
        else:
            relative = os.path.relpath(form, root)
            if not relative.startswith("..") and relative.split("/")[0] in MERGED:
                out.append(os.path.join(usr, relative))
    return list(dict.fromkeys(out))


def backend(which=shutil.which):
    """Name of the package database to ask, or None. dpkg/rpm are checked first (batchable)."""
    for name in ("dpkg", "rpm", "apk", "pacman", "xbps-query"):
        if which(name):
            return name
    return None


def _single(name, path, run):
    argv = {"dpkg": ["dpkg", "-S", "--"], "rpm": ["rpm", "-qf", "--"], "apk": ["apk", "info", "-W"],
            "pacman": ["pacman", "-Qo"], "xbps-query": ["xbps-query", "-o"]}[name]
    return run([*argv, path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def checker(run=subprocess.run, which=shutil.which, root="/"):
    """owned(path) -> True/False, or None when no package manager is available."""
    name = backend(which)
    if name is None:
        return lambda path: None

    cache = {}  # the same libraries are mapped by every process: ask the database once per spelling

    def ask(form):
        if form not in cache:
            cache[form] = _single(name, form, run)
        return cache[form]

    def owned(path):
        return any(ask(form) for form in aliases(path, root))
    return owned


def claimed(paths, name, run=subprocess.run):
    """Subset of the exact `paths` some package claims, asking dpkg/rpm in batches."""
    paths = sorted(set(paths))
    owned = set()
    for start in range(0, len(paths), BATCH):
        batch = paths[start:start + BATCH]
        if name == "dpkg":
            out = run(["dpkg", "-S", "--", *batch], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).stdout
            for line in out.splitlines():
                if line.startswith("diversion by"):
                    continue
                _, sep, path = line.partition(": ")
                if sep:
                    owned.add(path.strip())
        elif name == "rpm":
            out = run(["rpm", "-qf", "--qf", "%{NAME}\\n", "--", *batch], stdout=subprocess.PIPE,
                      stderr=subprocess.DEVNULL, text=True).stdout
            lines = out.splitlines()  # rpm prints one line per argument, in order
            if len(lines) == len(batch):
                owned.update(p for p, line in zip(batch, lines) if "is not owned by" not in line)
            else:
                owned.update(p for p in batch if _single("rpm", p, run))
        else:
            owned.update(p for p in batch if _single(name, p, run))
    return owned


def is_claimed(path, claimed_paths, root="/"):
    """True when any spelling of `path` is among the paths `claimed()` returned."""
    return any(form in claimed_paths for form in aliases(path, root))
