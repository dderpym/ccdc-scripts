"""Is this path owned by an installed package? Tests the path and its realpath (usrmerge)."""
import os
import subprocess

# manager binary -> argv prefix; rc 0 means owned
QUERIES = (
    ("dpkg", ["dpkg", "-S"]),
    ("rpm", ["rpm", "-qf"]),
    ("apk", ["apk", "info", "-W"]),
    ("pacman", ["pacman", "-Qo"]),
    ("xbps-query", ["xbps-query", "-o"]),
)


def _which(name, path=None):
    for directory in (path or os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")).split(os.pathsep):
        candidate = os.path.join(directory, name)
        if os.access(candidate, os.X_OK):
            return candidate
    return None


def checker(run=subprocess.run, which=_which):
    """owned(path) -> True/False, or None when no package manager is available."""
    prefix = next((argv for name, argv in QUERIES if which(name)), None)
    if prefix is None:
        return lambda path: None

    def owned(path):
        for candidate in dict.fromkeys((path, os.path.realpath(path))):
            result = run([*prefix, candidate], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result.returncode == 0:
                return True
        return False
    return owned
