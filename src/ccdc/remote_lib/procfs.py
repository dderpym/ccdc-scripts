"""Small /proc readers shared by the process scanners; `root` allows fixture trees."""
import os


def read(path, default=""):
    try:
        with open(path, "rb") as handle:
            return handle.read(65536).decode("utf-8", "replace")
    except OSError:
        return default


def processes(root="/proc"):
    """Yield dicts {pid, comm, exe, cmdline, ppid} for every readable process."""
    try:
        names = os.listdir(root)
    except OSError:
        return
    for name in sorted((n for n in names if n.isdigit()), key=int):
        base = os.path.join(root, name)
        try:
            exe = os.readlink(os.path.join(base, "exe"))
        except OSError:
            exe = ""
        ppid = 0
        for line in read(os.path.join(base, "status")).splitlines():
            if line.startswith("PPid:"):
                ppid = int(line.split()[1])
        yield {"pid": int(name), "comm": read(os.path.join(base, "comm")).strip(), "exe": exe,
               "cmdline": read(os.path.join(base, "cmdline")).replace("\0", " ").strip(), "ppid": ppid}
