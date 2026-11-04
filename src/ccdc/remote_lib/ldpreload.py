"""LD_PRELOAD helpers shared by the scan and the fix (runs on the target)."""
import os


def logical_lines(text):
    """Systemd-style lines: backslash continues, # and ; start comments."""
    pending = ""
    for raw in text.splitlines():
        line = pending + raw.strip()
        pending = ""
        if line.endswith("\\"):
            pending = line[:-1] + " "
            continue
        if line and line[0] not in "#;":
            yield line
    if pending.strip():
        yield pending.strip()


def mapped_libraries(proc="/proc"):
    """{library path: [(pid, comm)]} for every .so mapped by a readable process."""
    libs = {}
    for pid in sorted((p for p in os.listdir(proc) if p.isdigit()), key=int):
        try:
            with open(f"{proc}/{pid}/maps") as handle:
                names = {parts[5].strip() for parts in (line.split(None, 5) for line in handle) if len(parts) == 6}
            with open(f"{proc}/{pid}/comm") as handle:
                comm = handle.read().strip()
        except OSError:
            continue
        for name in names:
            if name.startswith("/") and ".so" in os.path.basename(name) and not name.endswith("(deleted)"):
                libs.setdefault(name, []).append((int(pid), comm))
    return libs
