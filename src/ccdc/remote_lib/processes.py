"""What counts as a fileless process or a fake kernel thread (shared by the memfd and
kworker scanners and the kill fix, so the fix re-checks with the scanner's own rule)."""
import re

# A deleted exe under these is almost always a package upgrade awaiting restart.
SYSTEM_DIRS = ("/usr/", "/bin/", "/sbin/", "/lib", "/opt/")
DELETED = " (deleted)"
# Names kernel threads really use. Plain "k*" would also match kubelet, klogd, ...
KERNEL_THREAD = re.compile(r"^(kworker|ksoftirqd|kthreadd|kswapd|kcompactd|khugepaged|kdevtmpfs|kauditd|"
                           r"khungtaskd|kblockd|ksmd|kintegrityd|kpsmoused|kthrotld|kstrp|kcryptd|kmpath|kdmflush)")


def classify_exe(exe):
    """'memfd', 'deleted' or None."""
    if exe.startswith("/memfd:"):
        return "memfd"
    if exe.endswith(DELETED) and not exe.startswith(SYSTEM_DIRS):
        return "deleted"
    return None


def is_fake_kernel_thread(proc):
    """Real kernel threads have no /proc/PID/exe."""
    return bool(proc["exe"]) and bool(KERNEL_THREAD.match(proc["comm"]))


def matches(proc, kind):
    if kind == "memfd":
        return classify_exe(proc["exe"]) is not None
    if kind == "kworker":
        return is_fake_kernel_thread(proc)
    raise ValueError("unknown kind: " + kind)
