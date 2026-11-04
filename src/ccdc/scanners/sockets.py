from ccdc.scanners.lse import LSEScanner


class SocketAndShareScanner(LSEScanner):
    """Writable tmux/screen sockets and NFS no_root_squash exports."""
    tests = ("sof130", "sof160", "fst210")
