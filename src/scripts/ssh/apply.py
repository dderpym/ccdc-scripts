"""SSH phase: apply the reviewed sshd policy (root login off, key auth on)."""
from ccdc.ansible import BundleScript


class ApplySSH(BundleScript):
    """run(target, enabled): `enabled` is whether password/kbd-interactive auth stays on. Returns success."""
    entry = "apply_ssh"
    live = True
    connection = True

    def arguments(self, enabled, **kwargs):
        return ["yes" if enabled else "no"]
