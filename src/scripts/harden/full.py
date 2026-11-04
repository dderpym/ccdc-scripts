"""The whole free-fixes pass: sshd first (it self-verifies), then the service clean-up."""
from ccdc.script import ComposedScript, Step
from scripts.harden.services import DisableUnneededServices
from scripts.ssh.harden import HardenSSHD


class Harden(ComposedScript):
    """SSH hardening first (it self-verifies), then the service clean-up."""

    def __init__(self, runner=None, allow=()):
        super().__init__(Step(HardenSSHD(runner)), Step(DisableUnneededServices(runner), allow=tuple(allow)))

