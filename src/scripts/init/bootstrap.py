"""Init phase: team access and controller trust."""
from ccdc.ansible import PlaybookScript


class Init(PlaybookScript):
    """Bootstrap team access (ccdc/ansible/playbooks/init.yml). Use a PasswordAuth target for the first run."""
    playbook = "init"


class HostKeys(PlaybookScript):
    """Replace the controller's saved host keys for the target (explicit trust reset; run before Init)."""
    playbook = "host-keys"
