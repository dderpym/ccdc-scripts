from ccdc.ansible import PlaybookScript


class Init(PlaybookScript):
    """Bootstrap team access (ccdc/ansible/playbooks/init.yml). Use a PasswordAuth target for the first run."""
    playbook = "init"
