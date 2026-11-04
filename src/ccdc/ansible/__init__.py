"""Scripts that act on a Target through Ansible."""
from ccdc.runner import AnsibleRunner
from ccdc.script import Script


class AnsibleScript(Script):
    """A script that acts on a Target; run(target, ...) is its first argument.

    The Target says which host and how to authenticate (ssh-agent key, bootstrap
    password, ...); see ccdc.target. Tests pass a fake runner.
    """

    def __init__(self, runner=None):
        self.runner = runner or AnsibleRunner()

    def run(self, target, **kwargs):
        raise NotImplementedError


class BundleScript(AnsibleScript):
    """Runs one entry of the host bundle (host/<entry>.py) and returns its parsed JSON."""
    entry = None
    become = True

    def arguments(self, **kwargs):
        return []

    def parse(self, document, **kwargs):
        return document

    def run(self, target, **kwargs):
        document = self.runner.entry(target, self.entry, self.arguments(**kwargs), become=self.become)
        return self.parse(document, **kwargs)


class PlaybookScript(AnsibleScript):
    """Runs playbooks/<playbook>.yml (next to this module) against the target; keyword arguments become extra-vars."""
    playbook = None

    def run(self, target, **variables):
        return self.runner.playbook(target, self.playbook, variables)
