"""Where a script runs and how it authenticates there."""
from dataclasses import dataclass, field


class Auth:
    """Ansible connection variables for one way of logging in."""

    def variables(self):
        return {}


@dataclass(frozen=True)
class AgentAuth(Auth):
    """The configured user (ansible.cfg: oski) with the key in the controller's ssh-agent."""
    user: str = ""

    def variables(self):
        return {"ansible_user": self.user} if self.user else {}


@dataclass(frozen=True)
class PasswordAuth(Auth):
    """A known password, e.g. the bootstrap root password. Never appears in argv or repr."""
    user: str = "root"
    password: str = field(default="", repr=False)

    def variables(self):
        ssh = ("-o ControlMaster=no -o ControlPath=none -o ForwardAgent=no "
               "-o PreferredAuthentications=password -o PubkeyAuthentication=no "
               "-o KbdInteractiveAuthentication=no")
        return {"ansible_user": self.user, "ansible_become": self.user != "root",
                "ansible_password": self.password, "ansible_ssh_pass": self.password,
                "ansible_ssh_args": ssh}


@dataclass(frozen=True)
class Target:
    host: str
    auth: Auth = field(default_factory=AgentAuth)

    def __str__(self):
        return self.host
