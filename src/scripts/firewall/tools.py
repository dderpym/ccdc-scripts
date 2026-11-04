"""Firewall phase: make sure the networking CLI tools exist before any policy is applied."""
from ccdc.ansible import PlaybookScript


class PrepareNetworkTools(PlaybookScript):
    """ip, ss, nft and the dual-stack iptables tools; installs only what is missing, starts nothing."""
    playbook = "network-tools"
