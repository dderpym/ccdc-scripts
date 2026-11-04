"""Remote-access agents worth a human look. Edit freely: names are matched against
process names/exe basenames and systemd unit names; paths are checked for existence."""
NAMES = ("meshagent", "xrdp", "xrdp-sesman", "netbird", "anydesk", "teamviewer", "teamviewerd",
         "rustdesk", "tailscaled", "zerotier-one", "x11vnc", "vncserver", "ngrok", "frpc", "chisel")
PATHS = ("/usr/local/mesh_services", "/opt/meshagent", "/opt/k3s/meshagent", "/usr/local/bin/meshagent",
         "/opt/teamviewer", "/etc/netbird")
