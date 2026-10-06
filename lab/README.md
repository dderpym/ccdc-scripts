# Disposable CCDC lab — deliberately vulnerable

Two local containers: **hatchery (Alpine)** and **tarpit (Debian)**. They run SSH,
nginx (TCP/80), and a small Python HTTP fixture (TCP/9000), without systemd.
They share the internal `172.30.133.0/24` Docker network. Host-visible services
bind **only to 127.0.0.1**, not your LAN/Tailscale interfaces. No Tailscale commands,
manual route/policy changes, runtime host networking, or privileged containers
are used. `NET_ADMIN` applies only to each container's own firewall namespace.

A single stdlib loopback relay connects to private bind-mounted Unix sockets
inside the containers. This avoids Docker DNAT/bridge routing getting captured
by an existing host VPN policy, without changing that policy. The relay pins real
socket inodes in an unmounted host-private directory, so replacing a container
socket with a symlink cannot redirect it to another host service. After directly
restarting containers, rerun `lab/manage up` to re-pin their new listeners.
No Docker socket or private SSH key is mounted into the containers. Package-download builds use
host networking; package daemons are not started during the build. Runtime
containers have no external network access. Requires a local Linux Docker daemon.

Do not expose these containers to a real network or use real team credentials.

```sh
. .venv/bin/activate
./lab/manage up                     # prompts for disposable root password
# Or use an owned mode-0600 one-line file, never a password in argv:
# ./lab/manage up --password-file secrets/lab/root.password
export ANSIBLE_INVENTORY=lab/inventory.yml

./scripts/ccdcctl ping
./scripts/ccdcctl ssh status
./scripts/ccdcctl firewall status
./scripts/ccdcctl listeners
./scripts/ccdcctl integrity
./scripts/ccdcctl lse
./scripts/ccdcctl monitor integrity --once
./scripts/ccdcctl monitor lse --once

./lab/check                         # opt-in live, read-only smoke suite
```

`lab/check` validates HTTP/SSH, existing discovery commands, persistent native
integrity findings, LSE test IDs, and the combined monitor. It writes private
evidence to `reports/lab/check.json`. It checks root password login too if
`secrets/lab/root.password` exists. No tests run against real inventory hosts.

Scanners return nonzero for these intentional findings; that is expected.
Integrity/LSE findings must not be accepted as baselines.
SSH/firewall monitoring still needs an explicitly reviewed policy baseline;
there is no implicit baseline during lab startup.

| Host | Container IP | Host SSH | Host nginx | Host fixture app |
| --- | --- | --- | --- | --- |
| hatchery | 172.30.133.70 | 127.0.0.1:22270 | http://127.0.0.1:8080 | http://127.0.0.1:9070 |
| tarpit | 172.30.133.170 | 127.0.0.1:22170 | http://127.0.0.1:8081 | http://127.0.0.1:9170 |

`manage up` derives the lab inventory from validated loopback relay endpoints
specified by the deployed containers' labels.
The regular `inventory.yml` is untouched. Scans use the existing controller and
Ansible inventory interface; there is no hardcoded controller-side host list.
The separate lab inventory contains only these two hosts.

A disposable `oski` key/account with passwordless sudo is provisioned for the
normal CLI. The root account uses the password entered at setup. Its password
is passed to `chpasswd` via stdin, never baked into images or Docker environment.
The team key placeholder `files/oski.pub` is not changed. This fixture provision
is not a test of `ccdcctl init`, which rotates root credentials and needs a real
team public key. Run init only explicitly if you want to test that workflow.
The entrypoint supervises SSH directly, not through a full distro init system;
`ssh configure` therefore correctly refuses an unmanaged service. Use a full
OpenRC/runit/systemd VM to test service reload/hardening. Host relays connect to
container loopback, so test external firewall enforcement from the other container,
not by assuming a host relay port exercises an external INPUT path.

Container SSH host keys are generated on first boot, not shared in the image.
The dedicated mode-0600 `secrets/lab/known_hosts` trusts public host keys read
from the local containers. Strict SSH host-key checking remains enabled.
Private keys and optional password files are under gitignored `secrets/lab/`.

## Intentional faults

- Modified package-owned `/usr/bin/ssh` contents (inert appended bytes) and mode
  `0777`, without breaking the server's SSH/SFTP transport.
- Deleted package-owned `/usr/bin/scp`.
- World-writable `/etc/passwd` (`0666`).
- World-writable `/etc/cron.d/ccdc-lab` (`0666`), with an inert `/bin/true` task.
- Changed vendor nginx configuration (one worker plus a fixture comment).
- Passwordless sudo for oski and permissive root/password SSH.

The normal native verification should flag package tampering; bounded critical
metadata checks should flag dangerous modes even on dpkg; LSE should flag the
writable critical/recurring-task state and sudo access. Some account/server
configuration differences and Docker virtual-directory metadata differences are
additional findings, not suppressed.
The extra HTTP fixture files are unowned and must not flood normal apk scans.

Findings persist until repaired. To experiment with mode repairs, use **only the
lab containers**, for example:

```sh
docker exec ccdc-lab-hatchery chmod 0644 /etc/passwd
./scripts/ccdcctl integrity hatchery
./scripts/ccdcctl lse hatchery
```

This fixes only that mode; package tampering and other vulnerabilities remain.
Normal scanners never repair these automatically. Restarts preserve repairs;
recreating the containers restores all deliberate faults.

## Reset/remove

```sh
./lab/manage down
./lab/manage up
# Afterwards keep/set ANSIBLE_INVENTORY=lab/inventory.yml to select the lab.
```

`down` stops only the managed relay and removes this Compose project's containers
and internal network;
other Docker workloads, Tailscale, and your main inventory are untouched.
Images and the disposable test key are retained for fast recreation. To return
to the normal inventory, `unset ANSIBLE_INVENTORY`. Existing reports use the same
host aliases, so save any competition reports before scanning lab aliases.
