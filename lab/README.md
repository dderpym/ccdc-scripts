# Disposable CCDC lab — deliberately vulnerable

Two self-contained Linux server containers: **hatchery (Alpine, BusyBox init +
OpenRC)** and **tarpit (Debian, systemd)**. Each boots its distribution's init as
PID 1 and runs managed SSH, nginx (TCP/80), cron, system logging, and a small
Python HTTP fixture (TCP/9000). Debian also runs journald and D-Bus. Service
start/stop/restart/reload commands work normally, including SSH hardening.

They share the `172.30.133.0/24` Docker bridge network, with normal Docker NAT
for **outbound internet access**, including Ansible package downloads. No
container service ports are published; host-visible relay services bind
**only to 127.0.0.1**. Containers use explicit public DNS (`1.1.1.1` and `8.8.8.8`)
and disable inherited DNS search domains. Docker's embedded resolver still resolves
lab service names; external queries do not use host/Tailscale DNS. `manage up`
checks package-repository and peer-name resolution before declaring the lab ready.
Network namespaces do not isolate Docker's default DNS configuration or host
forwarding/VPN policy; DNS is pinned explicitly here. No manual route/policy changes, runtime host
networking, host cgroup mounts, or `--privileged` containers are used.
`NET_ADMIN` applies to each container's own firewall namespace. Debian also
needs `SYS_ADMIN` to remount its **private cgroup v2 namespace** writable for
systemd. This is a broad capability: these intentionally vulnerable servers
are not a security boundary against hostile root users; use a dedicated lab
VM for adversarial testing. The kernel, network interface setup, and clock
remain supplied by Docker/the host, as with other system containers.

A single stdlib loopback relay connects to private bind-mounted Unix sockets
inside the containers. This avoids Docker DNAT/bridge routing getting captured
by an existing host VPN policy, without changing that policy. The relay pins real
socket inodes in an unmounted host-private directory, so replacing a container
socket with a symlink cannot redirect it to another host service. After directly
restarting containers, rerun `lab/manage up` to re-pin their new listeners.
No Docker socket or private SSH key is mounted into the containers. Package-download builds use
host networking; package daemons are not started during the build. Runtime
outbound access uses Docker's bridge, not host networking; host firewall/VPN
policy can still block that traffic. Requires a local Linux Docker daemon
with cgroup v2 and private cgroup namespace support. A host AppArmor policy must
allow Debian's private cgroup remount; a denial fails startup rather than silently
running without systemd. Runtime `/run` and `/tmp` are container-private tmpfs.

Do not expose these containers to a real network or use real team credentials.

```sh
source ./setup                     # Bash: activate .venv and all CLI completions
./lab/manage up                     # prompts for disposable root password
# Or use an owned mode-0600 one-line file, never a password in argv:
# ./lab/manage up --password-file lab/secrets/root.password
export ANSIBLE_INVENTORY=lab/inventory.yml

./scripts/ccdcctl ping
./scripts/ccdcctl ssh status
./scripts/ccdcctl firewall status
./scripts/ccdcctl listeners
./scripts/ccdcctl integrity
./scripts/ccdcctl lse
./scripts/ccdcctl monitor integrity --once
./scripts/ccdcctl monitor lse --once

./scripts/check-lab                 # opt-in live, read-only smoke suite
```

The repository's `scripts/check-lab` validates native init and running managed
services, package-repository DNS resolution, HTTP/SSH, existing discovery commands, persistent native integrity
findings, LSE test IDs, and the combined monitor. It writes private evidence to `reports/lab/check.json` and uses the
normal repository report paths. It checks root password login too if
`lab/secrets/root.password` exists. No tests run against real inventory hosts.

Scanners return nonzero for these intentional findings; that is expected.
Integrity/LSE findings must not be accepted as baselines.
SSH/firewall monitoring still needs an explicitly reviewed policy baseline;
there is no implicit baseline during lab startup. Firewall configure uses
Ansible to provision missing networking tools from distribution repositories;
init only bootstraps access. To apply changed DNS settings to existing containers,
rerun `lab/manage up` (Compose recreates them, resetting their writable state).

If the lab was created with the old internal-only network, recreate it once to
apply outbound access; Docker cannot change that property on an existing network:

```sh
./lab/manage down
./lab/manage up                     # prompts for disposable root password
```

This resets the disposable containers' writable state, including previous
hardening and package changes. Reapply and review policies afterward. It does
not change the host firewall or VPN policy.

| Host | Container IP | Host SSH | Host nginx | Host fixture app |
| --- | --- | --- | --- | --- |
| hatchery | 172.30.133.70 | 127.0.0.1:22270 | <http://127.0.0.1:8080> | <http://127.0.0.1:9070> |
| tarpit | 172.30.133.170 | 127.0.0.1:22170 | <http://127.0.0.1:8081> | <http://127.0.0.1:9170> |

`manage up` derives the lab inventory from validated loopback relay endpoints
specified by the deployed containers' labels. Like the regular inventory, it is
plain YAML; each host has only `ansible_host` and `ansible_port`. The default user
comes from the existing `ansible.cfg`, and lab key/known-hosts settings live in
`lab/group_vars/all.yml`. HTTP ports and bridge addresses are read from Docker
by the smoke suite, not stored in the SSH inventory.
`lab/` contains only the fixture setup, relay, generated connection inventory,
and disposable setup credentials in `lab/secrets/`. It has no dependency on
repository scripts or configuration; it can be moved outside this repository.
The repository targets its inventory just like any other hosts. Controller
credentials, reports, and baselines retain their normal repository paths;
there is no lab-specific output routing. Repository tests stay in `tests/`.
Run offline checks with `make test`; no containers are started by those tests.

For a lab stored elsewhere:

```sh
python3 /path/to/lab/manage up --password-file /path/to/lab/secrets/root.password
export ANSIBLE_INVENTORY=/path/to/lab/inventory.yml
./scripts/ccdcctl ping
./scripts/check-lab --inventory /path/to/lab/inventory.yml
```

Setup requires Docker Compose, Python with PyYAML, and `ssh-keygen`.
The regular `inventory.yml` is untouched. Scans use the existing controller and
Ansible inventory interface; there is no hardcoded controller-side host list.
The separate lab inventory contains only these two hosts.

A disposable `oski` key/account with passwordless sudo is provisioned for the
normal CLI. The root account uses the password entered at setup. Its password
is passed to `chpasswd` via stdin, never baked into images or Docker environment.
The team key placeholder `files/oski.pub` is not changed. This fixture provision
is not a test of `ccdcctl init`, which rotates root credentials and needs a real
team public key. Run init only explicitly if you want to test that workflow.
The entrypoint provisions fixtures, then execs the normal distro init. SSH is
managed by the vendor `sshd` OpenRC service on Alpine and `ssh.service` on Debian;
`ccdcctl ssh configure` can validate and reload it normally. The fixture app and
private socket relays have their own services too. For example:

```sh
docker exec ccdc-lab-hatchery rc-status
docker exec ccdc-lab-hatchery rc-service sshd reload
docker exec ccdc-lab-tarpit systemctl --no-pager status ssh nginx cron rsyslog
docker exec ccdc-lab-tarpit systemctl reload ssh
# Other fixture services: ccdc-app, ccdc-relay-{ssh,http,app} (OpenRC),
# or ccdc-app.service, ccdc-relay@{ssh,http,app}.service (systemd).
```

Host relays connect to container loopback, so test external firewall enforcement
from the other container, not by assuming a host relay port exercises an external
INPUT path. Restarting SSH/nginx/app leaves their relay listeners intact;
restarting the containers recreates those listeners and requires `manage up`.

Container SSH host keys and Debian's machine ID are generated on first boot,
not shared in the image. The dedicated mode-0600 `lab/secrets/known_hosts` trusts public host keys read
from the local containers. Strict SSH host-key checking remains enabled.
Select `lab/inventory.yml` to use these pins; merely copying the loopback
addresses into the main inventory does not select the lab's connection settings.
For an intentional trust reset, the repository offers
`ccdcctl init --replace-host-keys`; this also respects the lab inventory's
`ccdc_known_hosts_file`. Normal commands never replace keys automatically.
Private keys and optional password files are under gitignored `lab/secrets/`.
The Docker build context includes only the Dockerfile, entrypoint, and service
definitions, never credentials or generated reports.

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
writable critical/recurring-task state. Passwordless sudo for the repository's
`oski` account is expected access: LSE retains it in raw evidence, not alerts. Some account/server
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
to the normal inventory, `unset ANSIBLE_INVENTORY`. Reports and baselines use
the normal repository paths and the same host aliases, so save any competition
state before targeting the lab. Lab setup itself never reads or writes those
repository directories.
