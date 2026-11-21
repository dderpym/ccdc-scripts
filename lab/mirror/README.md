# Mirror lab: the real boxes, in containers

Six disposable systemd containers modelled on the competition boxes: **same distros, same last-octet
IPs, same service ports**, each seeded with ordinary misconfigurations that sound autofixable (file
modes, setuid bits, sshd settings, sudoers grants, secrets in readable files, a root-run service). It
complements the two-host `lab/` (Alpine/OpenRC + Debian), which is untouched and can run beside it.

Use it to fire the lab up, run your tooling against it, and see which issues get fixed. It is **not** a
place for hostile code: the "services" are tiny stand-ins and every issue is a plain mode, setting or
config line. Do not expose these containers to a real network or use real credentials; like `lab/`
they carry `SYS_ADMIN` (systemd's private cgroup) and are not a security boundary.

## Hosts

| Host | Mirrors | Image | IP | Stand-in ports | Loopback SSH / HTTP / app |
| --- | --- | --- | --- | --- | --- |
| daffy | Blog | Debian 13 | 172.31.133.11 | 80 | 22011 / 8011 / 9011 |
| elmer | Forums | Ubuntu 22.04 | 172.31.133.77 | 80 | 22077 / 8077 / 9077 |
| foghorn | Wiki/Chat | Rocky 9 | 172.31.133.13 | 80, 3010, 3011 | 22013 / 8013 / 9013 |
| sylvester | Video streamer | Rocky 9 | 172.31.133.69 | 48215, 48216, 52113 (aviary app) | 22069 / 8069 / 9069 |
| marvin | Database | Ubuntu 24.04 | 172.31.133.199 | 80, 3306, 27017, 8200 | 22199 / 8199 / 9199 |
| taz | Photo gallery | Debian 13 | 172.31.133.169 | 3000 | 22169 / 8169 / 9169 |

All hosts also run SSH (22), cron and rsyslog under systemd. Nothing is published on a host interface;
access goes through a loopback-only relay, exactly as in `lab/`. The aviary app on sylvester is a small
original stand-in for the scenario app (three ports, a root-run unit, secrets in `/etc/birdcage.env`).

## Start, check, stop

```sh
source ./setup                                   # activates .venv (PyYAML for the generated inventory)
./lab/mirror/manage up --password-file lab/mirror/secrets/root.password   # first build downloads 4 distros
export ANSIBLE_INVENTORY=lab/mirror/inventory.yml
./lab/mirror/check                               # index of every planted issue + availability
./lab/mirror/manage down                         # removes only the ccdc-mirror project
```

`secrets/root.password` is a disposable one-line mode-0600 file you create (`manage up` without the flag
prompts instead). The lab key, known-hosts file and generated inventory live in `lab/mirror/secrets/` and
`lab/mirror/inventory.yml`, both gitignored.

## `lab/mirror/check`: the one command

```text
check                          issue index (PRESENT / fixed per host) + availability
check --state present          only what is still broken           (or --state fixed)
check --host sylvester         filter by host / --category setuid  (both repeatable)
check --json                   machine-readable
check --expect faulty          exit 1 unless every issue is present (self-test after `manage up`)
check --expect fixed           exit 1 unless every issue is fixed
check --allow daffy:80 foghorn:3010
                               also assert the firewall: listed ports open, other stand-in ports
                               blocked, SSH always open
```

**Issue index.** Every planted issue gets a stable ID (`M-001`...), a host, a severity, a category and a
state. It currently lists 95 issues across `ssh`, `setuid`, `permissions`, `tamper`, `cron`, `secrets`,
`sudo` and `service`, plus 13 informational "port reachable from peers" rows that a firewall review is
meant to decide. A sample:

```text
ID     HOST      STATE    SEV    CATEGORY    ISSUE
M-001  daffy     PRESENT  high   ssh         sshd allows root login (PermitRootLogin yes)
M-043  daffy     PRESENT  high   setuid      /usr/bin/find is setuid
M-049  daffy     fixed    high   permissions /etc/crontab is group/other writable (mode 666)
```

The check does not care which tool fixes something or whether a scanner can detect it: an issue is
`PRESENT` until the file/setting really changes. It reads container state with `docker exec`, so
`fixed` means the mode or setting changed, not merely that a tool said so.

**Availability.** For every host: SSH service active and reachable from a peer, and an ICMP ping from a
peer. For birdcage: the service active, each of 48215 / 48216 / 52113 listening locally and reachable from
a peer, with no request ever sent to the app. A failed ping only warns, because the toolkit's firewall
blocks unsolicited echo by design; any other failed availability check makes the command exit nonzero.

**Adding an issue.** Plant it in `faults.sh`, then add one `Issue(...)` line to `issues.py` (a probe and a
"still present" test). Append, don't insert, to keep IDs stable. Rebuild with `manage up`; recreating the
containers resets all state, including previous hardening.

## Typical exercise

```sh
./lab/mirror/check --expect faulty               # starting state is as designed
./ccdcctl ping
./ccdcctl listeners
./ccdcctl firewall configure                     # approve, say, daffy:80 and foghorn:3010
./ccdcctl integrity --auto-apply=simple
./ccdcctl lse --auto-apply=all
./lab/mirror/check --state present               # what is still broken
./lab/mirror/check --allow daffy:80 foghorn:3010 # did the firewall do what you approved?
```

## Known toolkit issues seen while building this (checkout 8b3c9da)

These are in `src/ccdc`, not in the lab. Every host-collecting command (`listeners`, `firewall status`,
`integrity`, `lse`) crashed before reaching a host with `TypeError: collect() got multiple values for
argument 'run'`: `src/ccdc/batch.py` passes `None, (), None` positionally to `runner.collect(hosts,
archive, variables=None, run=...)`; calling `runner.collect(hosts, path, None, run=..., ...)` fixes it
(verified in a scratch copy). After that, `integrity --auto-apply=simple` fixes the permission issues
(`check` confirms), but `lse` still reports `scanner: Permission denied: .../lib/lse.sh`: the helper drops
to the login account before reading its root-private archive directory, and staging earlier then fails on
temp-dir cleanup. The same LSE failure occurs on the original `lab/` hosts. The current CLI also has no
`ssh` subcommand, so the sshd issues stay open until one exists.

## Limits

- Containers share the **host kernel**: kernel-CVE findings reflect your host, not the guest distro.
- No fileless/kernel-thread/memfd behaviour, no PAM hooks, no preload tricks, no re-planting.
- Not covered: Tiny Core (roadrunner), Arch (porky), NixOS (YSam), OPNsense, Windows.
- Firewall behaviour is container-namespace behaviour (`NET_ADMIN`): close to one host's netfilter, not
  hypervisor- or router-level filtering. `/tmp` is mounted executable, as on the real boxes.
- Images are minimal: Ubuntu's docs are excluded by the base image, which can show up as spurious
  "missing" package-verification rows in integrity scans.
