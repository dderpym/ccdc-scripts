# CCDC access, firewall, integrity + LSE

Bootstrap team SSH access, rotate root passwords, harden SSH, review listening
services, enforce inbound firewall rules, verify packaged system state, and triage
security findings across one Ansible inventory. **Commands target the whole inventory by default.**

- [Quickstart guide](#quickstart-guide)
- [Command reference and internals](#command-reference-and-internals)
- [Disposable local hatchery/tarpit lab](lab/README.md) — intentional package and permission faults, host-loopback services only

## Quickstart guide

### 1. Install the controller tools

Use a trusted Linux/macOS controller with OpenSSH, `uv`, and `tmux` installed.
Install `tmux` through your controller's package manager. If you need `uv`, use
[its official installer](https://docs.astral.sh/uv/getting-started/installation/).
Then, from this repository:

```sh
cd /path/to/berke1337-ccdc       # replace with your actual checkout path
uv sync
. .venv/bin/activate
```

`uv sync` creates `.venv` and installs the versions recorded in `uv.lock`.
The project requires controller Python 3.12+; uv can download a compatible Python
if needed. The only direct Python dependency is `ansible-core`; no extra Ansible
collections are required. Keep `pyproject.toml` and `uv.lock` in version control,
not `.venv`.

Targets need SSH and initial privileged access. The locked Ansible version needs
**target Python 3.9+** after bootstrap. Init installs Python 3 and sudo only if
missing, using the native package manager; it does not upgrade an existing old
Python. Check legacy hosts before competition. Firewall enforcement also needs
`nft` or both IPv4/IPv6 iptables save/restore tools; missing firewall tools are
reported, not installed. Some older Ansible password transports need controller
`sshpass`.

### 2. Set up the inventory and team key

Edit **only `inventory.yml`** for the host list. Replace the sample addresses:

```yaml
all:
  hosts:
    hatchery:
      ansible_host: 192.168.220.70
    tarpit:
      ansible_host: 192.168.220.170
    web01:
      ansible_host: 192.168.220.50
      # ansible_port: 2222       # only if SSH uses a different port
```

Aliases such as `web01` are how you target individual hosts. Use letters, numbers,
`_`, `-`, and `.`; start with a letter, number, or `_`. Do not name a host `all`.
Do **not** set `ansible_user: root` for the normal workflow: bootstrap selects
root itself, and subsequent commands use `oski`.

Keep the team's **private key outside the repository**. Copy its matching public
key into the one configured public-key source:

```sh
# Use your existing team key. Only if you need a new one, generate it once:
# ssh-keygen -t ed25519 -f ~/.ssh/team_ccdc_key -C ccdc-team

cp ~/.ssh/team_ccdc_key.pub files/oski.pub
# If you only have the private key, derive the public key instead:
# ssh-keygen -y -f ~/.ssh/team_ccdc_key > files/oski.pub

# Start an agent if you do not already have a working one:
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/team_ccdc_key
ssh-add -l                     # confirm the team key is loaded
```

The **private key goes into the SSH agent**; the public key goes into
`files/oski.pub`, not the agent. Enter the private key's passphrase when asked.
Do not leave the placeholder public key in place.

Verify each host's SSH fingerprint through a trusted console/competition source
and add the verified key to your controller's `~/.ssh/known_hosts`. For example,
for a host with an Ed25519 host key:

```sh
mkdir -p ~/.ssh
chmod 700 ~/.ssh
ssh-keyscan -t ed25519 -p 22 192.168.220.70 > /tmp/ccdc-hostkey
ssh-keygen -lf /tmp/ccdc-hostkey
# STOP: compare this fingerprint with the trusted fingerprint.
# Only after it matches:
cat /tmp/ccdc-hostkey >> ~/.ssh/known_hosts
chmod 600 ~/.ssh/known_hosts
```

Repeat for every inventory address and its actual SSH port. Use the host's
supported key type if it lacks Ed25519. **A scan alone is not verification.**
Host-key checking stays enabled; do not work around failures by disabling it.

### 3. Start tmux and bootstrap with the default root password

Start a persistent competition terminal from the repository:

```sh
tmux new-session -s ccdc
```

You are now inside tmux, initially with one shell pane. Activate the environment
in that shell and run bootstrap:

```sh
. .venv/bin/activate
./scripts/ccdcctl init all --save-bootstrap-password
```

At this prompt, type the known competition **default root password** and press
Enter. Nothing is echoed:

```text
Known bootstrap root password (saved controller-side):
```

The password is saved to `secrets/bootstrap.password` and tried on each host. If
one host rejects it, enter that host's actual root password at its hidden retry
prompt, or press Enter without typing to skip it. Connection/timeouts/host-key
errors do not trigger password guessing.

For each successfully initialized host, init:

1. Creates `oski`, installs the team public key, and grants passwordless sudo.
2. Proves a **fresh key-only `oski` login and sudo escalation**.
3. Generates an independent random **10-character root password** and saves it
   before changing the host's password.

Review `INIT SUMMARY`; repair failed/skipped hosts before continuing. Recovery
files are `secrets/root/<inventory-host>.password`, mode 0600 and gitignored.
They are **plaintext**: protect the controller disk and copy them into the team's
password manager. Previous values are retained as backups. A failed init may
leave a saved candidate that is not active; do not discard older recovery files.

### 4. Secure the network and accept reviewed baselines

Keep VM/physical console access available. Run these commands in your tmux pane,
one at a time, checking each summary before proceeding:

```sh
./scripts/ccdcctl ping all
./scripts/ccdcctl ssh configure all
./scripts/ccdcctl listeners all
```

For key-only SSH, choose `a` on the first host to disable password authentication
on the remaining hosts too; press Enter to reuse that choice on later hosts and
confirm each apply. If scoring/users require password SSH, choose `y` for one
host or `b` for the remaining hosts instead. **Root SSH login is always disabled
by SSH hardening**, regardless of that choice.

Read `reports/listeners.txt` and hand it to teammates to identify scoring-critical
services. Then review firewall decisions:

```sh
./scripts/ccdcctl firewall configure all
```

TCP/22 is preapproved. Other listening ports default to **blocked**: explicitly
allow the services scoring needs, including UDP where relevant and any other
active SSH ports. `y` allows a service on this host; `a` reuses an allow decision
for matching services on remaining hosts. Include each reviewed host with `y`,
then read the aggregate policy and explicitly confirm `y` to apply it. The final
default is **abort**, not apply. Do not approve blindly: ports not currently
listening, such as future/dynamic application ports, need separate consideration;
skip hosts whose requirements this port-only policy cannot safely represent.

Check the results, then explicitly accept the trusted state:

```sh
./scripts/ccdcctl ssh status all
./scripts/ccdcctl firewall status all
./scripts/ccdcctl ssh baseline all
./scripts/ccdcctl firewall baseline all
```

Do not baseline an unexplained or failed configuration. Firewall enforcement is
**runtime-only**: it must be reapplied after reboot. Monitoring does not fix drift.
Root recovery passwords are for console/login or `su` where permitted, **not a
root SSH backdoor after hardening**.

### 5. Triage current vulnerabilities and start the combined monitor

Beginning-of-competition workflow (review and baseline **only** SSH/firewall as
explained above):

```sh
./scripts/ccdcctl init
./scripts/ccdcctl ssh configure
./scripts/ccdcctl firewall configure
./scripts/ccdcctl ssh baseline       # only after reviewing effective policy
./scripts/ccdcctl firewall baseline  # only after reviewing effective policy

# Find non-stock/tampered system state:
./scripts/ccdcctl integrity
# Find high-confidence dangerous Linux configuration:
./scripts/ccdcctl lse

# Teammates investigate and remediate findings, then run continuously:
./scripts/ccdcctl monitor
```

Integrity and LSE are **not baseline-driven**. An initially compromised binary
or dangerous sudo/persistence condition remains a finding until fixed. Each
new scan evaluates current state; it never accepts the initial vulnerability as
trusted. Detection does not perform repairs. Detailed evidence is saved under
`reports/<host>/`; terminal output is severity-ranked and capped at 40 findings
per host, with remaining findings available in JSON.

The combined monitor uses independent workers: SSH/firewall default to 10s,
integrity to 60s, and LSE to 180s. A slow LSE run does not hold up SSH/firewall.
Startup lists intervals; afterwards it prints only new/changed/resolved findings
or scanner/connectivity failures, not periodic `OK` lines.

### 6. Optional separate tmux views

Use the combined monitor above for all four modules. The following optional
three-pane arrangement focuses on the existing network views; it does **not**
include integrity/LSE unless you run the combined monitor in another window.
The three views use existing commands, not a separate dashboard application:

```text
+--------------------------+--------------------------+
| SSH drift alerts         | Firewall drift alerts    |
+--------------------------+--------------------------+
| Refreshing listener / service inventory             |
+-----------------------------------------------------+
```

**How tmux keys work:** press `Ctrl+b`, release both keys, then press the indicated
key. The prefix is not held down while typing the second key.

Starting from your single setup pane:

1. `Ctrl+b`, then `"` (double quote): split into top and bottom. You land below.
2. `Ctrl+b`, then Up Arrow: return to the top pane.
3. `Ctrl+b`, then `%`: split the top into left and right. You land on the right.
4. `Ctrl+b`, then Left Arrow: select the top-left pane.

In **each pane**, ensure you are in the repository and activate `.venv`. Replace
the checkout path in these examples with yours.

**Top-left — SSH baseline drift:**

```sh
cd /path/to/berke1337-ccdc
. .venv/bin/activate
./monitor/ssh-monitor --interval 30
```

Select the top-right pane with `Ctrl+b`, then Right Arrow.

**Top-right — firewall baseline drift:**

```sh
cd /path/to/berke1337-ccdc
. .venv/bin/activate
./monitor/firewall-monitor --interval 30
```

Select the bottom pane with `Ctrl+b`, then Down Arrow.

**Bottom — current listener inventory, refreshed every minute:**

```sh
cd /path/to/berke1337-ccdc
. .venv/bin/activate
while :; do
    clear
    date
    ./scripts/ccdcctl listeners all
    sleep 60
done
```

The first two panes print `Monitoring ...` and then stay **quiet when healthy**.
They alert on drift, failed discovery/unreachability, and missing baselines;
recoveries are announced. The third pane is a **live snapshot**, not a third
drift detector: it refreshes `reports/listeners.txt` and `.json`, with no listener
baseline or change alerts. It runs read-only discovery, not firewall changes.

#### tmux survival guide

| Keys / command | What it does |
| --- | --- |
| `Ctrl+b`, Arrow | Move to the pane in that direction |
| `Ctrl+b`, `o` | Cycle through panes |
| `Ctrl+b`, `z` | Zoom/unzoom the current pane |
| `Ctrl+b`, `[` | Enter scrollback; use arrows/Page Up, then `q` to leave |
| `Ctrl+b`, `c` | Open another shell window without stopping monitors |
| `Ctrl+b`, `w` | List/select windows |
| `Ctrl+b`, `d` | Detach; processes keep running |
| `tmux attach-session -t ccdc` | Reattach from an outside terminal |
| `tmux list-sessions` | Find running sessions |
| `Ctrl+c` (no tmux prefix) | Stop the foreground monitor/loop in this pane |

For a long listener report, zoom the bottom pane or open another window and run
`less reports/listeners.txt` from the repository (`q` exits less). Detaching does
not stop monitoring, but shutting down the controller does. Do not use `exit` or
kill panes to detach. These keys assume tmux's default bindings.

## Command reference and internals

### Targets, environment, and authentication

Run commands from the repository with the uv environment active:

```sh
uv sync
. .venv/bin/activate
./scripts/ccdcctl ssh status
```

Alternatively, `uv run ./scripts/ccdcctl ssh status` supplies the environment
without shell activation; it also makes Ansible available to child processes.
The same works for wrappers: `uv run ./monitor/ssh-monitor --interval 30`.

`all` is the default for commands accepting a target. An exact **inventory alias**
can be used instead, such as `hatchery`; IP addresses, arbitrary Ansible patterns,
and groups other than `all` are not CLI targets. Hosts are re-enumerated using
`ansible-inventory`; there is no second host list. Monitors use `--host`, not a
positional host argument.

| Operation | SSH authentication | Privilege |
| --- | --- | --- |
| First saved-password init | Root password from the private bootstrap file, with one manual retry on authentication failure | Already root; sudo bypassed |
| Saved-host init rerun | Fresh `oski` key/sudo check first; if that fails, the saved per-host root password, then at most one manual retry | Sudo as `oski`, or already root |
| Manual init | Your supplied Ansible bootstrap user/key/password options | Root directly or your administrator's escalation |
| Ping, status, listeners, baselines, monitors, firewall rollback | Configured SSH user, normally `oski`, using the team key from the controller agent or inventory key path | Sudo, passwordless after init |
| SSH/firewall configuration safety checks | Explicit fresh, key-only `oski` login, bypassing multiplexing and password authentication | Passwordless sudo to root |

Ansible owns SSH transport. `ansible.cfg` defaults to `oski` with sudo escalation;
normal sessions may multiplex connections. Private keys are used **locally** by
the SSH agent, never copied to targets. Agent forwarding is disabled. Host keys are
checked against the controller's trusted known-hosts database. An inventory
`ansible_ssh_private_key_file` can select a team private key instead of the agent.

Inventory connection variables can override defaults. Remove stale
`ansible_user: root`/bootstrap privilege variables after setup, and do not keep
bootstrap overrides in `ANSIBLE_ARGS`. The safety preflights force a new `oski`
connection: a surviving cached session is not evidence that a new login works.

`ANSIBLE_ARGS` is shell-split into **trusted** transport/privilege options; it is
not a second inventory or a place for alternate inventory/limit arguments. Keep
passwords out of argv/history. Credential-bearing controller extra-vars use
private temporary files, removed after the subprocess exits.

**Security tradeoff:** `oski` has `NOPASSWD: ALL`, so a stolen team private key
is effectively root access. Unique root passwords prevent shared-password reuse;
they do not evict existing root sessions, remove attacker keys/persistence, or
prevent keylogging on an already-compromised host.

### `init [host|all]`: access bootstrap and root rotation

```sh
./scripts/ccdcctl init all --save-bootstrap-password
./scripts/ccdcctl init hatchery
./scripts/ccdcctl init all --bootstrap-password-file ~/.config/ccdc/bootstrap.password
```

- `--save-bootstrap-password` requires a terminal, asks once through a hidden
  prompt, and saves the known shared root password. Default: `secrets/bootstrap.password`.
- `--bootstrap-password-file PATH` reads a single nonempty password from a regular
  file owned by you with no group/other permissions (use mode 0600). Plaintext and
  Ansible Vault-encrypted single-password files are supported; this is **not** a
  YAML `ansible_password:` variables file.
- If the default file exists, plain `init` uses it automatically. On saved-host
  reruns it first tries `oski`; if root fallback is necessary, the host's saved
  recovery password replaces the automatic shared-password attempt.
- Only one password is attempted automatically per host. An authentication
  rejection offers one hidden manual retry; empty input skips the host. There is
  no retry for timeouts, host-key errors, or mutation/task failures. Noninteractive
  runs do not offer root-password retries. Remaining hosts still get processed.

The init role validates the public key, installs Python/sudo only when absent,
creates `oski` and its home/key permissions, adds the appropriate sudo/wheel group,
and writes a validated, narrowly owned sudoers file. Existing authorized keys
are preserved. Init does not rewrite SSH access restrictions; if AllowUsers,
groups, or account restrictions block `oski`, repair them using authorized
bootstrap/console access.

Before root rotation, a controller-side Ansible subprocess proves fresh `oski`
key authentication plus passwordless sudo. Each init generates a new independent,
cryptographically random 10-character alphanumeric password per host. It writes
`secrets/root/<host>.password`, retains the previous copy as a timestamped Ansible
backup, and flushes the files/directory to disk **before** sending the password to
native `chpasswd` through encrypted SSH stdin. Secret-bearing tasks use `no_log`;
the password is not printed or passed in argv. Directories are mode 0700 and
files are mode 0600, all gitignored.

A successful `INIT SUMMARY` means the update completed. Failure/interruption may
leave a **pending candidate** in the latest file; retain previous backups. Hosts
that reject 10-character passwords fail without weakening their password policy.
Protect/encrypt the controller disk and back up recovery credentials separately.
**Gitignore and permissions do not encrypt these plaintext recovery files.**

#### Vault storage for the bootstrap password

```sh
ansible-vault encrypt secrets/bootstrap.password
ansible-vault edit secrets/bootstrap.password
```

Loading invokes `ansible-vault view` with your configured Vault identity/unlock
prompt. Configure an identity (for example, `ANSIBLE_VAULT_PASSWORD_FILE` pointing
to a separately protected file) for unattended use. `--save-bootstrap-password`
refuses to replace an encrypted file with plaintext. Vault-encrypting the bootstrap
file does **not** encrypt the separately generated root recovery files.

#### Initial access through an existing administrator or key

Ignore saved root credentials and use normal Ansible options:

```sh
ANSIBLE_ARGS='-u root --ask-pass -e ansible_become=false' ./scripts/ccdcctl init all --no-bootstrap-password
ANSIBLE_ARGS='-u admin --ask-pass --ask-become-pass' ./scripts/ccdcctl init all --no-bootstrap-password
ANSIBLE_ARGS='-u root --private-key /path/to/bootstrap_key -e ansible_become=false' ./scripts/ccdcctl init all --no-bootstrap-password
```

The **team** private key must separately be available through the agent or
inventory for the `oski` proof. Without a saved default file or explicit
password-file option, `init` also falls back to normal Ansible authentication.
Do not combine saved-root mode with Ansible password-prompt flags.

An equivalent manual playbook is:

```sh
ansible-playbook playbooks/init.yml -u root --ask-pass -e ansible_become=false
```

It also performs the `oski` proof and root rotation. Init does not change SSH
policy; `ssh configure` later disables root SSH. Recovery needs console/login
or `su` access where permitted, not simply `ssh root@host` after hardening.

### `ping [host|all]`: verify administrative transport

```sh
./scripts/ccdcctl ping
./scripts/ccdcctl ping hatchery
```

Runs Ansible's `ping` module through SSH with configured escalation. This checks
SSH authentication, target Python/module execution, and sudo; **it is not ICMP
ping**, a port scan, or a scoring-service health check. It is not the explicit
fresh-login safety preflight, so it may use a multiplexed connection.

### `ssh status|configure|baseline [host|all]`

```sh
./scripts/ccdcctl ssh status                 # inventory summary
./scripts/ccdcctl ssh status hatchery        # full normalized JSON
./scripts/ccdcctl ssh configure all
./scripts/ccdcctl ssh baseline all
```

**Status** executes SSH discovery under sudo. Effective settings come from
`sshd -T`, not config-file greps. Discovery includes configuration sources and
context details without timestamps; inspect per-host JSON for Match policies and
active systemd SSH socket bindings separately from `sshd -T`.

**Configure** is interactive and sequential. It always sets root login to `no`
and public-key authentication to `yes`. Password and keyboard-interactive auth
are changed together. Choices allow per-host enable/disable/skip and reuse on
remaining hosts, still with overrides and confirmation.

An owned marked block at the **top** of `/etc/ssh/sshd_config` takes precedence
over original global settings, including on older OpenSSH without server Include
support. The legacy ChallengeResponseAuthentication setting is aligned. Other
files and the original configuration below the block are preserved. Candidates
are checked with `sshd -t`, then `sshd -T` globally and in admin/root contexts;
validation/reload failures restore the prior configuration. Conflicting Match
policies require explicit repair, not silent mass editing.

Reload handles systemd `ssh`/`sshd`, stock Alpine OpenRC defaults, and Void runit,
without routine restarts. Custom startup config/port/auth overrides are refused.
Socket-activated SSH supports these authentication-only changes; socket bindings
are not edited. Fresh key-only `oski`/sudo checks run before and after changes,
and the effective state is rediscovered. Keep console access available.

**Baseline** saves the currently observed SSH state to
`baselines/<host>/ssh.json`. It does not configure or validate your security
judgment: accepting a malicious state would make it the expected state.

### `listeners [host|all]`: service inventory

```sh
./scripts/ccdcctl listeners
./scripts/ccdcctl listeners hatchery
```

Runs listener discovery under sudo, prints the report, and replaces:

- `reports/listeners.txt`: teammate-readable bindings, process/PID, executable,
  user, and best-effort service attribution/confidence.
- `reports/listeners.json`: structured results and explicit per-host errors.

These reports contain the selected hosts, not an accumulating historical union.
A non-loopback binding is an **exposure candidate**, not proof of firewall/routing
reachability. Ownership may be unknown; confidence is not invented. Discovery
falls back from `ss` to `netstat`, `lsof`, then `/proc`, without installing tools.
It sees the host's current network namespace, not separate container namespaces.
The quickstart's third pane simply reruns this command; it does not baseline or
alert on listener changes.

### `firewall status|configure|rollback|baseline [host|all]`

```sh
./scripts/ccdcctl firewall status
./scripts/ccdcctl firewall status hatchery
./scripts/ccdcctl firewall configure all
./scripts/ccdcctl firewall rollback hatchery
./scripts/ccdcctl firewall baseline all
```

**Status** runs privileged discovery for nftables, iptables, firewalld, and ufw.
Full JSON includes INPUT policies, literal TCP/UDP ACCEPT candidates with
conditions, and normalized rules. For arbitrary existing rules, `null` means
**unknown**, not closed or open: earlier drops, source restrictions, or other
hooks can defeat an ACCEPT. Exact dual-stack summaries are verified for our owned
policy.

**Configure** gathers listeners and existing firewall state, then collects and
reviews **all selected host decisions before applying any**. TCP/22, loopback,
established/related flows, and essential IPv6 router/neighbor discovery (ICMPv6
133–136) are allowed. Other unsolicited inbound traffic is blocked unless you
approve its ports. Unsolicited echo is blocked; outbound traffic is unrestricted.

Listeners are grouped by service/process/executable. Bulk reuse requires matching
identity **and** protocol/ports, and can be overridden; unknown owners are not
assumed equivalent. The aggregate preview includes services that will be blocked.
Final confirmation defaults to abort. Application is one host at a time; listener
changes since review require a new review. All configured SSH ports must be
approved, and the role separately protects the actual server-side connection
port, including socket activation/NAT.

Enforcement requires fresh `oski` access and a controller-side rollback snapshot.
It refuses active managers, mixed/ambiguous backends, and unsafe configurations:

- **nftables replaces the entire ruleset atomically**; unsafe NAT/forward/output
  hooks are refused rather than discarded silently.
- **iptables inserts an owned first INPUT jump**, preserving unrelated policy.
- Prior source restrictions do not carry over: approved ports are open to **all
  sources**, for both IPv4 and IPv6.

Do not stack managers or silently disable ufw/firewalld. Migrate them explicitly
with console access, or manage that host separately. Fresh admin access and
observed firewall state are checked after application.

**Rollback** restores the latest pre-apply snapshot at
`reports/rollback/<host>/firewall.json`, not a monitoring baseline. Snapshots are
sensitive and gitignored; retain an independent controller copy. Rollback still
needs working SSH/sudo. If SSH is already blocked, use the console; there is no
timer-based automatic rollback daemon.

**Baseline** accepts current discovery into `baselines/<host>/firewall.json`.
It neither changes rules nor provides rollback. Enforcement is **runtime-only**,
not a distro-specific boot firewall manager: reapply after reboot.

### `integrity [status] [host|all] [--deep]`

```sh
./scripts/ccdcctl integrity
./scripts/ccdcctl integrity hatchery
./scripts/ccdcctl integrity status hatchery --deep
./scripts/ccdcctl monitor integrity
make integrity HOST=hatchery
```

Uses native package-manager verification plus a small critical-file metadata
check. Its source of truth is the operating system/package database, **not an
initial competition baseline**. Anything differing from known package/system
state remains visible until fixed. There is no integrity baseline command.

Normal verification uses Alpine `apk audit --system --check-permissions` (with
installed-option detection), plus a bounded native `--backup` audit of `/etc`
because `--system` skips protected configuration contents. Added-file codes from
that configuration pass are discarded; vendor config differences remain findings.
RPM systems use `rpm -Va --noscripts` (never verifier scripts), Debian/Ubuntu
use `dpkg --verify` (no debsums dependency), and Void uses XBPS file verification.
Unsupported options, verification errors, and timeouts produce warnings, not a
false clean result. XBPS verification uses a temporary metadata copy inside a
private mount namespace because its verifier can write/convert the database;
without namespace privileges it reports incomplete coverage rather than touching
the live database. Coverage differs by distribution: dpkg in particular cannot
verify all metadata. The bounded critical-path check supplements that with
numeric UID/GID, mode, file type, and symlink metadata; conservative security
rules are explicit checks, not learned first-run values.

Modified privileged executables and dangerous ownership/mode changes are
`CRITICAL`; important security configurations are `WARNING`; ordinary package
configuration differences are `REVIEW`. Configuration differences are never
permanently suppressed, including intentional SSH changes made by this repo.
Investigate rather than blindly restoring scoring configurations.

`--deep` is a manual expanded audit: Alpine may use `--full` to include added
files. Normal polling uses neither `--full` nor `--details`. Other package
managers already verify their installed package set. Raw evidence and normalized
records replace `reports/<host>/integrity/{raw.txt,report.json}` each scan.
No scan executes reinstall/fix/restore commands or automatically changes modes,
owners, or package-owned configuration. A compromised package database/verifier
can lie; corroborate serious findings through a trusted console/vendor source.

### `lse [status] [host|all] [--deep]`

```sh
./scripts/ccdcctl lse
./scripts/ccdcctl lse hatchery
./scripts/ccdcctl lse hatchery --deep
./scripts/ccdcctl monitor lse
make lse HOST=hatchery
```

Provides a high-signal security and privilege/persistence triage pass using the
pinned, vendored Linux Smart Enumeration script: version **4.14nw**, commit
`fcad39438dc10ac8a8e9c2e2800bf3864c6ab826`, GPL-3.0. See
[`vendor/LSE-PROVENANCE.md`](vendor/LSE-PROVENANCE.md) for upstream and license.
The scanner never downloads executable code.
The default run uses only LSE's highest-priority (level-0) findings, no color,
noninteractive operation, and no process-watching delay. Only affirmative
security tests are summarized; informational enumeration stays out of the live
terminal. Stable test IDs and normalized context identify findings where possible.
LSE runs as the configured login account (normally `oski`), **without become**:
root readability/writability is not evidence of an unprivileged escalation.
The team's intentionally passwordless sudo is still reported for review, not
silently accepted. Only selected level-0 tests and required dependencies execute
normally; manual deep mode also selects actionable level-1 tests. Process-watcher
tests are excluded because this pinned version would wait with `-p 0`.
Missing optional utilities and BusyBox `find` lacking `-writable` generate explicit
coverage warnings; other tests still run. Install compatible tools separately if
full coverage is needed. Coverage warnings do not resolve previously detected
conditions for affected tests, but do not block unrelated resolutions.

`--deep` runs level 1 for a more thorough manual investigation, not the normal
monitor loop. Complete human-readable output replaces `reports/<host>/lse.txt`
and `reports/<host>/lse/raw.txt`; parsed records replace
`reports/<host>/lse/report.json`. Reports can contain sensitive data and are
private/gitignored. LSE is triage, not a proof that the host is secure.

Findings are **not baselined or accepted as normal** merely because they were
present when the competition started. There is no LSE baseline command.
The workflow for both scanners is **finding → investigate/fix → next scan verifies
it is gone**, not first scan → accept vulnerability → ignore forever.
Scanner commands return nonzero for findings or incomplete/failed scans.

### `monitor [ssh|firewall|integrity|lse]`: polling and alerts

```sh
./scripts/ccdcctl monitor                          # all four, independent schedules
./scripts/ccdcctl monitor ssh --interval 30
./scripts/ccdcctl monitor firewall --host hatchery
./scripts/ccdcctl monitor integrity
./scripts/ccdcctl monitor lse --host hatchery
./scripts/ccdcctl monitor ssh --host hatchery --once
./monitor/ssh-monitor --interval 30                # existing wrapper
./monitor/firewall-monitor --interval 30           # existing wrapper
make monitor
```

Omitting the kind monitors all four. `--host` defaults to `all`. Set intervals in
inventory `all.vars` or individual host variables:

```yaml
ssh_poll_interval: 10
firewall_poll_interval: 10
integrity_poll_interval: 60
lse_poll_interval: 180
```

These are also the defaults. `--interval SECONDS` explicitly overrides all
selected modules; intervals must be 5..86400 seconds. Each module has its own
worker and schedule; scans never overlap themselves, and a slow scan does not
block other modules. The inventory is refreshed periodically. `--once` scans
each selected module once and returns nonzero if active alerts exist.

SSH/firewall alone compare effective policy with reviewed controller baselines.
Integrity/LSE repeatedly evaluate current known-good/security state. Runtime
alert deduplication suppresses repeat **terminal messages**, not findings: status
and latest reports still show persistent conditions. New or materially changed
findings alert immediately; disappeared findings emit one `RESOLVED` event.
A failed/incomplete scan does not claim previous findings were fixed. Scanner
and connectivity failures are deduplicated too. Restarting rediscovers all
current findings; no persistent integrity/LSE acceptance state is stored.

Healthy hosts are quiet. This is state polling, not login-log auditing,
service health monitoring, or automatic remediation. New hosts need init and
explicit reviewed **SSH/firewall only** baselines. Those baselines never
auto-update; failed baseline commands leave previous trust intact. After a
legitimate SSH/firewall policy change, inspect status before explicitly accepting
it; do not hide unexplained drift by rebaselining.

### Make aliases and controller files

`make ping/init/ssh/listeners/firewall/integrity/lse/baseline/monitor` wrap the corresponding
commands. `make ssh HOST=hatchery` targets one inventory alias. `make baseline`
accepts **both** SSH and firewall state; use it only after review. First-run
password storage uses the explicit CLI flag from the quickstart, not `make init`.
Use an activated environment, or `uv run make ping` / `uv run make test`.

| Path | Purpose |
| --- | --- |
| `inventory.yml` | The only host inventory |
| `files/oski.pub` | The team public key installed on targets |
| `ansible.cfg` | Default transport, user, privilege and host-key policy |
| `secrets/bootstrap.password` | Shared initial root credential; optionally Vault encrypted |
| `secrets/root/<host>.password` and backups | Plaintext generated recovery passwords |
| `reports/listeners.{txt,json}` | Latest selected-host listener inventory |
| `reports/rollback/<host>/firewall.json` | Latest pre-apply firewall snapshot |
| `baselines/<host>/{ssh,firewall}.json` | Explicitly accepted SSH/firewall monitoring state only |
| `reports/<host>/{integrity,lse}/{raw.txt,report.json}` | Latest raw evidence and current normalized findings |
| `reports/<host>/lse.txt` | Latest human-readable LSE report |
| `vendor/lse.sh` | Pinned upstream security triage script; never downloaded at runtime |

Private keys belong outside the repository. Secrets, report contents, baselines,
and `.venv` are gitignored; the placeholder directory markers remain tracked.

### Scope and validation

Host families: Debian/Ubuntu, CentOS/Rocky/RHEL-compatible, Alpine/OpenRC, and
Void/runit, with working repositories when bootstrap prerequisites are missing
and target Python compatible with the locked Ansible release. Do not assume
systemd. Test representative distro/init VMs before competition; offline checks
do not establish compatibility with every legacy release.

There are no automatic package upgrades/repairs, kernel/application/database
hardening, CVE scanning, dashboards, SIEM, antivirus, or generic malware scans.
LSE provides bounded security/persistence triage, not automatic remediation.
Delegate repairs using scanner evidence and the listener inventory. Init's missing Python/sudo prerequisites are its only package
installations; firewall forwarding/NAT and unrelated policy are not targets.

```sh
uv sync --locked
uv run make test
uv run ansible-playbook playbooks/init.yml --syntax-check
uv run ansible-playbook playbooks/ssh.yml --syntax-check
uv run ansible-playbook playbooks/firewall.yml --syntax-check
uv run ansible-playbook playbooks/lse.yml --syntax-check
```

Tests do not contact sample inventory hosts or change real root passwords.
Kernel firewall checks mutate rules only inside new user/network namespaces
when `unshare`, `nft`, and dual-stack iptables tools are available; otherwise they
are explicitly skipped. Root-rotation integration uses a fake password tool.
Review dependency upgrades before competition; `uv lock --upgrade-package
ansible-core` refreshes the lockfile within the supported version range, and
`uv sync` installs it. Do not hand-edit `uv.lock`.
