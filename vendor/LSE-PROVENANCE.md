# Linux Smart Enumeration (LSE)

- Upstream: https://github.com/diego-treitos/linux-smart-enumeration
- Author: Diego Blanco <diego.blanco@treitos.com>
- Version/tag: **4.14nw**, commit **fcad39438dc10ac8a8e9c2e2800bf3864c6ab826**
  (2023-12-23). This is the repository source, not a release bundle with CVE payloads.
- Source: https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/fcad39438dc10ac8a8e9c2e2800bf3864c6ab826/lse.sh
- License: GNU GPL version 3; unmodified upstream license in `LSE-LICENSE`.
- Local modifications to `lse.sh`: **none**. Wrapper filtering is separate.
- SHA-256 `lse.sh`: `a0c526f560189c81bc66303b81e828edabc68deed7e7bd28aed55a792c6d25c3`
- SHA-256 `LSE-LICENSE`: `3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986`

## Invocation and scope

`scripts/discover-lse --script vendor/lse.sh [--deep]` uses Python 3 stdlib
and `/bin/sh`. It runs the local file with **`-c -i -l 1 -p 0 -s SELECTION`**;
`--deep` expands the selection, never requesting output level 2. These flags are verified
against this pinned source's `lse_help` and `getopts`: color disabled,
noninteractive, important/interesting verbosity, zero-second process watch,
explicit selected tests. No fetch, self-update, CVE exploit bundle, packet
capture, serving mode, or general inventory selection is used.

The allowlist in `discover-lse` focuses on writable privileged files, cron and
services, unusual setuid binaries, exposed credentials, weak local database
authentication, dangerous NFS exports, extra UID-zero accounts, and container
administrative groups. Inventory prerequisites (`usr070`, `fst000`, `fst010`,
`sec010`) run to populate upstream variables but never appear as findings.
Normal mode selects 30 reportable checks and these four prerequisites, including
promoted level-1 checks for UID-zero accounts (`sys040`) and writable cron paths
(`ret050`). Output level 1 preserves their evidence without selecting unrelated
tests. Deep mode additionally selects ownership anomalies and MongoDB connection
checks: output level alone does not prevent upstream from executing level-1 tests.

Only affirmative (`yes!`) allowlisted tests with nonempty actionable evidence
are emitted. `nope`, `skip`, informational tests, banners, inventory, and
comments are excluded. Repeated IDs (upstream uses `sof020` four times) share
one finding with independent `{summary, evidence: [lines]}` context entries;
identical entries alone are deduplicated. Findings and contexts are stable
sorted. ANSI, listing mtimes/sizes, ISO timestamps, runtime counters, and
nonessential labeled PIDs/screen-socket PIDs and MongoDB sizes are removed/normalized.
The PostgreSQL context title's upstream `psql` typo is corrected to `pgsql`,
matching the actual selected command. `sys030` retains readable
shadow **paths**, not a dump of every password hash. Normal locked accounts
from `sys020`/`sys022` and commented NFS exports are not vulnerabilities.
Upstream `srv010` and `srv510` have malformed shell loops and are deliberately
not selected; no local upstream patch is hidden here. Setgid checks are also
omitted because this source misplaces its output-variable argument.

Findings are **review candidates**, not automatic fixes. Run as the account
whose access is being assessed (the playbook disables become). Permission
findings are suppressed if upstream reports UID 0, since root readability
and writability are expected; `errors` includes a coverage warning in that case.
Passwordless sudo for the team's oski account is expected after bootstrap.
Its `sud000` evidence is retained in raw output but excluded from normalized
findings when the effective account, resolved by UID rather than environment or
banner text, is `oski`. Other or unknown accounts retain the critical finding.
This is explicit repository policy, not an accepted initial baseline.
Missing find/getcap/sudo and unsupported find `-writable` (notably BusyBox) yield
explicit coverage warnings. `incomplete_ids` identifies affected tests so the
monitor retains their previous findings without preventing resolution of other
successfully scanned conditions. Use compatible utilities for full coverage;
the scanner does not install them. Database tests query
metadata using the default client connection configuration; existing saved
credentials, peer/socket authentication or configured hosts can affect them,
so "without a supplied password" does not prove unauthenticated remote access.
No secrets are requested on stdin. Complete raw output is retained separately from normalized findings, including
banners, inventory prerequisites, and diagnostic stderr. Raw reports may contain
password hashes and credentials from mount configuration/history: keep controller
results private.

## Passive supplemental checks

Original Python helpers `scripts/lse_extras.py`, `scripts/lse_host_risks.py`,
`scripts/kernel_risks.py` and `scripts/package_risks.py` add a curated subset
of LinPEAS coverage gaps to the same result. LSE itself is
still unmodified; its parser/allowlist contract below remains unchanged. See
[LINPEAS-GAPS.md](LINPEAS-GAPS.md) for the pinned comparison, implemented checks,
remaining gaps, kernel rule sources and limits. Supplements do not run LinPEAS,
execute exploits, probe AF_ALG, load modules, contact runtime/agent APIs or
download code. `sudo -n -l` and `doas -C` only list/match policy, never execute
a delegated command. Trusted native `systemctl` and package utilities only read
metadata. Credential supplements retain permission paths, never secret contents.
Kernel checks use running metadata; permission checks assess the actual effective
account and preserve scoped incomplete coverage when run as root or unavailable.
A private `getcap` forwarding shim records the native exit status while preserving
LSE stdout, with no second filesystem enumeration. This distinguishes an empty
successful capability inventory from LSE's indistinguishable `nope` failure output.

## Result and transport contract

Wrapper stdout is exactly one JSON object:

```
{"findings": [{"id": "fst210", "severity": "critical", "summary": "...",
               "context": [{"summary": "upstream test title", "evidence": ["..."]}]}],
 "raw": "complete scanner stdout and stderr", "errors": []}
```

stderr warnings, nonzero scan exits, and the 180-second deadline become `errors`
without discarding partial findings or failing the wrapper process. A deadline
kills the entire scan process group. LSE scratch files use a private temporary
directory, removed even after timeout. Missing optional utilities can produce
upstream `nope`/`skip`; upstream suppresses many command errors, so an empty
result is **not** a proof of a secure or fully inspected host.

Controller integration must invoke **`playbooks/lse.yml`**, not the existing
ad-hoc `collect('lse')` script transport: pinned source, license and helpers need transfer. The playbook
creates a mode-0700 directory, copies vendor script/license and wrapper as
mode-0600 files, uses the Ansible-selected/discovered Python interpreter,
also transfers the passive supplemental helpers, registers **`ccdc_lse_result`**,
and always removes the directory. No role is
needed. `lse_deep: true` (a boolean extra-var) enables the deeper mode.

By default, `ccdc_results` overwrites each per-host result on every callback;
registration alone does not protect a scan result from cleanup. The controller
can now filter successful tasks with `CCDC_RESULT_TASK`. The playbook's **last
task**, named exactly **`Collect LSE security state`**, republishes
`ccdc_lse_result.stdout` through a small Python command, after cleanup,
preserving top-level `stdout` and `rc`. This works both with the controller's
`CCDC_RESULT_TASK="Collect LSE security state"` filter and without a filter.
Deployment failures are rescued into the same JSON `errors` shape; cleanup
failures/unreachable hosts remain Ansible failures. Keep publication last.

Parent/controller should run `ansible-playbook playbooks/lse.yml --limit ...`
with its existing `CCDC_RESULT_DIR`, enabled `ccdc_results` callback, and
`CCDC_RESULT_TASK="Collect LSE security state"` if filtering, read
each `<result_dir>/<inventory_hostname>`, reject unreachable/failed/nonzero-rc
transport results, then decode **`response['stdout']`** as JSON. Also surface
the decoded scan `errors` (a successful transport may contain scan warnings).
Check mode does not scan or publish. Controller reporting and monitoring consume normalized findings, not raw output.
