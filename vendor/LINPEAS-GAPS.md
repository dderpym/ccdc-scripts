# LinPEAS → LSE coverage comparison and passive additions

## Source snapshot

Compared against **PEASS-ng commit `5bdfc78c7b93373237db0e39c8a669ea7eb04159`**
(2026-10-06), specifically [`linPEAS/builder/linpeas_parts`](https://github.com/peass-ng/PEASS-ng/tree/5bdfc78c7b93373237db0e39c8a669ea7eb04159/linPEAS/builder/linpeas_parts).
LSE is our unchanged **4.14nw** source pin; see [LSE-PROVENANCE.md](LSE-PROVENANCE.md).
This is a Linux-server feature/check-family comparison, not a promise to cover
every LinPEAS check. Generated credential/GTFOBins catalogs were not available
in the source checkout; their unresolved `peass{...}` placeholders are not used
as a vulnerability database. macOS/Android-specific checks are outside this repo's scope.

**No LinPEAS shell code, executable, generated bundle, or exploit is vendored or
executed.** The added Python checks are original metadata-only implementations
of selected ideas, not a second full enumeration scanner. No added dependencies.

## What LinPEAS adds

“LSE omitted” means upstream already has a check, but our wrapper doesn't select
or promote it. “Absent” means that analysis is missing even from upstream LSE.
Source paths below are relative to `linPEAS/builder/linpeas_parts/` in the pin above.

| Check family | LSE relationship | Disposition / LinPEAS sources |
| --- | --- | --- |
| Known kernel privilege-escalation CVEs | LSE has a CVE framework, but our source pin's `lse_cve_list` is empty; no packaged CVE rules | **Added small passive subset:** Copy Fail, Dirty Pipe, nftables, net/sched and ESP rules. `functions/checkCopyFail.sh`, `variables/kernel_cve_registry_data.sh`. Not a full CVE scanner. |
| Other kernel surfaces/CVEs | Absent: nftables, network scheduler, SCTP diagnostics, CIFS request-key, ESP/RXRPC, OVS/XFRM, XFS reflink | **Added upstream-only nftables, net/sched and ESP triage; others deferred:** RXRPC, OVS chains, SCTP, CIFS and XFS still need verified rules/prerequisites. `functions/check{NfTablesCVE202623111,NetSchedCVE202653264,DiagSpillCVE202674469,CIFSwitchCVE202646243,DirtyFrag,OVSPageCacheCVE2026,XFSTangoCVE202680530}.sh`. |
| Dangerous *individual* file capabilities | `sec010` already enumerates capabilities; selected `sec020`/`sec030` only detect writable/all-capability files | **Added:** interpret existing `sec010` evidence; executable/capability combinations, not every capability. `8_interesting_perms_files/4_Capabilities.sh`, `variables/capsVB.sh`. |
| Effective/ambient process capabilities and PAM capability assignments | Process analysis absent; `sec040`/`sec050` assignments omitted | **Added current/parent effective and ambient capabilities** for the actual account; PAM assignments remain deferred. Namespace/LSM constraints remain unverified. `8_interesting_perms_files/4_Capabilities.sh`, `5_Users_with_capabilities.sh`. A bounding set alone isn't active privilege. |
| Restricted sudo rules, command/argument risks, environment and Python import hooks | `sud010` can collect rules but is omitted; interpretation absent. Selected `sud000` only tries `id` | **Added narrow passive subset:** noninteractive listing, unrestricted interpreter rules and writable `secure_path`. Complex command restrictions, Python loader correlation and full sudo-policy evaluation are **deferred**. `6_users_information/7_Sudo_l.sh`. |
| doas policy | Absent | **Added narrow native configuration-only `doas -C` checks:** root interpreter permits, actual rule ordering and runtime config-mode guards. No delegated commands. `6_users_information/9_Doas.sh`. |
| Administrative runtime socket access | Docker/LXD group checks `ctn020`/`ctn210` selected, but group membership misses ACL/socket permission access | **Added:** named root-owned runtime sockets accessible to the scanning account; no connections/API calls. `functions/enumerateDockerSockets.sh`. Rootless/user-owned sockets aren't root-equivalent. |
| Dynamic-loader hooks | `fst000` inventory could contain paths, but `fst160`/`fst170` critical lists omit loader paths | **Added:** loader configs/includes, referenced library directories and preload libraries. `8_interesting_perms_files/6_Misconfigured_ldso.sh`. Writable search dirs are candidates, not proof root loads attacker code. |
| Active privileged service executables and parents; effective drop-ins / socket units | Nominal executable checks `srv010`/`srv510` are omitted **and malformed** in this LSE pin. Parent/effective-unit correlation absent | **Added active systemd root-service effective executable/config/drop-in/working-directory paths and replaceable parents.** Chroot/image paths and unsupported native syntax stay incomplete; socket-unit correlation remains deferred. `functions/checkSystemdWritableExecPaths.sh`, `4_procs_crons_timers_srvcs_sockets/11_Systemd.sh`, `12_Socket_files.sh`. |
| Root process executable permissions | `pro010` exists but is omitted; depends on process monitoring we intentionally disable | **Added bounded one-shot root `/proc` executable/parent permissions.** No watcher, arguments or environments; inaccessible/namespace-untranslatable paths remain incomplete. `4_procs_crons_timers_srvcs_sockets/3_Process_binaries_perms.sh`. |
| SGID executable risks | `fst040`/`fst060` omitted; upstream `fst040` misplaces its output-variable argument | **Added bounded executable SGID interpreter/writable-file candidates** granting a GID the account lacks. No reliance on the broken upstream IDs; privilege retention is unverified. `8_interesting_perms_files/2_SGID.sh`. |
| Privileged executable location, GTFOBins, binary strings/dependencies | LSE has uncommon/writable SUID checks, but no equivalent GTFOBins/reference correlation or parent-placement analysis | **Deferred:** don't execute unknown binaries, use `ldd`/`strace`, or mistake file replacement for preserved SUID/capability metadata. `8_interesting_perms_files/1_SUID.sh`, `functions/check_privileged_file_location.sh`. |
| SSH/GPG agent sockets | `sof070`/`sof080` exist but are omitted; tmux/screen socket tests already selected | **Added deep-only other-account SSH/GPG agent socket permissions;** no connections or own-agent alerts. `7_software_information/Ssh.sh`. |
| Kerberos cache/keytab exposure | `sof180` exists but is omitted | **Added other-account keytab/conventional ticket-cache readability metadata;** no own-account alerts or ticket contents. `7_software_information/Kerberos.sh`. |
| Targeted package CVEs: needrestart, PackageKit, UDisks, snap-confine, pkexec, sudo, Gogs and runtimes | No equivalent CVE rules in our LSE source bundle | **Added reviewed Debian/Ubuntu needrestart, PackageKit, PwnKit and sudo package-version triage.** Unknown vendor/source builds remain incomplete; RPM gets deep-only heuristics. UDisks, snap-confine, Gogs and runtimes remain deferred. `functions/checkNeedrestartCVE202448990.sh`, `checkUDisksCVE20267867.sh`, `checkSnapConfineCVE20268933.sh`, `7_software_information/PackageKit_Pack2TheRoot.sh`, `Gogs.sh`, `6_users_information/10_Pkexec.sh`, `1_system_information/2_Sudo_version.sh`. |
| Kubernetes credentials/host mounts/RBAC | Absent beyond basic container/group checks | **Added other-account conventional node/admin kubeconfig and kubelet-key readability metadata.** Projected own-pod tokens, RBAC and mount correlation remain deferred. `2_container/2_List_mounted_tokens.sh`, `6_Kubernetes_surfaces.sh`, `5_Container_breakout.sh`. No API requests in our addition. |
| Cloud credential paths/metadata and cross-process secrets | Absent beyond ordinary environment enumeration (`usr040`, omitted) | **Added other-account conventional cloud credential-file readability metadata.** Metadata/API queries, cross-process environments and credential dumps remain excluded. `3_cloud/`, `9_interesting_files/29_Interesting_environment_variables.sh`. |
| Broad config/log/application secret searches, backups, ACL inventories and other users' files | Partial LSE coverage (`fst090`, `fst110`, `fst190`, `fst510`, many `sof*`); much omitted | **Not blanket-added:** too much benign data and secret disclosure without ownership/consumer context. `7_software_information/`, `9_interesting_files/`, `10_api_keys_regex/`, `8_interesting_perms_files/3_Files_ACLs.sh`. |
| Network/host/service inventory, login history and protection-setting enumeration | Much exists in LSE but omitted; this repo also has listener/SSH/firewall commands | **Not findings:** don't duplicate inventory or declare every missing protection exploitable. |

### Already covered, not missing

Writable critical/PAM/profile/sudoers files and directories (`fst160`, `fst170`),
system PATH directories (`fst180`), cron files and referenced paths (`ret010`,
`ret050`, `ret060`), service configuration (`srv000`, `srv500`), writable/unusual
SUID files (`fst020`, `fst030`), critical account permissions (`sys020`, `sys022`,
`sys030`, `sys040`), NFS `no_root_squash` (`fst210`), database checks and tmux/screen
sockets already have selected LSE checks. Extra rules must not replace those.

## Integration and safety

`ccdcctl lse` / `monitor lse` keep their existing command, report and result
contract. `scripts/discover-lse` merges supplemental findings with LSE, retaining
raw evidence in private reports and stable IDs for monitor deduplication.
The playbook transfers helpers beside LSE and always removes its private scratch
directory. Permission checks assess the actual effective login account, not
`USER` or a spoofable banner; root scans report those checks incomplete rather
than flagging root's expected access. Kernel metadata checks still run as root.

The wrapper records native `getcap` exit status in its private scratch directory
while forwarding normal LSE output; it does not repeat the filesystem enumeration.
A successful empty capability inventory can resolve prior capability findings;
a failed/missing inventory remains scoped incomplete. Relative library search
entries are unknown, not invented config-relative paths; relative **includes**
are resolved against their including config without collapsing symlink/`..`
semantics. Sudo rule analysis deliberately declines complex restrictions and
explicit command denials instead of treating a partial grant as unrestricted.

Supplemental checks do not install packages, exploit bugs, write probes, load
modules, execute discovered application binaries, connect to runtime/agent APIs,
query cloud metadata, or activate application D-Bus services. Trusted `systemctl`
only lists/shows existing service-manager metadata; package queries/comparisons
are native metadata commands. Delegation checks invoke only `sudo -n -l` and
`doas -C`, never a delegated command. We do **not** import LinPEAS's Copy Fail
runtime probe, registry `eval` rules, container mount/write probes, SUID tracing,
credential dumping or brute-force checks.

A warning/candidate isn't proof of exploitability. Missing utilities, unreadable
metadata and traversal/read limits produce scoped `incomplete_ids` and coverage
findings so the monitor doesn't falsely resolve affected prior findings.
An empty report never certifies all LinPEAS checks or all CVEs passed.

## Reviewed kernel rule data

### Copy Fail — CVE-2026-31431

Sources:

- LinPEAS pin above: `functions/checkCopyFail.sh` and
  `variables/kernel_cve_registry_data.sh` (reference for passive prerequisites;
  its active runtime probe is explicitly not imported).
- [Ubuntu advisory](https://ubuntu.com/blog/copy-fail-vulnerability-fixes-available)
  for generic/HWE kernel build boundaries.
- [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-31431)
  for source-version boundaries.

Reviewed upstream introduction: 4.14; fixed stable releases: **5.10.254,
5.15.204, 6.1.170, 6.6.137, 6.12.85, 6.18.22, 6.19.12**, mainline **7.0**.
Other intervening/EOL branches remain candidates; RC/custom/vendor suffixes
are never silently treated as a fixed upstream release.

Normal vendor interpretation is intentionally narrow:

| Running-kernel provenance | Recognized fixed build |
| --- | --- |
| Ubuntu **generic** 5.4 | 5.4.0-230.250 |
| Ubuntu **generic** 5.15 | 5.15.0-179.189 |
| Ubuntu **generic** 6.8 | 6.8.0-117.117 |
| Ubuntu **generic** 6.17 | 6.17.0-29.29 |
| Debian 5.10 | 5.10.251-3 |
| Debian 6.1 | 6.1.170-1 |
| Debian 6.12 | 6.12.85-1 |
| Debian 6.19 | 6.19.12-1 |

Ubuntu identification requires a matching running `/proc/version_signature`
with `-generic` flavor. Debian uses the running `/proc/version` source-build
revision, not just its ABI name. Standard HWE / `~debNuN` backport suffixes
retain the documented numeric base fix; unknown revisions/flavors stay unknown.
**No comparison uses a container's `/etc/os-release` or installed kernel package
as proof the host/running kernel is patched.** Custom kernels/livepatch are not
verified. Metadata may be falsified by a compromised kernel/root account.

AEAD config or loaded-module evidence is recorded separately. Embedded running
`/proc/config.gz` takes precedence; an on-disk `/boot`/module config is only a
hint, never proof that the running API was compiled out. A configured
module does not prove autoload/algorithm reachability. A missing module doesn't
prove mitigation; a blacklist doesn't prove loaded/built-in code is disabled.
We don't infer a clean verdict from a changelog mention or run AF_ALG probes.
Normal alerts require an identified affected build and positive surface metadata;
unknown vendor/build/prerequisites yield a scoped coverage warning. `--deep` can
add clearly marked unverified upstream-version candidates for vendor kernels.

### Networking rules — upstream only

Sources: Linux CNA records for
[nftables CVE-2026-23111](https://cveawg.mitre.org/api/cve/CVE-2026-23111),
[net/sched CVE-2026-53264](https://cveawg.mitre.org/api/cve/CVE-2026-53264), and
[ESP CVE-2026-43284](https://cveawg.mitre.org/api/cve/CVE-2026-43284).

| Rule | Introduction | Reviewed stable first-fixed releases | Mainline fixed |
| --- | --- | --- | --- |
| nftables catchall-map UAF | 6.4; backported into 4.19.316, 5.4.262, 5.10.188, 5.15.121, 6.1.36, 6.3.10 | 5.15.200, 6.1.163, 6.6.124, 6.12.70, 6.18.10 | 6.19 |
| net/sched action UAF | 4.14 | 5.10.259, 5.15.210, 6.1.176, 6.6.143, 6.12.94, 6.18.36, 7.0.13 | 7.1 |
| ESP shared-fragment writes | 4.11 | 5.10.255, 5.15.206, 6.1.172, 6.6.138, 6.12.87, 6.18.28, 7.0.5 | 7.1 |

The ESP CNA lists both 5.15.205/206 and 6.1.171/172; the implementation
conservatively uses the later boundary. These rules do **not** apply upstream
fix thresholds to vendor kernels. Vendor/custom/RC builds stay scoped incomplete;
deep-only version matches are explicitly unverified. Intervening/EOL affected
branches are not silently certified fixed.

Surface evidence is separate: NF_TABLES, NET_CLS_ACT (no exploit-specific
flower/GACT requirement), and actual IPv4/IPv6 ESP plus XFRM. Only embedded
running config can prove compiled-out; loaded modules override inconsistent
config. CAP_NET_ADMIN and user-namespace config/sysctls are passive observations,
not permission proofs. Disabled user namespaces do not exclude an existing
namespace-scoped capability route. No netlink, namespace or module-load probes.

### Dirty Pipe — CVE-2022-0847

Source: [original disclosure by Max Kellermann](https://dirtypipe.cm4all.com/).
Introduced in **5.8**, fixed in **5.10.102, 5.15.25, 5.16.11** and later mainline
branches. The upstream-only rule respects all three stable fix branches, unlike
a single broad `5.8 <= version < 5.16.11` comparison. Within that range, unrecognized
vendor kernels are unknown (deep-mode version matches are explicitly heuristic).
Versions outside that upstream range are outside this rule's scope, not a general
vendor patch verdict.

These tables are a **static reviewed snapshot**, not a self-updating vulnerability
feed. New CVEs and vendor flavors require source review, fixtures and documented
rule updates. No network lookup occurs on targets.
