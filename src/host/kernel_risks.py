"""Passive, bounded kernel-CVE triage; never probes, loads modules or uses installed kernels.

Rules are a small reviewed snapshot, NOT a general CVE database. Vendor build
identification comes from the running kernel's /proc metadata, not os-release
(which describes the container userspace on Docker hosts).
"""
import gzip
import io
import os
from pathlib import Path
import re
import stat
import zlib

# Copy Fail/Dirty Pipe sources and scope are documented in vendor/LINPEAS-GAPS.md.
COPY_FAIL = "kernel:CVE-2026-31431"
DIRTY_PIPE = "kernel:CVE-2022-0847"
NFTABLES = "kernel:CVE-2026-23111"
NET_SCHED = "kernel:CVE-2026-53264"
ESP = "kernel:CVE-2026-43284"
IDS = [COPY_FAIL, DIRTY_PIPE, NFTABLES, NET_SCHED, ESP]
# Linux CNA snapshots, upstream/stable only; no vendor fix thresholds:
# https://cveawg.mitre.org/api/cve/CVE-2026-23111
# https://cveawg.mitre.org/api/cve/CVE-2026-53264
# https://cveawg.mitre.org/api/cve/CVE-2026-43284
NFT_INTRO = {(4, 19): 316, (5, 4): 262, (5, 10): 188,
             (5, 15): 121, (6, 1): 36, (6, 3): 10}
NFT_FIXED = {(5, 15): 200, (6, 1): 163, (6, 6): 124,
             (6, 12): 70, (6, 18): 10}
SCHED_FIXED = {(5, 10): 259, (5, 15): 210, (6, 1): 176,
               (6, 6): 143, (6, 12): 94, (6, 18): 36, (7, 0): 13}
# Duplicate CNA entries: use the later 5.15/6.1 fix conservatively.
ESP_FIXED = {(5, 10): 255, (5, 15): 206, (6, 1): 172,
             (6, 6): 138, (6, 12): 87, (6, 18): 28, (7, 0): 5}
COPY_FIXED = {(5, 10): 254, (5, 15): 204, (6, 1): 170,
              (6, 6): 137, (6, 12): 85, (6, 18): 22, (6, 19): 12}
UBUNTU_COPY_FIXED = {(5, 4): (5, 4, 0, 230, 250),
                     (5, 15): (5, 15, 0, 179, 189),
                     (6, 8): (6, 8, 0, 117, 117),
                     (6, 17): (6, 17, 0, 29, 29)}
DEBIAN_COPY_FIXED = {(5, 10): (5, 10, 251, 3), (6, 1): (6, 1, 170, 1),
                     (6, 12): (6, 12, 85, 1), (6, 19): (6, 19, 12, 1)}
LIMIT = 1024 * 1024


def read_regular(path, compressed=False):
    """Refuse devices/FIFOs; cap decompression as well as ordinary reads."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise OSError("not a regular file: " + str(path))
        data = stream.read(LIMIT + 1)
        if len(data) > LIMIT:
            raise OSError("input read limit exceeded: " + str(path))
        if compressed:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as archive:
                data = archive.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise OSError("read limit exceeded: " + str(path))
    return data.decode("utf-8", errors="replace")


def version(text):
    match = re.match(r"(\d{1,6})\.(\d{1,6})(?:\.(\d{1,6}))?(?![\d.])", text)
    return tuple(int(n or 0) for n in match.groups()) if match else None


def running_build(release, signature, banner):
    """Identify only running vendor builds with unambiguous numeric revisions."""
    if re.search(r"(?:-|\.)rc\d*", release):
        return "unknown", None  # A prerelease must not inherit a later final release's fix.
    ubuntu = re.match(r"Ubuntu (\d{1,6}\.\d{1,6}\.\d{1,6})-(\d{1,6})\.(\d{1,6})(?:~\d+\.\d+\.\d+)?-generic(?:\s|$)", signature)
    if ubuntu:
        base, abi, revision = ubuntu.groups()
        if release == base + "-" + abi + "-generic":
            return "ubuntu", (*version(base), int(abi), int(revision))
    debian = re.search(r"\bDebian (\d{1,6}\.\d{1,6}\.\d{1,6})-(\d{1,6})(?:~deb\d+u\d+)?(?:\s|$)", banner)
    if debian:
        base, revision = debian.groups()
        # Debian's ABI name differs from its source version, but the series must agree.
        if version(release) and version(release)[:2] == version(base)[:2]:
            return "debian", (*version(base), int(revision))
    return "upstream" if re.fullmatch(r"\d+\.\d+(?:\.\d+)?", release) else "unknown", version(release)


def copy_status(vendor, build):
    if not build:
        return "unknown"
    if vendor in ("ubuntu", "debian"):
        table = UBUNTU_COPY_FIXED if vendor == "ubuntu" else DEBIAN_COPY_FIXED
        fixed = table.get(build[:2])
        return ("affected" if build < fixed else "fixed") if fixed else "unknown"
    if vendor != "upstream":
        return "unknown"
    if build < (4, 14, 0) or build >= (7, 0, 0):
        return "outside-range"
    fixed_patch = COPY_FIXED.get(build[:2])
    if fixed_patch is not None and build[2] >= fixed_patch:
        return "fixed"
    return "affected"


def pipe_status(vendor, build):
    if not build or vendor == "unknown":
        return "unknown"
    if build[:3] < (5, 8, 0) or build[:3] >= (5, 17, 0):
        return "outside-range"  # Outside this upstream-only rule's scope, not a vendor verdict.
    if vendor != "upstream" or not build:
        return "unknown"  # Never apply stable-branch fix thresholds to distro kernels.
    fixed_patch = {(5, 10): 102, (5, 15): 25, (5, 16): 11}.get(build[:2])
    return "fixed" if fixed_patch is not None and build[2] >= fixed_patch else "affected"


def upstream_status(test_id, vendor, build):
    """Curated CNA ranges; numeric distro/custom versions cannot establish fixes."""
    if vendor != "upstream" or not build:
        return "unknown"
    if test_id == NFTABLES:
        table, final = NFT_FIXED, (6, 19, 0)
        intro = NFT_INTRO.get(build[:2])
        affected = build >= (6, 4, 0) or (intro is not None and build[2] >= intro)
    else:
        table = SCHED_FIXED if test_id == NET_SCHED else ESP_FIXED
        final = (7, 1, 0)
        affected = build >= ((4, 14, 0) if test_id == NET_SCHED else (4, 11, 0))
    if build >= final:
        return "fixed"
    if not affected:
        return "outside-range"
    fixed_patch = table.get(build[:2])
    return "fixed" if fixed_patch is not None and build[2] >= fixed_patch else "affected"


NAMESPACE_SYSCTLS = {"/proc/sys/kernel/unprivileged_userns_clone": "kernel.unprivileged_userns_clone",
                     "/proc/sys/user/max_user_namespaces": "user.max_user_namespaces"}


def userns_finding(policy):
    """Unprivileged user namespaces are the usual route to CAP_NET_ADMIN; offer to switch them off."""
    was = {NAMESPACE_SYSCTLS[name]: value for name, value in policy.items()
           if name in NAMESPACE_SYSCTLS and value not in ("0", "unknown")}
    if not was:
        return None
    return {"id": "ns-unprivileged-userns", "severity": "review",
            "summary": "Unprivileged user namespaces are enabled",
            "context": {"sysctls": policy,
                        "certainty": "setting observed; disabling breaks rootless containers and browser/Flatpak sandboxes"},
            "fixes": [{"kind": "sysctl", "settings": dict.fromkeys(was, "0"), "was": was, "tier": "all"}]}


def inspect_kernel(deep=False, root=Path("/"), release=None):
    """Normal: identified builds; deep also shows explicitly unverified version matches."""
    release = os.uname().release if release is None else release
    diagnostics, missing = [], []

    def read(name, optional=False, compressed=False):
        try:
            return read_regular(root / name.lstrip("/"), compressed)
        except FileNotFoundError:
            if not optional:
                missing.append(name + ": unavailable")
        except (OSError, EOFError, zlib.error) as exc:
            missing.append(name + ": " + str(exc))
        return ""

    signature = read("/proc/version_signature", optional=True)
    banner = read("/proc/version")
    vendor, build = running_build(release, signature, banner)
    diagnostics.append("Running kernel: %s; build provenance: %s %s" % (release, vendor, build))
    diagnostics.append("Kernel coverage: Copy Fail (upstream, Ubuntu generic 5.4/5.15/6.8/6.17, Debian 5.10/6.1/6.12/6.19); Dirty Pipe, nftables CVE-2026-23111, net/sched CVE-2026-53264 and ESP CVE-2026-43284 upstream-only. No exploit probes; no complete-CVE or livepatch assessment.")
    config, config_source = "", ""
    for name in ("/proc/config.gz", "/boot/config-" + release, "/lib/modules/" + release + "/config"):
        config = read(name, optional=True, compressed=name.endswith(".gz"))
        if config:
            config_source = name
            break
    diagnostics.append("Kernel/AEAD config source: " + (config_source or "unavailable")
                       + ("; indicative disk config, not running proof" if config_source and config_source != "/proc/config.gz" else ""))

    def surface(symbols, modules=()):
        # Loaded code wins; only the embedded config proves compiled-out.
        if any((root / "sys/module" / module).is_dir() for module in modules):
            return "loaded"
        values = [re.search(r"^" + symbol + r"=([ym])$", config, re.M) for symbol in symbols]
        if any(value and value[1] == "y" for value in values):
            return "builtin"
        if any(values):
            return "module-configured"
        if config_source == "/proc/config.gz" and all(
                "# " + symbol + " is not set" in config.splitlines() for symbol in symbols):
            return "disabled"
        return "unknown"

    exposure = surface(("CONFIG_CRYPTO_USER_API_AEAD",), ("algif_aead",))
    diagnostics.append("Copy Fail AEAD surface: " + exposure + "; module autoload policy and algorithm reachability are not verified")
    # A blacklist alone is not proof of mitigation. Do not run modprobe or AF_ALG:
    # even an innocuous AF_ALG bind can autoload host kernel modules.
    nft_surface = surface(("CONFIG_NF_TABLES",), ("nf_tables",))
    # Any loaded action is positive evidence, never a requirement for one exploit's action.
    action_modules = [path.name for path in (root / "sys/module").glob("act_*") if path.is_dir()]
    sched_surface = surface(("CONFIG_NET_CLS_ACT",), action_modules)
    esp_surface = surface(("CONFIG_INET_ESP", "CONFIG_INET6_ESP"), ("esp4", "esp6"))
    xfrm_surface = surface(("CONFIG_XFRM",))
    if esp_surface != "loaded":  # A loaded ESP module already depends on XFRM.
        if "disabled" in (esp_surface, xfrm_surface):
            esp_surface = "disabled"
        elif "unknown" in (esp_surface, xfrm_surface):
            esp_surface = "unknown"
    surfaces = {COPY_FAIL: exposure, DIRTY_PIPE: "not probed", NFTABLES: nft_surface,
                NET_SCHED: sched_surface, ESP: esp_surface}
    for test_id in (NFTABLES, NET_SCHED, ESP):
        diagnostics.append(test_id + " surface: " + surfaces[test_id]
                           + "; module autoload policy and reachability are not verified")
    diagnostics.append("ESP XFRM surface: " + xfrm_surface)
    status_text = read("/proc/self/status", optional=True)
    cap = re.search(r"^CapEff:\s*([0-9a-fA-F]{1,16})\s*$", status_text, re.M)
    net_admin = ("present" if int(cap[1], 16) & (1 << 12) else "absent") if cap else "unknown"
    userns = surface(("CONFIG_USER_NS",))
    namespace_policy = {}
    for name in ("/proc/sys/kernel/unprivileged_userns_clone", "/proc/sys/user/max_user_namespaces"):
        value = read(name, optional=True).strip()
        namespace_policy[name] = value if re.fullmatch(r"\d{1,10}", value) else "unknown"
    privilege_path = {"requirement": "CAP_NET_ADMIN in the relevant network namespace; may be obtained via user/network namespaces",
                      "self_cap_net_admin": net_admin, "user_ns_config": userns,
                      "namespace_sysctls": namespace_policy,
                      "certainty": "passive observations only; namespace creation and capability scope not verified; disabled userns does not exclude privileged paths"}
    diagnostics.append("Network privilege path: self CAP_NET_ADMIN=" + net_admin
                       + "; CONFIG_USER_NS=" + userns + "; sysctls=" + str(namespace_policy)
                       + "; no namespace probes or automatic suppression")
    findings, incomplete = [], set()
    for test_id, label, status in ((COPY_FAIL, "Copy Fail", copy_status(vendor, build)),
                                   (DIRTY_PIPE, "Dirty Pipe", pipe_status(vendor, build)),
                                   (NFTABLES, "nftables", upstream_status(NFTABLES, vendor, build)),
                                   (NET_SCHED, "net/sched action lifecycle", upstream_status(NET_SCHED, vendor, build)),
                                   (ESP, "ESP shared fragments", upstream_status(ESP, vendor, build))):
        diagnostics.append(test_id + ": " + status)
        observed_surface = surfaces[test_id]
        network_rule = test_id in (NFTABLES, NET_SCHED, ESP)
        if status in ("fixed", "outside-range") or (observed_surface == "disabled" and (status != "unknown" or not network_rule)):
            continue
        if status == "affected" and observed_surface != "unknown":
            findings.append({"id": test_id, "severity": "warning" if vendor in ("ubuntu", "debian") else "review",
                             "summary": label + ": running build matches an affected range; review patch/mitigation status",
                             "context": {"kernel": release, "vendor": vendor, "running_build": list(build),
                                         "version_status": status, "surface": observed_surface,
                                         **({"privilege_path": privilege_path, "config_source": config_source,
                                             **({"xfrm_surface": xfrm_surface} if test_id == ESP else {})} if network_rule else {}),
                                         "certainty": "passive candidate, not proof of exploitation; custom patches/livepatch may apply"}})
            continue
        incomplete.add(test_id)
        # RC provenance has no build: never interpret an uncertain prerelease as final.
        if deep and build and (vendor == "unknown" or (network_rule and vendor != "upstream")):
            numeric = build[:3] if network_rule else version(release)
            heuristic = (upstream_status(test_id, "upstream", numeric) if network_rule else
                         copy_status("upstream", numeric) if test_id == COPY_FAIL else pipe_status("upstream", numeric))
            if heuristic == "affected" and observed_surface != "disabled":
                findings.append({"id": test_id, "severity": "review",
                                 "summary": label + ": unverified upstream-version match; vendor backports unknown",
                                 "context": {"kernel": release, "vendor": vendor, "surface": observed_surface,
                                             "version_status": "unknown", "upstream_heuristic": heuristic,
                                             "upstream_version": list(numeric),
                                             **({"privilege_path": privilege_path, "config_source": config_source} if network_rule else {}),
                                             "certainty": "unverified version-only heuristic"}})
    if incomplete:
        findings.append({"id": "scanner-extra-kernel", "severity": "warning",
                         "summary": "Kernel CVE coverage incomplete; running vendor build or prerequisites could not be established",
                         "context": {"checks": sorted(incomplete), "details": sorted(set(missing))}})
    userns_fix = userns_finding(namespace_policy)
    if userns_fix:
        findings.append(userns_fix)
    result = {"findings": sorted(findings, key=lambda row: row["id"]),
              "raw": "\n".join(diagnostics + sorted(set(missing))), "errors": []}
    if incomplete:
        result["incomplete_ids"] = sorted(incomplete)
    return result
