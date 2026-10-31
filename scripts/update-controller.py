"""Interactive package review followed by guarded updates and opt-in restarts."""
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace


SCHEMA = 2


def endpoint(ctl, variables):
    values = {key: value for key, value in variables.items()
              if key.startswith("ansible_") or key == "ccdc_known_hosts_file"}
    return hashlib.sha256(json.dumps([values, ctl.EXTRA], sort_keys=True).encode()).hexdigest()


def call_host(ctl, host, action, **fields):
    """Send one request to host/manage_updates.py through the shared remote runner."""
    document = {"action": action, **fields}
    token = fields.get("token")
    destination = ctl.ROOT / "reports" / host / "updates" / "backups" / token if token else None
    if destination:
        destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix="ccdc-update-results-") as directory:
        with tempfile.NamedTemporaryFile(mode="w", prefix="ccdc-update-request-", suffix=".json") as out:
            json.dump(document, out)
            out.flush()
            result = ctl.run(["ansible-playbook", "playbooks/remote.yml", "--limit", host, *ctl.EXTRA,
                              "--extra-vars", ctl.remote.request("manage_updates", payload=out.name)],
                             result_dir=directory, result_task=ctl.remote.TASK)
        if getattr(ctl, "VERBOSE", False):
            print(ctl.terminal(result.stdout + result.stderr))
        try:
            response = json.loads((Path(directory) / host).read_text())
            if response.get("failed") or response.get("unreachable") or response.get("rc", 0) or result.returncode:
                ctl.save(ctl.ROOT / "reports" / host / "updates" / "remote-failure.json",
                         {"action": action, "token": token, "response": response})
                try:
                    error = json.loads(response.get("stdout", "")).get("error")
                except ValueError:
                    error = None
                raise RuntimeError(error or response.get("msg") or "update task failed; inspect remote-failure.json")
            state = json.loads(response["stdout"])
            if not isinstance(state, dict) or state.get("error"):
                raise ValueError("invalid remote update result")
        except (OSError, KeyError, ValueError) as exc:
            raise RuntimeError("No usable update result: " + str(exc)) from exc
    if action == "apply":
        fetch_backup(ctl, host, token, state, destination)
    return state


def fetch_backup(ctl, host, token, state, destination):
    """Copy the root-only configuration archive to the controller after a successful apply."""
    archive = state.get("backup_archive")
    if not isinstance(archive, str) or not re.fullmatch(
            "/var/backups/ccdc-updates/" + re.escape(token) + "/[^/]+", archive):
        raise RuntimeError("update returned an unexpected recovery archive path")
    arguments = json.dumps({"src": archive, "dest": str(destination / "configs.tar.gz"), "flat": True})
    result = ctl.run(["ansible", "all", "--limit", host, "--become", "-m", "ansible.builtin.fetch",
                      "-a", arguments, *ctl.EXTRA])
    if result.returncode:
        ctl.save(ctl.ROOT / "reports" / host / "updates" / "remote-failure.json",
                 {"action": "fetch", "token": token, "output": result.stdout + result.stderr})
        raise RuntimeError("backup transfer failed; inspect remote-failure.json")


def check_access(ctl, host):
    if not ctl.verify_admin_access(host):
        raise RuntimeError("fresh oski key login/sudo failed")


def candidates(state):
    if state.get("schema") != SCHEMA or not isinstance(state.get("candidates"), list):
        raise ValueError("invalid update discovery document")
    seen = set()
    for item in state["candidates"]:
        if (not isinstance(item, dict) or not isinstance(item.get("name"), str)
                or not re.fullmatch(r"[a-z0-9][a-z0-9+_.:-]*", item["name"])
                or item["name"] in seen or item.get("risk") not in ("lower", "manual")
                or not all(isinstance(item.get(k), str) and item[k] for k in ("old", "new", "reason"))):
            raise ValueError("invalid update candidate")
        seen.add(item["name"])
    return state["candidates"]


def show_services(ctl, state):
    if not isinstance(state.get("services"), list):
        raise ValueError("invalid service discovery document")
    for service in state["services"]:
        if (not isinstance(service, dict) or not isinstance(service.get("name"), str)
                or not isinstance(service.get("active"), bool)
                or not isinstance(service.get("reasons"), list)
                or not all(isinstance(reason, str) for reason in service["reasons"])):
            raise ValueError("invalid service discovery record")
    active = [s["name"] for s in state["services"] if s["active"]]
    print("Running managed services: " + ctl.terminal(", ".join(active) or "none discovered"))
    for warning in state.get("warnings", []):
        print("WARNING: " + ctl.terminal(warning))
    for process in state.get("unmanaged", []):
        print("MANUAL PROCESS REVIEW: " + ctl.terminal(json.dumps(process, sort_keys=True)))


def explain_selection_failure(ctl, host):
    # Show dependency relationships, not raw native output (which can contain repository credentials).
    try:
        evidence = json.loads((ctl.ROOT / "reports" / host / "updates" / "remote-failure.json").read_text())
        if evidence.get("action") != "select":
            return
        output = json.loads(evidence["response"]["stdout"]).get("native_output", "")
        lines = [line for line in output.splitlines() if re.match(
            r"^\s*(?:[a-z0-9][a-z0-9+_.:-]*\s*:\s*)?(?:Depends|PreDepends|Breaks|Conflicts):", line)]
        for line in lines[:15]:
            print("  " + ctl.terminal(line)[:500])
    except (OSError, ValueError, KeyError, TypeError):
        pass


def review(ctl, host, catalog):
    found = candidates(catalog)
    lower = [c for c in found if c["risk"] == "lower"]
    manual = [c for c in found if c["risk"] == "manual"]
    for label, items in (("LOWER-RISK CANDIDATES", lower), ("HELD FOR MANUAL UPDATE", manual)):
        print(f"\n{label} ({len(items)})")
        for item in items:
            print(ctl.terminal(f"  {item['name']}: {item['old']} -> {item['new']}\n    {item['reason']}"))
    for warning in catalog.get("warnings", []):
        print("WARNING: " + ctl.terminal(warning))
    for held in catalog.get("held", []):
        print("HELD/NOTICE: " + ctl.terminal(held))
    print("Lower-risk is a conservative package classification, not a guarantee of compatibility.")
    print("Removals, new dependencies and changes to held packages will not be allowed.")
    while True:
        choice = ctl.ask("[a] select all lower-risk, [r] review each, [s] skip host", ["a", "r", "s"], "a")
        if choice == "s":
            return None
        selected = []
        for item in lower:
            if choice == "a" or ctl.ask(f"{item['name']}: [y] include, [n] hold", ["y", "n"], "y") == "y":
                selected.append(item["name"])
        try:
            exact = call_host(ctl, host, "select", snapshot=catalog, packages=selected)
            candidates(exact)
            if exact.get("selected") != sorted(selected) or not isinstance(exact.get("changes"), list):
                raise ValueError("resolver did not preserve reviewed selection")
        except RuntimeError as exc:
            print("Selection cannot be resolved without an unsafe/unreviewed change: " + ctl.terminal(exc))
            explain_selection_failure(ctl, host)
            print(f"Private native diagnostics: reports/{host}/updates/remote-failure.json")
            if ctl.ask("[r] revise selection, [s] skip host", ["r", "s"], "s") == "r":
                continue
            return None
        print("\nEXACT TRANSACTION")
        for change in exact["changes"]:
            print(ctl.terminal(f"  {change['name']}: {change['old']} -> {change['new']}"))
        if not exact["changes"]:
            print("  No packages will be installed.")
        print("Package hooks may restart services during installation. No reboot or automatic rollback.")
        if ctl.ask("[y] save this reviewed plan, [n] skip host", ["y", "n"], "n") == "y":
            return exact
        return None


def offer_restarts(ctl, host, before, report, directory):
    inspection = call_host(ctl, host, "services", before=before)
    show_services(ctl, inspection)
    report["services_after"] = inspection
    pending = [s for s in inspection["services"] if s["reasons"]]
    report["deferred_restarts"] = [s["name"] for s in pending]
    report["restarts"] = []
    ctl.save(directory / "result.json", report)
    for service in pending:
        name = service["name"]
        print(ctl.terminal(f"\n{host}: {name} ({service.get('confidence', 'unknown')} attribution)"))
        for reason in service["reasons"]:
            print("  " + ctl.terminal(reason))
        print("Restart can interrupt clients. Unknown application configuration/health is not validated.")
        if not sys.stdin.isatty():
            print("  DEFERRED: no terminal; --yes never approves service restarts.")
            continue
        choice = ctl.ask("[r] restart this service, [s] defer, [q] stop rollout", ["r", "s", "q"], "s")
        if choice == "q":
            return False
        if choice == "r":
            result = call_host(ctl, host, "restart", service=name, before=before)
            if result.get("status") not in ("restarted", "already-current"):
                raise RuntimeError(f"{name}: restart did not complete successfully")
            report["restarts"].append(result)
            report["deferred_restarts"].remove(name)
            ctl.save(directory / "result.json", report)
            check_access(ctl, host)
    final = call_host(ctl, host, "services", before=before)
    report["services_final"] = final
    show_services(ctl, final)
    previous = {s["name"] for s in before["services"] if s["active"]}
    stopped = [s["name"] for s in final["services"] if s["name"] in previous and not s["active"]]
    if stopped:
        raise RuntimeError("previously running services are now stopped: " + ", ".join(stopped))
    report["deferred_restarts"] = [s["name"] for s in final["services"] if s["reasons"]]
    return True


def updates(controller, action, hosts, variables, yes=False):
    ctl = SimpleNamespace(**controller) if isinstance(controller, dict) else controller
    if action == "plan" and yes:
        raise ValueError("--yes is only valid with update apply")
    plans = {}
    if action == "plan":
        for host in hosts:
            ctl.save(ctl.ROOT / "reports" / host / "updates" / "plan.json",
                     {"schema": SCHEMA, "host": host, "ready": False})
        if not sys.stdin.isatty():
            raise ValueError("update plan is an interactive walkthrough; run it in a terminal")
    else:
        # Validate every selected saved plan before the first package mutation.
        for host in hosts:
            plan = json.loads((ctl.ROOT / "reports" / host / "updates" / "plan.json").read_text())
            if (not isinstance(plan, dict) or plan.get("schema") != SCHEMA or plan.get("host") != host
                    or not plan.get("ready") or plan.get("endpoint") != endpoint(ctl, variables.get(host, {}))
                    or not isinstance(plan.get("remote"), dict)
                    or not isinstance(plan.get("created"), (int, float))
                    or not 0 <= time.time() - plan["created"] <= 86400):
                raise ValueError(f"{host}: missing, old-format, changed or expired plan; run update plan again")
            candidates(plan["remote"])
            plans[host] = plan
            print(f"{host}: " + ctl.terminal(json.dumps(plan["remote"].get("changes", []), sort_keys=True)))
        print("Install only saved reviewed updates; later restarts require separate per-service approval.")
        print("Package hooks may restart services immediately. Application/scoring health is not automatically verified.")
        if not yes:
            if not sys.stdin.isatty():
                raise ValueError("apply requires a terminal or explicit --yes for package installation only")
            if ctl.ask("[y] install these saved plans, [n] abort", ["y", "n"], "n") != "y":
                print("Aborted; no updates applied.")
                return False
    failed = False
    for index, host in enumerate(hosts, 1):
        ctl.heading(host, index, len(hosts))
        directory = ctl.ROOT / "reports" / host / "updates"
        token = secrets.token_hex(16)
        report = {"host": host, "action": action, "started": time.time(), "token": token,
                  "status": "in-progress", "application_health_verified": False}
        ctl.save(directory / "result.json", report)
        try:
            check_access(ctl, host)
            services = call_host(ctl, host, "services")
            show_services(ctl, services)
            report["services_before"] = services
            if action == "plan":
                catalog = call_host(ctl, host, "plan")
                exact = review(ctl, host, catalog)
                if exact is None:
                    report["status"] = "skipped"
                else:
                    ctl.save(directory / "plan.json", {"schema": SCHEMA, "host": host,
                             "created": time.time(), "ready": True,
                             "endpoint": endpoint(ctl, variables.get(host, {})),
                             "remote": exact})
                    print(f"Saved reports/{host}/updates/plan.json (expires after 24 hours).")
                    report["status"] = "planned"
            else:
                plan = plans[host]
                if not 0 <= time.time() - plan["created"] <= 86400:
                    raise RuntimeError("plan expired during rollout; run update plan again")
                ctl.save(directory / "plan.json", dict(plan, ready=False))
                report["recovery"] = f"/var/backups/ccdc-updates/{token}"
                report["transaction"] = call_host(ctl, host, "apply", expected=plan["remote"], token=token)
                ctl.save(directory / "result.json", report)
                check_access(ctl, host)
                if not offer_restarts(ctl, host, services, report, directory):
                    report["status"] = "paused"
                    failed = True
                else:
                    check_access(ctl, host)
                    report["status"] = "updated"
                    count = len(report["deferred_restarts"])
                    print(f"{host}: updated; {count} service restart(s) deferred. Verify application/scoring health.")
        except (EOFError, KeyboardInterrupt):
            report["status"] = "interrupted"
            raise
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
            report.update(status="failed", error=str(exc))
            print(f"{host}: FAILED - " + ctl.terminal(exc), file=sys.stderr)
            failed = True
        finally:
            report["finished"] = time.time()
            ctl.save(directory / "result.json", report)
            ctl.save(directory / "runs" / (token + ".json"), report)
        if failed and action == "apply":
            print("Rollout stopped; remaining hosts untouched. Inspect result.json and recovery files.", file=sys.stderr)
            break
    return failed
