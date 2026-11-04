"""`ccdcctl scan`: run every registered scanner, then (optionally) every matching autofix."""
from concurrent.futures import ThreadPoolExecutor

from ccdc import registry
from ccdc.findings import SEVERITIES


def scan_target(target, scanners):
    findings, errors = [], []
    for scanner in scanners:
        getattr(scanner, "begin_round", lambda t: None)(target)  # duck-typed scanners may lack rounds
    try:
        for scanner in scanners:
            try:
                result = scanner.run(target)
            except Exception as exc:  # one broken scanner must not hide the others
                errors.append(f"{scanner.name}: {exc}")
                continue
            findings.extend(result)
            errors.extend(f"{scanner.name}: {e}" for e in result.errors)
    finally:
        for scanner in scanners:
            getattr(scanner, "end_round", lambda t: None)(target)
    return list(dict.fromkeys(findings)), errors  # identical findings from overlapping scanners collapse


def scan_all(targets, scanners=None, workers=10):
    scanners = registry.scanners() if scanners is None else scanners
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return dict(zip(targets, pool.map(lambda t: scan_target(t, scanners), targets)))


def apply_fixes(findings, autofix, approve=lambda finding, text: True, out=print):
    """Run the fix for every fixable finding the callback approves; returns [(finding, ok, detail)].

    Approved findings that share an AutoFix group key are fixed by one script run, so a
    host with several deviating settings gets one change, one proof and one watchdog.
    """
    approved = []
    for finding in findings:
        if autofix.can_fix(finding):
            text = autofix.describe(finding)
            if approve(finding, text):
                approved.append((finding, text))
    batches, order = {}, []
    for finding, text in approved:
        key = autofix.group_key(finding)
        key = ("single", len(order)) if key is None else key
        if key not in batches:
            batches[key] = []
            order.append(key)
        batches[key].append((finding, text))
    outcome = []
    for key in order:
        members = batches[key]
        try:
            if autofix.group_key(members[0][0]) is None:
                autofix.get_fix(members[0][0]).run()
            else:
                autofix.get_group_fix([f for f, _ in members]).run()
            results = [(f, True, text) for f, text in members]
        except Exception as exc:
            results = [(f, False, f"{text}: {exc}") for f, text in members]
        for row in results:
            out(("fixed   " if row[1] else "FAILED  ") + row[2])
        outcome.extend(results)
    return outcome


def report(results, autofix, out=print):
    bad = False
    for target, (findings, errors) in results.items():
        out(f"\n=== {target} ===")
        for severity in SEVERITIES:
            for finding in (f for f in findings if f.severity == severity):
                mark = "fixable " if autofix.can_fix(finding) else ""
                out(f"  {severity.upper():8} {mark}{finding.summary}")
        for error in errors[:10]:
            out(f"  WARNING scanner: {error}")
        if errors:
            out("  Scan incomplete; absence of findings does not prove a clean host.")
        bad = bad or bool(findings or errors)
    return bad
