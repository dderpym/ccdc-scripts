"""`ccdcctl scan`: run every registered scanner, then (optionally) every matching autofix."""
from concurrent.futures import ThreadPoolExecutor

from ccdc import registry
from ccdc.findings import SEVERITIES


def scan_target(target, scanners):
    findings, errors = [], []
    for scanner in scanners:
        try:
            result = scanner.run(target)
        except Exception as exc:  # one broken scanner must not hide the others
            errors.append(f"{scanner.name}: {exc}")
            continue
        findings.extend(result)
        errors.extend(f"{scanner.name}: {e}" for e in result.errors)
    return list(dict.fromkeys(findings)), errors  # identical findings from overlapping scanners collapse


def scan_all(targets, scanners=None, workers=10):
    scanners = registry.scanners() if scanners is None else scanners
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return dict(zip(targets, pool.map(lambda t: scan_target(t, scanners), targets)))


def apply_fixes(findings, autofix, approve=lambda finding, text: True, out=print):
    """Run the fix for every fixable finding the callback approves; returns [(finding, ok, detail)]."""
    outcome = []
    for finding in findings:
        if not autofix.can_fix(finding):
            continue
        text = autofix.describe(finding)
        if not approve(finding, text):
            continue
        try:
            autofix.get_fix(finding).run()
            outcome.append((finding, True, text))
        except Exception as exc:
            outcome.append((finding, False, f"{text}: {exc}"))
        out(("fixed   " if outcome[-1][1] else "FAILED  ") + outcome[-1][2])
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
