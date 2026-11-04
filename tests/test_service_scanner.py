from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ccdc.scanners.services import DockerSocketMount, ServiceScanner, UninspectedService  # noqa: E402
from ccdc.target import Target  # noqa: E402

TARGET = Target("web01")


class Runner:
    def __init__(self, document):
        self.document, self.calls = document, []

    def entry(self, target, entry, args=(), **request):
        self.calls.append((entry, list(args)))
        return self.document


class ServiceScannerTests(unittest.TestCase):
    def test_typed_findings(self):
        runner = Runner({"errors": [], "findings": [
            {"id": "extra-services-unverified", "severity": "warning", "summary": "s",
             "context": [{"summary": "Not inspected", "evidence": ["sssd.service: ExecStart syntax/path unknown"]}]},
            {"id": "extra-docker-sock-mounts", "severity": "warning", "summary": "s",
             "context": [{"summary": "runtime socket mounted: /var/run/docker.sock:/var/run/docker.sock",
                          "evidence": ["container abc123"]}]},
            {"id": "scanner-extra-services", "severity": "warning", "summary": "gap", "context": []},
        ]})
        result = ServiceScanner(runner).run(TARGET)
        self.assertEqual(list(result), [
            UninspectedService(TARGET, "sssd.service", "ExecStart syntax/path unknown"),
            DockerSocketMount(TARGET, "container abc123", "/var/run/docker.sock:/var/run/docker.sock")])
        self.assertEqual(runner.calls[0][0], "discover_lse")
        self.assertIn("extra-docker-sock-mounts", runner.calls[0][1][1])


if __name__ == "__main__":
    unittest.main()
