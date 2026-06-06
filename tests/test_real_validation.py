import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.cve_scanner import CVEScanner
from core.directory_bruter import DirectoryBruter


class FakeResponse:
    def __init__(self, status=200, text="", headers=None):
        self.status = status
        self._text = text
        self.headers = headers or {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self, *args, **kwargs):
        return self._text

    async def read(self):
        return self._text.encode()


class FakeSession:
    def __init__(self, routes):
        self.routes = routes
        self.requested = []

    def _response_for(self, method, url):
        self.requested.append((method, url))
        value = self.routes(method, url) if callable(self.routes) else self.routes.get((method, url), self.routes.get(url))
        if value is None:
            value = FakeResponse(404, "not found")
        return value

    def get(self, url, **kwargs):
        return self._response_for("GET", url)

    def post(self, url, **kwargs):
        return self._response_for("POST", url)

    def request(self, method, url, **kwargs):
        return self._response_for(method, url)


def test_cve_scanner_rejects_unresolved_templates_and_alerts_fp():
    async def run():
        session = FakeSession({})
        scanner = CVEScanner(session, strict_validation=False)
        findings, logs = [], []
        scanner.finding_found.connect(findings.append)
        scanner.log_message.connect(logs.append)
        scanner.cve_signatures = [{
            "name": "Bad synced template", "check_type": "path", "path": "/?x={{randstr}}",
            "indicator": "VULNERABLE:", "status": [200],
        }]
        await scanner.scan("https://example.test")
        assert findings == []
        assert any("FP ALERT" in msg and "unresolved" in msg for msg in logs)
        assert not session.requested, "unexecutable templates must not trigger simulated HTTP checks"
    asyncio.run(run())


def test_cve_scanner_rejects_soft_404_indicator_match():
    async def run():
        body = "<html><title>Not Found</title>Content-Security-Policy missing</html>"
        session = FakeSession(lambda method, url: FakeResponse(200, body))
        scanner = CVEScanner(session, strict_validation=True)
        findings, logs = [], []
        scanner.finding_found.connect(findings.append)
        scanner.log_message.connect(logs.append)
        scanner.cve_signatures = [{
            "name": "Generic CSP false positive", "category": "Exploit", "type": "Auto-Synced",
            "check_type": "path", "path": "/admin", "indicator": "Content-Security-Policy", "status": [200],
        }]
        await scanner.scan("https://example.test")
        assert findings == []
        assert any("FP ALERT" in msg for msg in logs)
    asyncio.run(run())


def test_cve_scanner_reports_confirmed_lfi_with_confidence_metadata():
    async def run():
        session = FakeSession({"https://example.test/passwd": FakeResponse(200, "root:x:0:0:root:/root:/bin/bash\n")})
        scanner = CVEScanner(session, strict_validation=False)
        findings = []
        scanner.finding_found.connect(findings.append)
        scanner.cve_signatures = [{
            "name": "Real passwd LFI", "category": "LFI", "type": "LFI", "check_type": "path",
            "path": "/passwd", "indicator": "root:x:0:0", "status": [200],
        }]
        await scanner.scan("https://example.test")
        assert len(findings) == 1
        assert findings[0].severity == "CRITICAL"
        assert findings[0].confidence == "CONFIRMED"
        assert findings[0].evidence == "root:x:0:0"
    asyncio.run(run())


def test_directory_bruter_alerts_and_suppresses_soft_404_hits():
    async def run():
        body = "<html>custom not found page</html>"
        session = FakeSession(lambda method, url: FakeResponse(200, body))
        bruter = DirectoryBruter(session, strict_validation=True)
        bruter.wordlist = ["admin/"]
        findings, logs = [], []
        bruter.finding_found.connect(findings.append)
        bruter.log_message.connect(logs.append)
        await bruter.run("https://example.test")
        assert findings == []
        assert any("FP ALERT" in msg for msg in logs)
    asyncio.run(run())
