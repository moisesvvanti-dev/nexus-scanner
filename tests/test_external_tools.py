import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.external_tools import ExternalToolRunner, parse_nuclei_jsonl, parse_whatweb_json


def test_parse_nuclei_requires_real_matched_result_and_evidence():
    raw = "\n".join([
        json.dumps({"template-id": "missing-matched", "info": {"severity": "high", "name": "No Match"}}),
        json.dumps({
            "template-id": "exposed-panel",
            "info": {"severity": "high", "name": "Admin Panel Exposure", "description": "panel exposed", "remediation": "Restrict access"},
            "matched-at": "https://authorized.example/admin",
            "matcher-name": "status-200",
            "curl-command": "curl -i https://authorized.example/admin",
        }),
    ])

    findings = parse_nuclei_jsonl(raw)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.target == "https://authorized.example/admin"
    assert finding.severity == "HIGH"
    assert finding.confidence == "HIGH"
    assert "template=exposed-panel" in finding.evidence
    assert "status-200" in finding.evidence


def test_parse_whatweb_creates_fingerprint_info_not_vulnerability():
    raw = json.dumps([
        {
            "target": "https://authorized.example",
            "plugins": {
                "nginx": {"version": ["1.25.4"]},
                "HTTPServer": {"string": ["nginx/1.25.4"]},
            },
        }
    ])

    findings = parse_whatweb_json(raw)

    assert len(findings) == 1
    assert findings[0].severity == "INFO"
    assert findings[0].vuln_type == "Technology Fingerprint (WhatWeb)"
    assert findings[0].confidence == "HIGH"
    assert "nginx" in findings[0].evidence


def test_command_builders_are_safe_and_authorized_scope_only():
    runner = ExternalToolRunner(rate_limit=7, timeout=44)

    nuclei_cmd = runner.build_nuclei_command("https://authorized.example")
    whatweb_cmd = runner.build_whatweb_command("https://authorized.example")

    assert nuclei_cmd[:3] == ["nuclei", "-u", "https://authorized.example"]
    assert "-jsonl" in nuclei_cmd
    assert "-rate-limit" in nuclei_cmd
    assert "7" in nuclei_cmd
    assert "-duc" in nuclei_cmd  # disable update check; updates are explicit, not hidden during scan
    assert whatweb_cmd == ["whatweb", "--log-json=-", "--no-errors", "https://authorized.example"]


def test_missing_external_tool_returns_fp_alert_not_fake_finding(monkeypatch):
    runner = ExternalToolRunner()
    monkeypatch.setattr("core.external_tools.shutil.which", lambda name: None)

    result = runner.check_tool("nuclei")

    assert result.available is False
    assert "[FP ALERT]" in result.message
    assert "not installed" in result.message
