from __future__ import annotations

import asyncio
import json
import shutil
from dataclasses import dataclass
from typing import Iterable

try:
    from .models import Vulnerability
except ImportError:
    from core.models import Vulnerability


@dataclass
class ToolCheck:
    name: str
    available: bool
    path: str = ""
    message: str = ""


@dataclass
class ExternalToolResult:
    tool: str
    returncode: int
    stdout: str
    stderr: str = ""
    findings: list[Vulnerability] | None = None


_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "informational": "INFO",
    "unknown": "INFO",
}


class ExternalToolRunner:
    """Safe bridges for evidence-first external scanners.

    Nuclei and WhatWeb are not Python packages. They must be installed as system
    tools. This runner never invents findings when a tool is absent or when the
    tool output lacks target-specific evidence.
    """

    def __init__(self, rate_limit: int = 25, timeout: int = 180, templates: str | None = None):
        self.rate_limit = int(rate_limit)
        self.timeout = int(timeout)
        self.templates = templates

    def check_tool(self, name: str) -> ToolCheck:
        path = shutil.which(name)
        if not path:
            return ToolCheck(
                name=name,
                available=False,
                message=f"[FP ALERT] External tool '{name}' is not installed; no findings will be simulated.",
            )
        return ToolCheck(name=name, available=True, path=path, message=f"{name} found at {path}")

    def build_nuclei_command(self, target: str) -> list[str]:
        cmd = [
            "nuclei",
            "-u",
            target,
            "-jsonl",
            "-silent",
            "-duc",  # disable automatic update check; update explicitly with docs command
            "-rate-limit",
            str(self.rate_limit),
            "-retries",
            "1",
            "-timeout",
            "10",
        ]
        if self.templates:
            cmd.extend(["-t", self.templates])
        return cmd

    def build_whatweb_command(self, target: str) -> list[str]:
        return ["whatweb", "--log-json=-", "--no-errors", target]

    async def run_nuclei(self, target: str) -> ExternalToolResult:
        check = self.check_tool("nuclei")
        if not check.available:
            return ExternalToolResult("nuclei", 127, check.message, findings=[])
        stdout, stderr, code = await self._run(self.build_nuclei_command(target))
        return ExternalToolResult("nuclei", code, stdout, stderr, parse_nuclei_jsonl(stdout))

    async def run_whatweb(self, target: str) -> ExternalToolResult:
        check = self.check_tool("whatweb")
        if not check.available:
            return ExternalToolResult("whatweb", 127, check.message, findings=[])
        stdout, stderr, code = await self._run(self.build_whatweb_command(target))
        return ExternalToolResult("whatweb", code, stdout, stderr, parse_whatweb_json(stdout))

    async def _run(self, cmd: list[str]) -> tuple[str, str, int]:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(process.communicate(), timeout=self.timeout)
        except asyncio.TimeoutError:
            process.kill()
            out, err = await process.communicate()
            return out.decode("utf-8", errors="ignore"), "timeout exceeded", 124
        return out.decode("utf-8", errors="ignore"), err.decode("utf-8", errors="ignore"), process.returncode


def parse_nuclei_jsonl(raw: str) -> list[Vulnerability]:
    findings: list[Vulnerability] = []
    for obj in _iter_json_lines(raw):
        matched = obj.get("matched-at") or obj.get("host") or obj.get("ip")
        info = obj.get("info") or {}
        template_id = obj.get("template-id") or obj.get("template") or "unknown-template"
        matcher = obj.get("matcher-name") or obj.get("type") or "matched"
        if not matched or not info:
            continue
        severity = _SEVERITY_MAP.get(str(info.get("severity", "info")).lower(), "INFO")
        name = str(info.get("name") or template_id)
        description = str(info.get("description") or name)
        remediation = str(info.get("remediation") or "Review the affected service, update/patch the component, and restrict exposure according to the validated Nuclei template.")
        evidence_bits = [f"template={template_id}", f"matcher={matcher}", f"matched_at={matched}"]
        if obj.get("curl-command"):
            evidence_bits.append(f"poc={obj['curl-command']}")
        findings.append(
            Vulnerability(
                target=str(matched),
                vuln_type=f"Nuclei: {name}",
                severity=severity,
                impact=description,
                remediation=remediation,
                confidence="HIGH" if severity != "INFO" else "MEDIUM",
                evidence="; ".join(evidence_bits),
                false_positive_note="Validate the Nuclei template match manually when the template relies on weak matchers or version-only fingerprints.",
            )
        )
    return findings


def parse_whatweb_json(raw: str) -> list[Vulnerability]:
    try:
        data = json.loads(raw.strip())
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        entries = [data]
    elif isinstance(data, list):
        entries = data
    else:
        return []

    findings: list[Vulnerability] = []
    for entry in entries:
        target = entry.get("target") or entry.get("uri")
        plugins = entry.get("plugins") or {}
        if not target or not plugins:
            continue
        tech = _summarize_plugins(plugins)
        if not tech:
            continue
        findings.append(
            Vulnerability(
                target=str(target),
                vuln_type="Technology Fingerprint (WhatWeb)",
                severity="INFO",
                impact="WhatWeb identified exposed technologies. This is reconnaissance evidence, not a vulnerability by itself.",
                remediation="Use the fingerprint to check real product/version advisories; do not assign CVEs without product/version/advisory proof.",
                confidence="HIGH",
                evidence=tech,
                false_positive_note="Fingerprinting can be wrong behind CDNs/WAFs; verify important technology/version claims before reporting CVEs.",
            )
        )
    return findings


def _iter_json_lines(raw: str) -> Iterable[dict]:
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            yield obj


def _summarize_plugins(plugins: dict) -> str:
    parts = []
    for name, value in sorted(plugins.items()):
        detail = ""
        if isinstance(value, dict):
            versions = value.get("version") or value.get("versions")
            strings = value.get("string")
            if isinstance(versions, list) and versions:
                detail = "=" + ",".join(map(str, versions[:3]))
            elif isinstance(strings, list) and strings:
                detail = "=" + ",".join(map(str, strings[:2]))
        parts.append(f"{name}{detail}")
    return "; ".join(parts)
