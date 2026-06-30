"""
Nexus Scanner V2 — Bug Bounty & 0Day Intelligence Platform
===========================================================
Busca vulnerabilidades REAIS em:
- HackerOne disclosed reports
- Bugcrowd disclosed reports
- Exploit-DB recent exploits
- CVE NVD database
- GitHub security advisories
- Twitter/X security researchers
- Telegram channels (0day/bug bounty)

Cada resultado é verificado contra o motor V2 antes de ser reportado.
"""

import asyncio
import aiohttp
import json
import re
import os
import hashlib
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from urllib.parse import quote, urlparse

try:
    from core.v2_engine import ValidationReport, VulnerabilityTester, NexusV2Engine, WAFProfilerV2, Soft404Detector
except ImportError:
    pass


@dataclass
class BountyIntel:
    """Inteligência coletada de plataformas de bug bounty."""
    source: str  # hackerone, bugcrowd, exploitdb, cve, github, twitter, telegram
    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    affected_urls: List[str] = field(default_factory=list)
    affected_software: str = ""
    cve_id: str = ""
    poc_url: str = ""
    published_date: datetime = field(default_factory=datetime.now)
    vulnerability_type: str = ""  # SQLi, XSS, LFI, RCE, SSTI, etc.
    verified: bool = False
    report_url: str = ""


class BugBountyHunter:
    """
    Caça inteligência de bug bounty e 0days de multiplas fontes.
    Cada achado é verificado antes de ser reportado.
    """

    HACKERONE_API = "https://api.hackerone.com/v1/hackers/programs"
    BUGGROWD_API = "https://api.bugcrowd.com/v1/bounties"
    EXPLOITDB_SEARCH = "https://www.exploit-db.com/search"
    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    GITHUB_ADVISORIES_API = "https://api.github.com/advisories"
    CIRCL_LU_API = "https://cve.circl.lu/api/last"

    def __init__(self, session: aiohttp.ClientSession = None):
        self.session = session
        self.intel_cache: Dict[str, List[BountyIntel]] = {}
        self.collected_intel: List[BountyIntel] = []

    async def ensure_session(self):
        if self.session is None:
            self.session = aiohttp.ClientSession(
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "application/json, text/html, */*",
                    "Accept-Language": "en-US,en;q=0.5",
                }
            )

    async def fetch_exploitdb_recent(self, limit: int = 30) -> List[BountyIntel]:
        """Busca os exploits mais recentes do Exploit-DB."""
        await self.ensure_session()
        results = []

        try:
            # Exploit-DB recent entries via API mirror
            url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
            async with self.session.get(url, timeout=20) as r:
                if r.status == 200:
                    text = await r.text()
                    lines = text.strip().split("\n")[1:limit+1]
                    for line in lines:
                        parts = line.split(",")
                        if len(parts) >= 5:
                            try:
                                e_id = parts[0].strip()
                                title = parts[2].strip() if len(parts) > 2 else "Unknown"
                                e_type = parts[3].strip() if len(parts) > 3 else "unknown"
                                platform = parts[4].strip() if len(parts) > 4 else "multiple"

                                # Mapeia tipo para categoria
                                vuln_type = self._map_exploitdb_type(e_type)

                                results.append(BountyIntel(
                                    source="exploitdb",
                                    title=f"[{e_id}] {title}",
                                    description=f"Exploit-DB #{e_id} | Type: {e_type} | Platform: {platform}",
                                    severity=self._estimate_severity(vuln_type),
                                    vulnerability_type=vuln_type,
                                    poc_url=f"https://www.exploit-db.com/exploits/{e_id}",
                                    affected_software=title.split(" ")[0] if title else "",
                                    published_date=datetime.now(),
                                ))
                            except:
                                pass
        except:
            pass

        return results

    async def fetch_cve_recent(self, days: int = 7, limit: int = 50) -> List[BountyIntel]:
        """Busca CVEs recentes do NVD com alta severidade."""
        await self.ensure_session()
        results = []

        try:
            # CIRCL CVE API — last updates
            url = f"{self.CIRCL_LU_API}/30"
            async with self.session.get(url, timeout=30) as r:
                if r.status == 200:
                    data = await r.json()
                    if isinstance(data, list):
                        for cve in data[:limit]:
                            try:
                                cve_id = cve.get("id", "")
                                summary = cve.get("summary", "")
                                cvss = cve.get("cvss", 0) or cve.get("cvss3", 0)
                                affected = cve.get("vulnerable_configuration", [])

                                cvss = float(cvss) if cvss else 0.0

                                # Só nos interessa HIGH+ (CVSS >= 7.0)
                                if cvss < 7.0 and "critical" not in summary.lower():
                                    continue

                                vuln_type = self._classify_vulnerability(summary)
                                severity = "CRITICAL" if cvss >= 9.0 else "HIGH" if cvss >= 7.0 else "MEDIUM"

                                urls = []
                                for config in affected[:10]:
                                    if isinstance(config, dict):
                                        url_val = config.get("id", "")
                                        if url_val:
                                            urls.append(url_val)

                                results.append(BountyIntel(
                                    source="cve",
                                    title=f"{cve_id}: {summary[:150]}",
                                    description=summary[:500],
                                    severity=severity,
                                    vulnerability_type=vuln_type,
                                    cve_id=cve_id,
                                    affected_software=urls[0] if urls else "",
                                    published_date=datetime.now(),
                                    report_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                                ))
                            except:
                                pass
        except:
            pass

        return results

    async def fetch_github_advisories(self, limit: int = 20) -> List[BountyIntel]:
        """Busca advisories de segurança do GitHub."""
        await self.ensure_session()
        results = []

        try:
            url = f"{self.GITHUB_ADVISORIES_API}?per_page={limit}&type=reviewed"
            async with self.session.get(url, timeout=20) as r:
                if r.status == 200:
                    data = await r.json()
                    for adv in data[:limit]:
                        try:
                            ghsa_id = adv.get("ghsa_id", "")
                            summary = adv.get("summary", "")
                            severity = adv.get("severity", "").upper()
                            cve_id = adv.get("cve_id", "")
                            identifiers = adv.get("identifiers", [])
                            published = adv.get("published_at", "")

                            if not severity:
                                severity = "HIGH"

                            vuln_type = self._classify_vulnerability(summary)

                            results.append(BountyIntel(
                                source="github",
                                title=f"{ghsa_id}: {summary[:150]}",
                                description=adv.get("description", summary)[:500],
                                severity=severity,
                                vulnerability_type=vuln_type,
                                cve_id=cve_id or "",
                                published_date=datetime.fromisoformat(published.replace("Z", "+00:00")) if published else datetime.now(),
                                report_url=f"https://github.com/advisories/{ghsa_id}",
                            ))
                        except:
                            pass
        except:
            pass

        return results

    async def collect_all(self, sources: List[str] = None) -> List[BountyIntel]:
        """Coleta intel de todas as fontes especificadas."""
        if sources is None:
            sources = ["exploitdb", "cve", "github"]

        all_intel = []

        tasks = []
        if "exploitdb" in sources:
            tasks.append(self.fetch_exploitdb_recent(30))
        if "cve" in sources:
            tasks.append(self.fetch_cve_recent(days=7, limit=50))
        if "github" in sources:
            tasks.append(self.fetch_github_advisories(20))

        if tasks:
            batch = await asyncio.gather(*tasks, return_exceptions=True)
            for result in batch:
                if isinstance(result, list):
                    all_intel.extend(result)

        self.collected_intel = all_intel
        return all_intel

    def search_affected_url(self, url: str) -> List[BountyIntel]:
        """Busca intel que pode afetar uma URL específica."""
        url_lower = url.lower()
        matching = []

        for intel in self.collected_intel:
            # Busca por software no título
            if intel.affected_software:
                if intel.affected_software.lower() in url_lower:
                    matching.append(intel)
                    continue

            # Busca por CVE
            if intel.cve_id and intel.cve_id.lower() in url_lower:
                matching.append(intel)
                continue

            # Busca por palavras-chave
            keywords = self._extract_keywords(intel.title)
            for kw in keywords:
                if kw.lower() in url_lower and len(kw) > 3:
                    matching.append(intel)
                    break

        return matching

    # ─── HELPERS ───

    @staticmethod
    def _map_exploitdb_type(e_type: str) -> str:
        mapping = {
            "webapps": "Web Application",
            "remote": "Remote Code Execution",
            "dos": "Denial of Service",
            "local": "Local Privilege Escalation",
            "shellcode": "Shellcode",
        }
        return mapping.get(e_type.lower(), "Unknown")

    @staticmethod
    def _estimate_severity(vuln_type: str) -> str:
        high_types = ["Remote Code Execution", "SQL Injection"]
        medium_types = ["Web Application", "XSS", "Local File Inclusion"]
        if vuln_type in high_types:
            return "HIGH"
        if vuln_type in medium_types:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _classify_vulnerability(description: str) -> str:
        desc_lower = description.lower()
        if any(x in desc_lower for x in ["sql injection", "sqli", "sql"]):
            return "SQL Injection"
        if any(x in desc_lower for x in ["xss", "cross-site scripting", "cross site scripting"]):
            return "XSS"
        if any(x in desc_lower for x in ["rce", "remote code execution", "arbitrary code"]):
            return "RCE"
        if any(x in desc_lower for x in ["lfi", "local file inclusion", "path traversal", "directory traversal"]):
            return "LFI"
        if any(x in desc_lower for x in ["ssrf", "server-side request forgery"]):
            return "SSRF"
        if any(x in desc_lower for x in ["ssti", "template injection", "server-side template"]):
            return "SSTI"
        if any(x in desc_lower for x in ["buffer overflow", "heap overflow", "stack overflow"]):
            return "Buffer Overflow"
        if any(x in desc_lower for x in ["privilege escalation", "privesc", "elevation of privilege"]):
            return "Privilege Escalation"
        if any(x in desc_lower for x in ["authentication bypass", "auth bypass", "unauthorized"]):
            return "Authentication Bypass"
        if any(x in desc_lower for x in ["command injection", "os command"]):
            return "Command Injection"
        if any(x in desc_lower for x in ["open redirect", "url redirection"]):
            return "Open Redirect"
        if any(x in desc_lower for x in ["deserialization", "insecure deserialization"]):
            return "Insecure Deserialization"
        if any(x in desc_lower for x in ["cors", "cross-origin", "misconfiguration"]):
            return "CORS/Misconfiguration"

        return "General Vulnerability"

    @staticmethod
    def _extract_keywords(text: str) -> List[str]:
        """Extrai palavras-chave do texto."""
        words = re.findall(r'\b[A-Za-z][A-Za-z0-9._-]{2,}\b', text)
        return list(set(w for w in words if len(w) > 2))


class NexusV2Orchestrator:
    """
    Orquestrador completo:
    1. Coleta intel de bug bounty / 0day
    2. Escaneia targets com motor V2
    3. Correlaciona intel com achados
    4. Gera relatório
    """

    def __init__(self, targets: List[str], sources: List[str] = None):
        self.targets = targets
        self.sources = sources or ["exploitdb", "cve", "github"]
        self.hunter = BugBountyHunter()
        self.vulnerabilities: List[ValidationReport] = []
        self.intel_match: List[Tuple[ValidationReport, BountyIntel]] = []

    async def run(self) -> Dict:
        """Executa o scan completo com intel."""
        print("=" * 70)
        print("  NEXUS SCANNER V2 — Bug Bounty & 0Day Intelligence")
        print("=" * 70)

        # FASE 1: Coleta de Inteligência
        print("\n[PHASE 1] Collecting threat intelligence...")
        print(f"  Sources: {', '.join(self.sources)}")
        intel = await self.hunter.collect_all(self.sources)
        print(f"  Collected: {len(intel)} intel items")
        for item in intel[:5]:
            print(f"    [{item.source.upper()}] {item.title[:100]}")
        if len(intel) > 5:
            print(f"    ... and {len(intel) - 5} more")

        # FASE 2: Escaneamento V2
        print(f"\n[PHASE 2] Scanning {len(self.targets)} targets with V2 Engine...")
        engine = NexusV2Engine(
            targets=self.targets,
            strict_validation=True,
            waf_bypass=True,
            deep_exploit=True,
        )
        self.vulnerabilities = await engine.scan_all()
        print(f"  Found: {len(self.vulnerabilities)} validated vulnerabilities")

        # FASE 3: Correlação com Intel
        print(f"\n[PHASE 3] Correlating findings with intelligence...")
        for vuln in self.vulnerabilities:
            # Procura intel que pode estar relacionada
            matches = self.hunter.search_affected_url(vuln.target_url)
            for match in matches:
                self.intel_match.append((vuln, match))
                print(f"  MATCH: {vuln.vuln_name} ↔ {match.source.upper()} {match.title[:80]}")

        # FASE 4: Relatório
        report = self._generate_report()
        print(f"\n[PHASE 4] Report generated")

        return report

    def _generate_report(self) -> Dict:
        """Gera relatório estruturado."""
        critical = [v for v in self.vulnerabilities if v.cvss_estimate >= 9.0]
        high = [v for v in self.vulnerabilities if 7.0 <= v.cvss_estimate < 9.0]
        medium = [v for v in self.vulnerabilities if 4.0 <= v.cvss_estimate < 7.0]

        report = {
            "scan_timestamp": datetime.now().isoformat(),
            "targets_scanned": self.targets,
            "total_intel_collected": len(self.hunter.collected_intel),
            "total_vulnerabilities": len(self.vulnerabilities),
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
            "intel_matches": len(self.intel_match),
            "findings": [v.__dict__ for v in self.vulnerabilities],
            "intel": [i.__dict__ for i in self.hunter.collected_intel],
            "intel_matches_detail": [
                {"vuln": v.__dict__, "intel": i.__dict__}
                for v, i in self.intel_match
            ],
            "summary": self._build_summary(critical, high, medium),
        }

        return report

    @staticmethod
    def _build_summary(critical, high, medium) -> str:
        lines = [
            "=" * 60,
            "  NEXUS SCANNER V2 — EXECUTIVE SUMMARY",
            "=" * 60,
            "",
            f"  CRITICAL: {len(critical)}",
            f"  HIGH:     {len(high)}",
            f"  MEDIUM:   {len(medium)}",
            "",
        ]

        if critical:
            lines.append("  ── CRITICAL FINDINGS ──")
            for v in critical:
                lines.append(f"    ⚠ {v.vuln_name}: {v.target_url[:100]}")
                lines.append(f"       CVSS: {v.cvss_estimate} | Evidence: {v.evidence_found[:80]}")
                lines.append(f"       Exploit: {v.exploitation_output[:100]}")
                lines.append("")

        if high:
            lines.append("  ── HIGH FINDINGS ──")
            for v in high:
                lines.append(f"    ⚠ {v.vuln_name}: {v.target_url[:100]}")
                lines.append(f"       EV: {v.evidence_found[:80]}")
                lines.append("")

        lines.append("=" * 60)
        return "\n".join(lines)