import asyncio
import html
import os
import random
import re
import string
from dataclasses import dataclass
from difflib import SequenceMatcher
from urllib.parse import urljoin

from core.qt_compat import QObject, Signal
from core.models import Vulnerability


@dataclass
class _Baseline404:
    status_a: int = 0
    status_b: int = 0
    length_a: int = -1
    length_b: int = -1
    text_a: str = ""
    text_b: str = ""

    @property
    def ready(self) -> bool:
        return self.length_a >= 0 and self.length_b >= 0


class CVEScanner(QObject):
    """CVE/signature scanner with strict evidence validation.

    The previous implementation reported any configured indicator as a CRITICAL
    CVE. That produced many false positives, especially with auto-synced Nuclei
    templates containing unresolved placeholders or generic strings such as
    ``Content-Security-Policy``. This scanner now fails closed: unsupported
    templates are skipped, soft-404 responses are rejected, and findings are
    emitted only with concrete evidence and confidence metadata.
    """

    finding_found = Signal(object)
    log_message = Signal(str)

    GENERIC_INDICATORS = {
        "content-security-policy",
        "vulnerable:",
        "target appears to be vulnerable",
        "error",
        "success",
        "ok",
        "login",
        "admin",
        "forbidden",
        "not found",
    }

    HIGH_CONFIDENCE_TYPES = {"LFI", "RFI", "SQLI", "SENSITIVE", "CONFIG", "EXPOSURE"}

    def __init__(self, session, strict_validation=True):
        super().__init__()
        self.session = session
        self.strict_validation = strict_validation
        self.cve_signatures = []
        self._baseline_404 = _Baseline404()
        self._load_signatures()

    def _load_signatures(self):
        """Loads CVE signatures from data/cve.json."""
        try:
            import json

            paths = [
                os.path.join("data", "cve.json"),
                os.path.join(os.path.dirname(__file__), "..", "data", "cve.json"),
            ]

            for p in paths:
                if os.path.exists(p):
                    with open(p, "r", encoding="utf-8") as f:
                        self.cve_signatures = json.load(f)
                    self.log_message.emit(
                        f"<span style='color:#aaa'>[*] Loaded {len(self.cve_signatures)} CVE definitions from {p}</span>"
                    )
                    return

            self.log_message.emit("<span style='color:#ff5555'>[!] CVE Database not found. Using minimal fallback.</span>")
            self.cve_signatures = [
                {
                    "name": "PHP Info Disclosure (Fallback)",
                    "category": "Info",
                    "type": "Info",
                    "check_type": "path",
                    "path": "/phpinfo.php",
                    "indicator": "PHP Version",
                    "status": [200],
                }
            ]
        except Exception as e:
            self.log_message.emit(f"<span style='color:#ff0000'>[!] Error loading CVE database: {str(e)}</span>")

    async def scan(self, target_url):
        self.log_message.emit(
            f"<span style='color:#00f3ff'>[*] Initiating REAL CVE Scan ({len(self.cve_signatures)} Signatures, strict_validation={self.strict_validation})...</span>"
        )
        base_url = target_url.rstrip("/")

        if self.strict_validation:
            await self._profile_soft_404(base_url)

        sem = asyncio.Semaphore(50)

        async def _bounded_check(sig):
            async with sem:
                await self._check_signature(base_url, sig)

        for i in range(0, len(self.cve_signatures), 200):
            batch = self.cve_signatures[i : i + 200]
            await asyncio.gather(*[_bounded_check(sig) for sig in batch])

    async def _profile_soft_404(self, base_url):
        token1 = "nexus-fp-check-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        token2 = "nexus-fp-check-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=18))
        urls = [urljoin(base_url + "/", token1), urljoin(base_url + "/", token2)]
        try:
            async with self.session.get(urls[0], timeout=7, allow_redirects=True) as r1:
                body1 = await r1.text(errors="ignore")
            async with self.session.get(urls[1], timeout=7, allow_redirects=True) as r2:
                body2 = await r2.text(errors="ignore")
            self._baseline_404 = _Baseline404(r1.status, r2.status, len(body1), len(body2), self._normalize(body1), self._normalize(body2))
            self.log_message.emit(
                f"<span style='color:#888'>[STRICT] CVE soft-404 baseline: {self._baseline_404.length_a}/{self._baseline_404.length_b} bytes.</span>"
            )
        except Exception as e:
            self.log_message.emit(f"<span style='color:#ffaa00'>[STRICT] CVE soft-404 baseline failed: {str(e)}</span>")
            self._baseline_404 = _Baseline404()

    async def _check_signature(self, base_url, sig):
        try:
            name = sig.get("name", "Unnamed signature")
            check_type = str(sig.get("check_type", "path")).lower()
            if check_type == "header":
                await self._check_header_signature(base_url, sig)
                return
            if check_type == "post":
                await self._check_post_signature(base_url, sig)
                return
            if check_type != "path":
                self._warn_false_positive(name, "unsupported check_type; skipped instead of simulating a result")
                return

            path = self._resolve_path(sig.get("path", ""))
            if path is None:
                self._warn_false_positive(name, "unresolved template placeholders in path")
                return

            target = urljoin(base_url + "/", path.lstrip("/"))
            async with self.session.get(target, timeout=7, allow_redirects=True) as r:
                content = await r.text(errors="ignore")
                headers = dict(getattr(r, "headers", {}) or {})
                await self._evaluate_response(target, r.status, content, headers, sig)
        except Exception as e:
            self.log_message.emit(f"<span style='color:#888'>[CVE] Skipped signature due to request error: {str(e)}</span>")

    async def _check_header_signature(self, base_url, sig):
        name = sig.get("name", "Unnamed signature")
        indicator = sig.get("indicator", "")
        if not indicator or self._is_generic_indicator(indicator):
            self._warn_false_positive(name, "header signature has no specific indicator")
            return
        async with self.session.get(base_url, headers=sig.get("headers", {}), timeout=7, allow_redirects=True) as r:
            headers_text = "\n".join(f"{k}: {v}" for k, v in getattr(r, "headers", {}).items())
            await self._evaluate_response(base_url, r.status, headers_text, dict(getattr(r, "headers", {}) or {}), sig)

    async def _check_post_signature(self, base_url, sig):
        name = sig.get("name", "Unnamed signature")
        path = self._resolve_path(sig.get("path", ""))
        if path is None:
            self._warn_false_positive(name, "unresolved POST template placeholders in path")
            return
        target = urljoin(base_url + "/", path.lstrip("/"))
        async with self.session.post(target, data=sig.get("data", {}), timeout=7, allow_redirects=True) as r:
            content = await r.text(errors="ignore")
            await self._evaluate_response(target, r.status, content, dict(getattr(r, "headers", {}) or {}), sig)

    async def _evaluate_response(self, target, status, content, headers, sig):
        name = sig.get("name", "Unnamed signature")
        valid_status = sig.get("status")
        if valid_status and status not in valid_status:
            return

        if self.strict_validation and self._looks_like_soft_404(status, content):
            self._warn_false_positive(name, f"soft-404 baseline matched at {target}")
            return

        ok, reason, confidence, evidence = self._validate_evidence(content, headers, sig)
        if not ok:
            self._warn_false_positive(name, reason)
            return

        if sig.get("category") == "Fingerprinting":
            self.log_message.emit(f"<span style='color:#00f3ff'>[*] Fingerprint confirmed: {name} ({evidence})</span>")
            return

        severity = self._severity_for(sig, confidence)
        self._report_vuln(target, name, sig.get("type", "CVE"), evidence, severity, confidence)

    def _resolve_path(self, raw_path):
        raw_path = str(raw_path or "/")
        raw_path = raw_path.replace("{{BaseURL}}", "").replace("{{RootURL}}", "")
        # Anything else is a partial Nuclei/template expression and cannot be
        # executed truthfully by this simple scanner.
        if "{{" in raw_path or "}}" in raw_path:
            return None
        return raw_path or "/"

    def _validate_evidence(self, content, headers, sig):
        indicator = str(sig.get("indicator", "") or "")
        category = str(sig.get("category", "") or "")
        vuln_type = str(sig.get("type", "") or "")
        name = str(sig.get("name", "") or "")

        if not indicator:
            return False, "signature has no indicator; status code alone is not proof", "LOW", ""

        body = content or ""
        decoded_indicator = html.unescape(indicator)
        if decoded_indicator not in body and indicator not in body:
            return False, f"indicator '{indicator}' not present in response", "LOW", ""

        lowered_indicator = indicator.strip().lower()
        if self._is_generic_indicator(indicator):
            return False, f"generic indicator '{indicator}' is not enough evidence", "LOW", indicator

        lower_type_blob = f"{category} {vuln_type} {name}".upper()
        body_lower = body.lower()

        if "LFI" in lower_type_blob or "PATH TRAVERSAL" in lower_type_blob:
            lfi_markers = ["root:x:0:0", "[extensions]", "[fonts]", "boot loader", "daemon:x:"]
            if any(marker.lower() in body_lower for marker in lfi_markers):
                return True, "confirmed LFI marker", "CONFIRMED", indicator
            return False, "LFI signature did not include OS file markers", "LOW", indicator

        if any(t in lower_type_blob for t in ["INFO", "FINGERPRINT"]):
            return True, "fingerprint indicator present", "MEDIUM", indicator

        # Auto-synced exploit signatures are trusted only if the indicator is
        # specific and appears in a compact, non-generic response.
        normalized = self._normalize(body)
        if len(normalized) > 50000 and "<html" in body_lower:
            return False, "indicator found inside a very large HTML page; likely generic noise", "LOW", indicator

        confidence = "HIGH" if any(t in lower_type_blob for t in self.HIGH_CONFIDENCE_TYPES) else "MEDIUM"
        return True, "specific indicator present", confidence, indicator

    def _is_generic_indicator(self, indicator):
        ind = str(indicator or "").strip().lower()
        return len(ind) < 6 or ind in self.GENERIC_INDICATORS

    def _looks_like_soft_404(self, status, content):
        if not self._baseline_404.ready:
            return False
        if status not in {200, 403, 404}:
            return False
        norm = self._normalize(content)
        length = len(content or "")
        avg_len = (self._baseline_404.length_a + self._baseline_404.length_b) / 2
        variance = abs(self._baseline_404.length_a - self._baseline_404.length_b)
        length_close = abs(length - avg_len) <= max(200, variance * 2)
        ratio_a = SequenceMatcher(None, norm[:2000], self._baseline_404.text_a[:2000]).ratio()
        ratio_b = SequenceMatcher(None, norm[:2000], self._baseline_404.text_b[:2000]).ratio()
        return length_close and max(ratio_a, ratio_b) >= 0.90

    def _normalize(self, text):
        text = re.sub(r"nexus-fp-check-[a-z0-9]+", "NEXUS_FP_TOKEN", text or "", flags=re.I)
        text = re.sub(r"\s+", " ", text).strip().lower()
        return text

    def _severity_for(self, sig, confidence):
        explicit = str(sig.get("severity", "") or "").upper()
        if explicit in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            return explicit
        if confidence == "CONFIRMED":
            return "CRITICAL"
        if confidence == "HIGH":
            return "HIGH"
        return "MEDIUM"

    def _warn_false_positive(self, name, reason):
        self.log_message.emit(
            f"<span style='color:#ffaa00'>[FP ALERT] {name}: rejected as possible false positive ({reason}).</span>"
        )

    def _report_vuln(self, target, name, vuln_type, evidence, severity, confidence):
        vuln = Vulnerability(
            target=target,
            vuln_type=vuln_type,
            severity=severity,
            impact=f"{name}: confirmed indicator '{evidence}' at {target}",
            confidence=confidence,
            evidence=evidence,
            comando_direto=f"curl -v \"{target}\"",
        )
        self.finding_found.emit(vuln)
        self.log_message.emit(
            f"<span style='color:#ff0055'>[!] REAL CVE FINDING: {name} ({severity}, confidence={confidence})</span>"
        )
