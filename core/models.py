from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

# Standard CVSS v3.1 mapping for severity labels
_SEVERITY_CVSS_MAP = {
    "CRITICAL": 9.5,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 2.0,
    "INFO": 0.0,
}

# Standard remediation suggestions per vulnerability type
_REMEDIATION_MAP = {
    "Reflected XSS": "Sanitize and encode all user inputs before rendering in HTML context. Implement Content-Security-Policy headers.",
    "SQLi": "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
    "Time-Based Blind SQLi": "Use parameterized queries / prepared statements. Implement WAF rules to detect blind injection patterns.",
    "LFI": "Validate and whitelist file paths. Disable allow_url_include in PHP. Use chroot jails.",
    "RCE": "Never pass unsanitized user input to system commands. Use allowlists for command arguments.",
    "SSTI": "Use sandboxed template engines. Never render user-controlled template strings.",
    "Sensitive File Exposure": "Remove or restrict access to sensitive files (.env, .git, backups). Configure web server deny rules.",
    "Critical .env Exposure": "URGENT: Rotate all credentials in the exposed .env file immediately. Block public access.",
    "Subdomain Takeover": "Remove dangling DNS CNAME records or reclaim the external service resource.",
    "Open Redirect": "Validate redirect URLs against a whitelist of allowed domains.",
    "Missing Security Headers": "Add X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, and CSP headers.",
    "Data Dump": "Immediately remove exposed database dumps. Rotate all credentials found in the dump.",
    "Potential SSRF": "Validate and whitelist URLs/IPs in server-side requests. Block internal IP ranges.",
    "Prototype Pollution": "Freeze Object.prototype. Validate and sanitize object keys from user input.",
}

@dataclass
class Target:
    name: str
    url: str
    status: str = "Pending"  # Pending, Scanning, Completed, Error

@dataclass
class Vulnerability:
    target: str
    vuln_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    impact: str
    cvss_score: float = 0.0
    remediation: str = ""
    timestamp: datetime = field(default_factory=datetime.now)

    def __post_init__(self):
        # Auto-assign CVSS score from severity if not explicitly set
        if self.cvss_score == 0.0:
            self.cvss_score = _SEVERITY_CVSS_MAP.get(self.severity.upper(), 0.0)
        # Auto-assign remediation from vuln_type if not explicitly set
        if not self.remediation:
            for key, remedy in _REMEDIATION_MAP.items():
                if key.lower() in self.vuln_type.lower():
                    self.remediation = remedy
                    break
            if not self.remediation:
                self.remediation = "Investigate and apply appropriate security controls for this vulnerability type."

    def to_dict(self):
        return {
            "target": self.target,
            "vuln": self.vuln_type,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "impact": self.impact,
            "remediation": self.remediation,
            "timestamp": self.timestamp.isoformat()
        }
