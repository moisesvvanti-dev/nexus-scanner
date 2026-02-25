from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

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
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self):
        return {
            "target": self.target,
            "vuln": self.vuln_type,
            "severity": self.severity,
            "impact": self.impact,
            "timestamp": self.timestamp.isoformat()
        }
