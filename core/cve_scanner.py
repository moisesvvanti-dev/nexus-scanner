import aiohttp
import asyncio
from PySide6.QtCore import QObject, Signal
from core.models import Vulnerability

class CVEScanner(QObject):
    finding_found = Signal(object)
    log_message = Signal(str)

    def __init__(self, session):
        super().__init__()
        self.session = session
        self.cve_signatures = []
        self._load_signatures()

    def _load_signatures(self):
        """Loads CVE signatures from data/cve.json."""
        try:
            import json
            import os
            
            # Paths to check
            paths = [
                os.path.join("data", "cve.json"),
                os.path.join(os.path.dirname(__file__), "..", "data", "cve.json")
            ]
            
            for p in paths:
                if os.path.exists(p):
                    with open(p, "r", encoding="utf-8") as f:
                        self.cve_signatures = json.load(f)
                    self.log_message.emit(f"<span style='color:#aaa'>[*] Loaded {len(self.cve_signatures)} CVE definitions from {p}</span>")
                    return

            # Fallback if no file found
            self.log_message.emit("<span style='color:#ff5555'>[!] CVE Database not found. Using minimal fallback.</span>")
            self.cve_signatures = [
                 # Minimal fallback
                {
                    "name": "PHP Info Disclosure (Fallback)",
                    "category": "Info",
                    "type": "Info",
                    "check_type": "path",
                    "path": "/phpinfo.php",
                    "indicator": "PHP Version",
                    "status": [200]
                }
            ]
        except Exception as e:
            self.log_message.emit(f"<span style='color:#ff0000'>[!] Error loading CVE database: {str(e)}</span>")

    async def scan(self, target_url):
        self.log_message.emit(f"<span style='color:#00f3ff'>[*] Initiating Governmental Max CVE Scan ({len(self.cve_signatures)} Signatures)...</span>")
        
        base_url = target_url.rstrip('/')
        
        async def _check_sig(sig):
            try:
                name = sig['name']
                check_type = sig['check_type']
                indicator = sig.get('indicator', '')
                
                if check_type == 'header':
                    async with self.session.get(base_url, headers=sig.get('headers', {}), timeout=7) as r:
                         pass
                
                elif check_type == 'path':
                    target = base_url + sig['path']
                    async with self.session.get(target, timeout=7) as r:
                         content = await r.text()
                         valid_status = sig.get('status')
                         if valid_status and r.status not in valid_status:
                              return
                              
                         if indicator and indicator in content:
                              if indicator.lower() in target.lower() and content.count(indicator) < 2:
                                   return
                              if len(content) > 50000 and "html" in content.lower():
                                   if sig.get("category") != "Fingerprinting":
                                        return
                              if sig.get("category") == "Fingerprinting":
                                   import re
                                   version_match = re.search(r'(?:version|ver=)["\']?([0-9.]+)', content)
                                   if version_match:
                                        self.log_message.emit(f"<span style='color:#00f3ff'>[*] Detected {name}: {version_match.group(1)}</span>")
                                   else:
                                        self.log_message.emit(f"<span style='color:#00f3ff'>[*] Detected {name}</span>")
                              else:
                                   self._report_vuln(target, name, sig['type'], f"Found indicator '{indicator}' at {target} (Status: {r.status})")

                elif check_type == 'POST':
                    target = base_url + sig['path']
                    async with self.session.post(target, data=sig.get('data', {}), timeout=7) as r:
                        content = await r.text()
                        valid_status = sig.get('status')
                        if valid_status and r.status not in valid_status:
                             return
                        if sig.get('indicator') and sig['indicator'] in content:
                             self._report_vuln(target, name, sig['type'], f"Found indicator '{sig['indicator']}'")
            except Exception:
                pass

        # Execute in massive concurrent batches (Governmental Scale)
        batch_size = 500
        for i in range(0, len(self.cve_signatures), batch_size):
            batch = self.cve_signatures[i:i+batch_size]
            await asyncio.gather(*[_check_sig(sig) for sig in batch])

    def _report_vuln(self, target, name, vuln_type, description):
        vuln = Vulnerability(target=target, vuln_type=vuln_type, severity="CRITICAL", impact=f"{name}: {description}")
        self.finding_found.emit(vuln)
        self.log_message.emit(f"<span style='color:#ff0055'>[!] CRITICAL CVE DETECTED: {name}</span>")
