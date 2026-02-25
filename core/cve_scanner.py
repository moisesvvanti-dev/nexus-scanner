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
        self.log_message.emit(f"<span style='color:#00f3ff'>[*] Initiating Advanced CVE Scan (Top Critical Vulnerabilities)...</span>")
        
        base_url = target_url.rstrip('/')
        
        for sig in self.cve_signatures:
            try:
                name = sig['name']
                check_type = sig['check_type']
                
                # Retrieve indicator
                indicator = sig.get('indicator', '')
                
                # HEADERS VULN CHECK
                if check_type == 'header':
                    # Blind checks are hard to confirm without OOB interaction (like Interactsh)
                    # We just fire the payload.
                    async with self.session.get(base_url, headers=sig['headers'], timeout=3) as r:
                         pass # Fire and forget for now, unless we have OOB listener
                
                # PATH VULN CHECK
                elif check_type == 'path':
                    target = base_url + sig['path']
                    print(f"[DEBUG] Checking {target} for {sig['name']}")
                    async with self.session.get(target, timeout=5) as r:
                         content = await r.text()
                         valid_status = sig.get('status')
                         if valid_status and r.status not in valid_status:
                              continue # Skip if status code doesn't match expected
                              
                         if indicator and indicator in content:
                              # Strict Validation: Ensure the indicator wasn't just reflected from the URL
                              if indicator.lower() in target.lower() and content.count(indicator) < 2:
                                   # This is likely a soft 404 reflecting the path! Ignore.
                                   self.log_message.emit(f"<span style='color:#aa5500'>[STRICT] Rejected '{name}' on {target} (Reflected 404 Detected)</span>")
                                   continue
                                   
                              # Strict Validation: Length and structure check
                              # Many payloads look for generic things like 'root:' or 'SQL'. We need to make sure the page isn't just a massive HTML blob containing it by chance.
                              if len(content) > 50000 and "html" in content.lower():
                                   # It's a massive webpage, a CVE indicator here is highly suspicious unless it's a specific version tag.
                                   if sig.get("category") != "Fingerprinting":
                                        continue

                              # Special handling for Version Fingerprinting
                              if sig.get("category") == "Fingerprinting":
                                   import re
                                   # Try to extract version (e.g. elementor-version="3.35.5" or ?ver=3.x.x)
                                   version_match = re.search(r'(?:version|ver=)["\']?([0-9.]+)', content)
                                   if version_match:
                                        version = version_match.group(1)
                                        self.log_message.emit(f"<span style='color:#00f3ff'>[*] Detected {name}: {version}</span>")
                                   else:
                                        self.log_message.emit(f"<span style='color:#00f3ff'>[*] Detected {name}</span>")
                              else:
                                   self._report_vuln(target, name, sig['type'], f"Found indicator '{indicator}' at {target} (Status: {r.status})")

                # POST VULN CHECK
                elif check_type == 'POST':
                    target = base_url + sig['path']
                    async with self.session.post(target, data=sig.get('data', {}), timeout=5) as r:
                        content = await r.text()
                        valid_status = sig.get('status')
                        if valid_status and r.status not in valid_status:
                             continue

                        if sig['indicator'] in content:
                             self._report_vuln(target, name, sig['type'], f"Found indicator '{sig['indicator']}'")

            except Exception:
                pass

    def _report_vuln(self, target, name, vuln_type, description):
        vuln = Vulnerability(target=target, vuln_type=vuln_type, severity="CRITICAL", impact=f"{name}: {description}")
        self.finding_found.emit(vuln)
        self.log_message.emit(f"<span style='color:#ff0055'>[!] CRITICAL CVE DETECTED: {name}</span>")
