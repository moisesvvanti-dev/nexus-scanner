import aiohttp
import asyncio
from PySide6.QtCore import QObject, Signal

class DirectoryBruter(QObject):
    finding_found = Signal(object)
    log_message = Signal(str)

    def __init__(self, session, strict_validation=True):
        super().__init__()
        self.session = session
        self.strict_validation = strict_validation
        self.baseline_404_length = -1
        self.baseline_variance = 0
        self.baseline_404_text = ""
        self.wordlist = [
            # High Value Configs
            ".env", ".env.backup", ".env.save", ".env.old",
            "config.php", "config.php.bak", "config.xml", "config.json",
            "web.config", "appsettings.json",
            
            # Version Control
            ".git/HEAD", ".svn/entries", ".hg/dirstate",
            ".vscode/sftp.json", ".idea/workspace.xml",
            
            # Backups
            "backup.zip", "backup.sql", "backup.tar.gz", "backup.rar",
            "www.zip", "html.zip", "site.zip",
            "dump.sql", "database.sql", "db.sql", "users.sql",
            
            # Admin Panels
            "admin/", "administrator/", "panel/", "dashboard/", "wp-admin/",
            "phpmyadmin/", "pma/", "dbadmin/",
            
            # Logs
            "error_log", "debug.log", "access.log", "laravel.log",
            
            # Cloud/Docker
            "Dockerfile", "docker-compose.yml", "kube-config",
            "sftp-config.json"
        ]

    async def run(self, base_url):
        self.log_message.emit(f"<span style='color:#00f3ff'>[*] Initiating Directory/File Brute-Force (Hidden Path Discovery)...</span>")
        
        # Ensure base URL format
        if not base_url.endswith('/'):
            base_url += '/'
            
        # Optional: Strict Validation Baseline Check
        if self.strict_validation:
            self.log_message.emit("<span style='color:#ff0055'>[STRICT MODE] Gathering Soft-404 Baseline Profile...</span>")
            try:
                import random
                import string
                filler1 = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
                filler2 = ''.join(random.choices(string.ascii_letters + string.digits, k=25))
                fake_url1 = f"{base_url}this-path-does-not-exist-{filler1}"
                fake_url2 = f"{base_url}this-path-does-not-exist-{filler2}"
                
                async with self.session.get(fake_url1, timeout=5, allow_redirects=True) as r1:
                    content1 = await r1.read()
                    self.baseline_404_length = len(content1)
                    self.baseline_404_text = content1[:200].decode('utf-8', errors='ignore').strip()
                    
                async with self.session.get(fake_url2, timeout=5, allow_redirects=True) as r2:
                    content2 = await r2.read()
                    self.baseline_variance = abs(len(content2) - len(content1))
                    
                self.log_message.emit(f"<span style='color:#888'>[STRICT] Baseline 404 size established: {self.baseline_404_length} bytes (Variance: {self.baseline_variance}).</span>")
            except Exception as e:
                self.baseline_variance = 0
                self.log_message.emit(f"<span style='color:#ffaa00'>[STRICT] Failed to profile server: {str(e)}</span>")
            
        tasks = []
        for path in self.wordlist:
            tasks.append(self._check_path(base_url, path))
            
        # Run in chunks to control concurrency
        chunk_size = 20
        for i in range(0, len(tasks), chunk_size):
            await asyncio.gather(*tasks[i:i+chunk_size])

    async def _check_path(self, base_url, path):
        target = base_url + path
        try:
            # HEAD request often faster, but GET more reliable for some servers blocking HEAD
            async with self.session.get(target, timeout=5, allow_redirects=False) as r:
                # 200 OK is usually a hit
                # 301/302 might be a hit (redirect to login)
                # 403 Forbidden means it exists but is protected (still a finding!)
                
                if r.status == 200:
                    text = await r.read()
                    text_decoded = text[:200].decode('utf-8', errors='ignore').strip()
                    
                    # 1. Native Keyword Check
                    if len(text) > 0 and b"404" not in text and b"Not Found" not in text:
                        
                        # 2. Strict Validation Check (Anti False-Positive)
                        if self.strict_validation and self.baseline_404_length > 0:
                            # Account for dynamic variance plus path length differences
                            size_diff = abs(len(text) - self.baseline_404_length)
                            leniency = max(150, self.baseline_variance * 2 + len(path))
                            if size_diff <= leniency or text_decoded == self.baseline_404_text:
                                # This is a soft 404 false positive. Ignore it.
                                return

                        self._report_finding(target, "Hidden File Discovered (200 OK)")
                        
                elif r.status == 403:
                    if path.endswith("/"):
                        self._report_finding(target, "Restricted Directory Found (403 Forbidden)")
                    else:
                        self._report_finding(target, "Protected File Found (403 Forbidden)")
                    
                    # Attempt Bypass
                    await self._attempt_bypass(target)
                        
                elif r.status in [301, 302]:
                    # Check where it goes
                    location = r.headers.get("Location", "")
                    if "login" in location or "admin" in location:
                        self._report_finding(target, f"Redirects to Login/Admin ({r.status})")
                        # Attempt to bypass the redirect
                        await self._attempt_bypass(target)

        except Exception:
            pass

    async def _attempt_bypass(self, url):
        """Attempts to bypass 403/301 using headers, path manipulation, and HTTP verbs."""
        
        # 1. Header-based Bypass (Expanded)
        # Some WAFs trust these headers to bypass checks
        bypass_headers = [
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwared-Host": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Remote-Addr": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Host": "127.0.0.1"},
            {"Cluster-Client-IP": "127.0.0.1"},
            {"X-ProxyUser-Ip": "127.0.0.1"},
            {"Client-IP": "127.0.0.1"},
            {"True-Client-IP": "127.0.0.1"},
            # URL Overrides
            {"X-Original-URL": url},
            {"X-Rewrite-URL": url},
            {"Referer": url}
        ]
        
        for headers in bypass_headers:
             try:
                 async with self.session.get(url, headers=headers, timeout=5, allow_redirects=False) as r:
                     if r.status == 200:
                         header_name = list(headers.keys())[0]
                         self._report_finding(url, f"BYPASS SUCCESS (Header: {header_name})", severity="CRITICAL")
                         self.log_message.emit(f"<span style='color:#00ff00'>[!!!] BYPASS SUCCESS! {url} -> 200 OK (via {header_name})</span>")
                         return
             except: pass

        # 2. Path-based Bypass & Manipulation
        # 2. Path-based Bypass & Manipulation
        # Separate the base and the path for smart manipulation
        parsed_url = url.rstrip('/')
        parts = parsed_url.rsplit('/', 1)
        if len(parts) == 2:
            base, endpoint = parts
            variations = [
                f"{parsed_url}/.",
                f"{parsed_url}//",
                f"{parsed_url}/./",
                f"{parsed_url}/%2e",
                f"{parsed_url}/%20",
                f"{parsed_url}%09",
                f"{parsed_url}?",
                f"{parsed_url}??",
                f"{parsed_url}#",
                f"{base}/./{endpoint}",
                f"{base}/..././{endpoint}",
                f"{base}/%2e/{endpoint}",
                f"{base}/{endpoint}..;/",
                f"{base}/;/{endpoint}"
            ]
        else:
            variations = [
                f"{parsed_url}/.",
                f"{parsed_url}//",
                f"{parsed_url}/./",
                f"{parsed_url}/%2e",
                f"{parsed_url}/%20",
                f"{parsed_url}?",
                f"{parsed_url}#"
            ]
        
        for var in variations:
            try:
                async with self.session.get(var, timeout=5, allow_redirects=False) as r:
                    if r.status == 200:
                        self._report_finding(url, f"BYPASS SUCCESS (Path: {var})", severity="CRITICAL")
                        self.log_message.emit(f"<span style='color:#00ff00'>[!!!] BYPASS SUCCESS! {url} -> 200 OK (via Path: {var})</span>")
                        return
            except: pass
            
        # 3. HTTP Verb Tampering (GET -> POST/HEAD/PUT/TRACE)
        # Sometimes ACLs only block GET
        for method in ['POST', 'TRACE', 'HEAD', 'PUT']:
             try:
                 async with self.session.request(method, url, timeout=5, allow_redirects=False) as r:
                     if r.status == 200 and len(await r.read()) > 0:
                         self._report_finding(url, f"BYPASS SUCCESS (Method: {method})", severity="CRITICAL")
                         self.log_message.emit(f"<span style='color:#00ff00'>[!!!] BYPASS SUCCESS! {url} -> 200 OK (via {method})</span>")
                         return
             except: pass

    def _report_finding(self, url, description, severity="MEDIUM"):
        from core.models import Vulnerability
        
        vuln = Vulnerability(
            target=url,
            vuln_type="Hidden Asset" if severity == "MEDIUM" else "Auth Bypass",
            severity=severity,
            impact=description
        )
        self.finding_found.emit(vuln)
        self.log_message.emit(f"<span style='color:#ffcc00'>[+] BRUTE-FORCE HIT: {url} ({description})</span>")
