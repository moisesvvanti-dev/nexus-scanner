import asyncio
import os
import time
import re
import json
from urllib.parse import urlparse
from playwright.async_api import async_playwright, Page
from PySide6.QtCore import QObject, Signal
import base64
import binascii

from core.ai_assistant import AIAssistant

class BrowserScanner(QObject):
    log_message = Signal(str)
    finding_found = Signal(object) # Re-use the Vulnerability model signal
    forms_found = Signal(list)     # New: Emit found forms for AuthBypass
    screenshot_taken = Signal(str)
    payload_generated = Signal(str, str)  # url, script

    def __init__(self, target_url, deep_scan=False, headless=True, proxychains=False, ai_key=None, ai_model=None):
        super().__init__()
        self.target_url = target_url
        self.deep_scan = deep_scan
        self.headless = headless
        self.proxychains = proxychains
        self.ai_key = ai_key
        self.ai_model = ai_model
        self.ai_assistant = AIAssistant(ai_key, ai_model) if ai_key else None
        
        self.browser = None
        self.context = None
        self.page = None
        self.playwright = None
        self.network_log = [] # Store requests for AI context masking

    async def initialize(self):
        """Starts Playwright and Browser."""
        try:
            self.playwright = await async_playwright().start()
            launch_args = {
                "headless": self.headless,
                "args": [
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-accelerated-2d-canvas',
                    '--no-first-run',
                    '--no-zygote',
                    '--single-process',
                    '--disable-gpu',
                    '--disable-web-security',
                    '--disable-site-isolation-trials',
                    '--disable-blink-features=AutomationControlled'
                ],
                "ignore_default_args": ["--enable-automation"]
            }
            if self.proxychains:
                launch_args["proxy"] = {"server": "socks5://127.0.0.1:9050"}

            self.browser = await self.playwright.chromium.launch(**launch_args)
            
            self.context = await self.browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
                ignore_https_errors=True
            )
            
            self.page = await self.context.new_page()
            
            # Attach Listeners
            self.page.on("console", self._handle_console)
            self.page.on("pageerror", self._handle_page_error)
            self.page.on("request", self._handle_request)
            self.page.on("response", self._handle_response)
            
            # Apply Stealth Scripts
            await self._apply_stealth()
            
        except Exception as e:
            self.log_message.emit(f"<span style='color:#ff0000'>[!] Browser Init Failed: {str(e)}</span>")

    async def check_connection(self):
        """Verifies if the browser and page are still alive. Restarts if dead."""
        try:
            if not self.browser or not self.browser.is_connected() or not self.page or self.page.is_closed():
                 self.log_message.emit("<span style='color:#ffcc00'>[*] Browser connection lost. Re-initializing...</span>")
                 await self.initialize()
                 return self.page is not None
            return True
        except:
            await self.initialize()
            return self.page is not None

    async def scan_page(self, url):
        """Scans a specific URL using the active browser session with Robust Auto-Recovery."""
        max_retries = 3
        for attempt in range(max_retries):
            # 1. Ensure Connection
            if not await self.check_connection():
                 self.log_message.emit(f"<span style='color:#ff0000'>[!] Critical: Could not restore browser session for {url}. Retrying ({attempt+1}/{max_retries})...</span>")
                 await asyncio.sleep(2)
                 continue

            self.log_message.emit(f"<span style='color:#00f3ff'>[*] Browser Browsing: {url}...</span>")
            
            try:
                # Add headers for credibility
                if not self.page or self.page.is_closed(): raise Exception("Page Closed")
                
                await self.page.set_extra_http_headers({
                    "Accept-Language": "en-US,en;q=0.9",
                    "Upgrade-Insecure-Requests": "1",
                    "Sec-Ch-Ua": '"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"',
                    "Sec-Ch-Ua-Mobile": "?0",
                    "Sec-Ch-Ua-Platform": '"Windows"',
                })
                
                # Apply Spoofer/Stealth before navigation
                await self._rotate_identity()
                
                try:
                    response = await self.page.goto(url, wait_until="domcontentloaded", timeout=45000)
                except Exception as e:
                    if "Connection closed" in str(e) or "Target closed" in str(e):
                        raise Exception("Browser Crash Detected")
                    raise e
                
                # WAF/Block Detection & Retry Logic
                if response and response.status in [403, 406, 503]:
                     self.log_message.emit(f"<span style='color:#ffcc00'>[!] WAF Blocked ({response.status}) - Retrying with new identity...</span>")
                     await asyncio.sleep(5)
                     await self._rotate_identity()
                     response = await self.page.goto(url, wait_until="domcontentloaded", timeout=45000)
                     
                if response and response.status in [401, 403]:
                     self.log_message.emit(f"<span style='color:#ff0055'>[!] Access Denied ({response.status}) - WAF/Bot Protection active.</span>")
                
                # Wait a bit for potential JS redirects or challenges
                await self.page.wait_for_timeout(3000)

                # Run Checks
                # We pass existing page context
                await self._check_local_storage()
                await self._check_session_storage()
                await self._check_cookies()
                # await self._check_dom_xss(url) # Temporarily disabled for stability

                # EXTRACT FORMS (for Auth Bypass Engine)
                forms = await self.page.evaluate("""() => {
                    return Array.from(document.forms).map(f => ({
                        action: f.action,
                        method: f.method || 'GET',
                        inputs: Array.from(f.querySelectorAll('input, textarea, select')).map(i => i.name || i.id)
                    }));
                }""")
                if forms:
                    self.log_message.emit(f"<span style='color:#00f3ff'>[INFO] Discovered {len(forms)} interactable forms.</span>")
                    self.forms_found.emit(forms)

                # Screenshot
                try:
                    title = await self.page.title()
                    safe_title = "".join([c if c.isalnum() else "_" for c in title])[:50]
                    screenshot_path = os.path.join("scans", "screenshots", f"{safe_title}_{int(time.time())}.png")
                    os.makedirs(os.path.dirname(screenshot_path), exist_ok=True)
                    await self.page.screenshot(path=screenshot_path, full_page=True)
                    self.screenshot_taken.emit(screenshot_path)
                except:
                    pass

                # 7. AI Analysis (Groq)
                if self.ai_assistant:
                    # In deep scan / extreme bypass, generate multiple payloads
                    if self.deep_scan:
                        await self._run_extreme_ai_bypass()
                    else:
                        await self._run_ai_analysis()
                
                return # Success!

            except Exception as e:
                err_msg = str(e)
                if "Browser Crash" in err_msg or "Target closed" in err_msg or "Connection closed" in err_msg:
                    self.log_message.emit(f"<span style='color:#ff5555'>[!] Browser Crash Detected. Rebooting Driver...</span>")
                    await self.stop()
                    await asyncio.sleep(2)
                    await self.initialize()
                else:
                    self.log_message.emit(f"<span style='color:#ff0000'>[!] Browser Nav Error ({url}): {str(e)}</span>")
                    break # Non-recoverable error on this URL

    async def _run_extreme_ai_bypass(self):
        """Generates multiple advanced bypass techniques via Groq."""
        self.log_message.emit("<span style='color:#aa00ff; font-weight:bold'>[AI] INITIATING EXTREME BYPASS LOOP (CVE-2026-25049) TO FIND CRITICAL LEVEL 10 VULNS...</span>")
        
        try:
            content = await self.page.content()
            
            # Request multi-vector attacks
            attack_types = [
                "1. Auth Bypass (Cookie/JWT manipulation)",
                "2. Logic Flaw (Price/Balance manipulation)",
                "3. DOM-based XSS (Cookie stealing context)",
                "4. Prototype Pollution / Prototype overrides",
                "5. Admin Escalation via LocalStorage/State override"
            ]
            
            for attack in attack_types:
                self.log_message.emit(f"<span style='color:#aa00ff'>[AI] Testing Vector: {attack}...</span>")
                prompt_extension = f"Generate an exploit targeting specifically: {attack}. Create a highly obfuscated JavaScript IIFE payload to execute this."
                
                script = await self.ai_assistant.generate_custom_script(
                    content, "custom", extra_instructions=prompt_extension
                )
                
                if script and not "ERROR" in script and not script.startswith("// PoC generation failed"):
                    self.payload_generated.emit(self.target_url, script)
                    
                    self.log_message.emit("<span style='color:#ff0055'>[AI] Injecting EXTREME Payload into Browser...</span>")
                    try:
                        result = await self.page.evaluate("""(scriptContent) => {
                            try {
                                new Function(scriptContent)();
                                return "Exploit Executed Successfully";
                            } catch (e) {
                                return "Payload Error: " + e.message;
                            }
                        }""", script)
                        
                        self.log_message.emit(f"<span style='color:#00ff9d'>[AI] EXECUTION RESULT: {result[:100]}</span>")
                        
                        # Briefly pause to allow effects
                        await asyncio.sleep(2)
                    except Exception as e:
                         self.log_message.emit(f"<span style='color:#ff5555'>[AI] Injection Failed: {str(e)}</span>")
                         
        except Exception as e:
            self.log_message.emit(f"<span style='color:#ff5555'>[AI] Extreme Bypass Error: {str(e)}</span>")

    async def _run_ai_analysis(self):
        """Captures DOM, sends to AI, and attempts to run generated bypass scripts."""
        self.log_message.emit("<span style='color:#aa00ff'>[AI] STARTING DEEP ANALYSIS (Groq)...</span>")
        
        try:
            # Capture DOM
            content = await self.page.content()
            
            # Send to AI
            self.log_message.emit(f"<span style='color:#aa00ff'>[AI] Sending page context to {self.ai_model}...</span>")
            # Pass network log for better masking
            script = await self.ai_assistant.analyze_page(self.target_url, content, "", network_log=self.network_log)
            
            # Check for AI Refusal
            if not script or any(phrase in script.lower() for phrase in ["i'm sorry", "i cannot", "unable to", "illegal", "ethical"]):
                self.log_message.emit(f"<span style='color:#ff5555'>[AI] Generation Refused/Failed: {script[:100] if script else 'Empty response'}</span>")
                return

            if script:
                self.log_message.emit("<span style='color:#00ff9d'>[AI] GENERATED ATTACK VECTOR:</span>")
                self.log_message.emit(f"<span style='color:#555'>{script[:200]}...</span>")
                print(f"[DEBUG] AI SCRIPT: {script}")
                
                # Emit to Payloads tab
                self.payload_generated.emit(self.target_url, script)
                
                # Execute Script
                self.log_message.emit("<span style='color:#aa00ff'>[AI] Injecting Payload into Browser...</span>")
                try:
                    # Pass script as an argument to avoid Python f-string syntax errors with JS braces
                    result = await self.page.evaluate("""(scriptContent) => {
                        try {
                            // Use new Function to execute the string as code
                            new Function(scriptContent)();
                            return "Payload Executed Successfully via new Function()";
                        } catch (e) {
                            return "Payload Error: " + e.message;
                        }
                    }""", script)
                    
                    self.log_message.emit(f"<span style='color:#00ff9d'>[AI] EXECUTION RESULT: {result}</span>")
                except Exception as e:
                     self.log_message.emit(f"<span style='color:#ff5555'>[AI] Injection Failed: {str(e)}</span>")
            else:
                self.log_message.emit("<span style='color:#aa00ff'>[AI] No viable payload generated.</span>")

        except Exception as e:
            self.log_message.emit(f"<span style='color:#ff5555'>[AI] Analysis Error: {str(e)}</span>")

    async def start_scan(self):
        """Legacy wrapper for single target scan."""
        await self.initialize()
        await self.scan_page(self.target_url)
        if self.deep_scan:
             await self._spider_links()
        await self.stop()

    async def stop(self):
        if not self.headless and self.page:
             self.log_message.emit("<span style='color:#00ff00'>[+] SCAN COMPLETE. Browser kept open for manual investigation. Close the browser window to finish.</span>")
             try:
                 # Wait for the user to close the browser window
                 await self.page.wait_for_event("close", timeout=0) 
             except:
                 pass

        if self.context: await self.context.close()
        if self.browser: await self.browser.close()
        if self.playwright: await self.playwright.stop()

    async def _handle_console(self, msg):
        """Monitors console for sensitive info or errors."""
        text = msg.text
        
        # Filter Noise (CORS, 404s on assets, tracking scripts)
        noise = [
            "failed to load resource", "cors policy", "err_failed", 
            "access to fetch at", "access to script at", "access to font at",
            "recaptcha", "privacy_sandbox", "facebook", "analytics", "gtm",
            "typekit", "font-size", "deprecated", "autocomplete", "password field", 
            "form submission", "cookie", "samesite", "fbq", "content security policy",
            "frame-ancestors", "violates the following"
        ]
        
        if any(n in text.lower() for n in noise):
             return # Skip reporting noise to user
        
        if msg.type == "error":
             self.log_message.emit(f"<span style='color:#ff5555'>[Console Error] {text[:200]}</span>")
        
        # Enhanced Sensitive Data & DB Error Detection
        text_lower = text.lower()
        
        # Secrets
        if "token" in text_lower or "key" in text_lower or "password" in text_lower:
             self.log_message.emit(f"<span style='color:#ffcc00'>[!] Suspicious Console Log: {text[:200]}</span>")
             
        # DB Errors (SQLi / NoSQLi info leaks)
        # DB Errors (SQLi / NoSQLi info leaks)
        # Removed "syntax error" as it catches JS errors too often (e.g. jQuery)
        db_errors = [
            "sql syntax", "ora-", "mysql", "odbc", 
            "unterminated string", "supabase", "mariadb", "postgresql",
            "bson", "mongo", "sqlite3", "pg_query", "sqlstate"
        ]
        
        # Explicit check to avoid JS errors disguised as DB errors
        is_js_error = any(js_term in text_lower for js_term in [
             "jquery", "bootstrap", "react", "vue", "min.js", 
             "unrecognized expression", "unexpected token"
        ])

        if any(err in text_lower for err in db_errors) and not is_js_error:
             self.log_message.emit(f"<span style='color:#ff0055'>[!] DB ERROR LEAK DETECTED: {text[:200]}</span>")
             
        # Catch generic "Syntax Error" ONLY if it looks like SQL and not JS
        if "syntax error" in text_lower and "sql" in text_lower and not is_js_error:
             self.log_message.emit(f"<span style='color:#ff0055'>[!] DB ERROR LEAK DETECTED: {text[:200]}</span>")
             
        # Anti-Bot Detection Logs
        if "challenge" in text_lower or "captcha" in text_lower or "401" in text_lower or "403" in text_lower:
             # Only show if not part of the noisy 3rd party blocks we just filtered
             # But 403 on the MAIN domain is important.
             if "recaptcha" not in text_lower and "facebook" not in text_lower:
                  self.log_message.emit(f"<span style='color:#aaaaaa'>[info] Anti-Bot/Auth Log: {text[:100]}</span>")

    async def _handle_page_error(self, err):
        msg = str(err)
        if "fbq is not defined" in msg: return # Silence noise
        # Label as Remote Site Error to avoid confusion with tool crashes
        self.log_message.emit(f"<span style='color:#ff5555'>[Remote Site Error] {msg[:200]}</span>")

    async def _handle_request(self, request):
        """Inspects outgoing requests for PII."""
        try:
            # Capture for AI Context
            self.network_log.append({
                'url': request.url,
                'method': request.method,
                'post_data': request.post_data
            })
            
            post_data = request.post_data
            if post_data and ("password" in post_data or "admin" in post_data):
                 self.log_message.emit(f"<span style='color:#aaa'>[Net] POST Data monitored to {request.url}</span>")
        except (UnicodeDecodeError, Exception):
            # Binary data or other errors (e.g. zlib compressed) - ignore
            pass

    async def _handle_response(self, response):
        """Inspects responses for headers."""
        try:
            headers = response.headers
            # Check Security Headers
            missing = []
            if "content-security-policy" not in headers: missing.append("CSP")
            if "x-frame-options" not in headers: missing.append("X-Frame-Options")
            
            if missing and response.url == self.target_url: # Only main page
                 self.log_message.emit(f"<span style='color:#aaa'>[-] Missing Security Headers: {', '.join(missing)}</span>")
        except:
            pass

    async def _check_local_storage(self):
        try:
            data = await self.page.evaluate("() => JSON.stringify(localStorage)")
            if len(data) > 2: # Not exist or empty "{}"
                self.log_message.emit(f"<span style='color:#00f3ff'>[INFO] LocalStorage Data Found ({len(data)} bytes)</span>")
                if "token" in data.lower() or "auth" in data.lower():
                     self.log_message.emit(f"<span style='color:#ff0055'>[!] CRITICAL: Potential Auth Token in LocalStorage!</span>")
        except:
            pass

    async def _check_session_storage(self):
        try:
            data = await self.page.evaluate("() => JSON.stringify(sessionStorage)")
            if len(data) > 2:
                self.log_message.emit(f"<span style='color:#00f3ff'>[INFO] SessionStorage Data Found ({len(data)} bytes)</span>")
        except:
            pass

    async def _check_cookies(self):
        try:
            cookies = await self.context.cookies()
            for cookie in cookies:
                name = cookie['name']
                value = cookie['value']
                domain = cookie['domain']
                
                # 1. Missing Security Flags
                if not cookie.get('secure', False):
                     self.log_message.emit(f"<span style='color:#ffcc00'>[!] Insecure Cookie (Missing Secure Flag): {name}</span>")
                if not cookie.get('httpOnly', False):
                     self.log_message.emit(f"<span style='color:#ffcc00'>[!] Insecure Cookie (Missing HttpOnly Flag): {name}</span>")
                
                # 2. SameSite Attribute
                same_site = cookie.get('sameSite', 'None')
                if same_site == 'None' and not cookie.get('secure', False):
                     self.log_message.emit(f"<span style='color:#ff5555'>[!] CRITICAL: Cookie {name} has SameSite=None but is NOT Secure (CSRF Risk)</span>")
                elif same_site == 'None' or same_site == 'Lax':
                     self.log_message.emit(f"<span style='color:#aaa'>[?] Clean Cookie: {name} uses SameSite={same_site} (Verify CSRF tokens separately)</span>")

                # 3. Loosely Scoped Domain (Parent Domain)
                if domain.startswith('.') and domain.count('.') < 2: 
                     # e.g., .example.com (applies to all subdomains)
                     self.log_message.emit(f"<span style='color:#ffcc00'>[!] Loosely Scoped Cookie: {name} set for parent domain {domain} (Subdomain takeover risk)</span>")

                # 4. Sensitive Data Analysis (JWT, Base64, Serialized)
                await self._analyze_cookie_value(name, value)
                
        except Exception:
            pass

    async def _analyze_cookie_value(self, name, value):
        """Deep inspection of cookie values for secrets/structure."""
        # A. Check for JWT
        if value.count('.') == 2 and (value.startswith('eyJ') or value.startswith('eyI')):
            self.log_message.emit(f"<span style='color:#00f3ff'>[INFO] JWT Detected in cookie: {name}</span>")
            parts = value.split('.')
            try:
                # Decode Header
                header_json = self._safe_b64_decode(parts[0])
                payload_json = self._safe_b64_decode(parts[1])
                
                if header_json:
                    if '"alg":"none"' in header_json.lower():
                        self.log_message.emit(f"<span style='color:#ff0055'>[!] CRITICAL: JWT '{name}' uses 'none' algorithm! (Auth Bypass)</span>")
                    self.log_message.emit(f"<span style='color:#aaa'>    - JWT Header: {header_json}</span>")

                if payload_json:
                     # Check for sensitive claims
                     lower_payload = payload_json.lower()
                     if "admin" in lower_payload or "role" in lower_payload or "privilege" in lower_payload:
                          self.log_message.emit(f"<span style='color:#ffcc00'>[!] Interesting JWT Payload in '{name}': {payload_json} (Evaluate for escalation)</span>")
                     else:
                          self.log_message.emit(f"<span style='color:#aaa'>    - JWT Payload: {payload_json}</span>")
            except:
                pass

        # B. Check for simple Base64
        elif len(value) > 20 and "=" in value and not " " in value:
             decoded = self._safe_b64_decode(value)
             if decoded and all(32 <= ord(c) < 127 for c in decoded): # Readable ASCII
                 # Check for sensitive keywords in decoded string
                 if any(k in decoded.lower() for k in ["admin", "root", "user", "role", "auth", "session"]):
                      self.log_message.emit(f"<span style='color:#ffcc00'>[!] Decoded Base64 Cookie '{name}': {decoded} (Potential Info Leak)</span>")

        # C. Check for PHP Serialization (O:4:"User")
        if re.match(r'O:\d+:"', value) or re.match(r'a:\d+:{', value):
             self.log_message.emit(f"<span style='color:#ff0055'>[!] PHP Serialized Object found in '{name}'. (Potential Insecure Deserialization!)</span>")

    def _safe_b64_decode(self, data):
        """Safely decodes base64 strings with padding fix."""
        try:
            missing_padding = len(data) % 4
            if missing_padding:
                data += '=' * (4 - missing_padding)
            return base64.urlsafe_b64decode(data).decode('utf-8')
        except:
            return None

    async def _check_dom_xss(self, base_url=None):
        """Checks for DOM-based XSS sinks."""
        # Simple heuristic: scan for dangerous sinks in page source
        # A real DOM scanner would taint tracing, but that's complex.
        # We will look for usage of eval(), document.write(), innerHTML with URL params.
        
        # We can try to inject a canary in the URL and see if it appears in the DOM structure
        canary = "PENTESTGPT_XSS_CANARY"
        current_url = base_url if base_url else self.page.url
        
        if "?" in current_url:
            fuzz_url = current_url + "&test=" + canary
        else:
            fuzz_url = current_url + "?test=" + canary
            
        # Navigate to fuzzed URL
        try:
            await self.page.goto(fuzz_url, wait_until="domcontentloaded", timeout=10000)
            content = await self.page.content()
            if canary in content:
                 # Check if it's in a script tag or dangerous attribute
                 # This is a basic check.
                 if f"<script>{canary}" in content or f"'{canary}'" in content:
                      self.log_message.emit(f"<span style='color:#ff0055'>[!] POTENTIAL REFLECTED XSS at {fuzz_url}</span>")
        except:
            pass

    async def _spider_links(self):
        """Simple JS-aware spider."""
        # Wait for potential JS rendering
        try:
             await self.page.wait_for_load_state("networkidle", timeout=5000)
        except:
             pass
             
        links = await self.page.evaluate('''() => {
            return Array.from(document.querySelectorAll('a')).map(a => a.href);
        }''')
        self.log_message.emit(f"<span style='color:#aaa'>[Spider] Found {len(links)} links on page (JS-Rendered).</span>")

    async def _apply_stealth(self):
        """Injects JS to mask webdriver and emulate a real user."""
        try:
            await self.page.add_init_script("""
                // Pass the Webdriver Test.
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined,
                });

                // Pass the Chrome Test.
                window.chrome = {
                    runtime: {},
                };

                // Pass the Permissions Test.
                try {
                    const originalQuery = window.navigator.permissions.query.bind(window.navigator.permissions);
                    window.navigator.permissions.query = (parameters) => (
                        parameters.name === 'notifications' ?
                        Promise.resolve({ state: 'granted' }) :
                        originalQuery(parameters)
                    );
                } catch(e) {}

                // Pass the Plugins Length Test.
                Object.defineProperty(navigator, 'plugins', {
                    get: () => [1, 2, 3, 4, 5],
                });

                // Pass the Languages Test.
                Object.defineProperty(navigator, 'languages', {
                    get: () => ['en-US', 'en'],
                });
            """)
        except:
            pass

    async def _rotate_identity(self):
        """
        [EXTREME STEALTH] Rotates browser identity to evade advanced WAFs (Cloudflare/Akamai).
        Techniques:
        - Random User-Agent (Desktop/Linux/Mac)
        - Clears Cookies/Storage/Permissions
        - Mocks Hardware Concurrency & Device Memory
        - Mocks WebGL Vendor (GPU Spoofing)
        - Randomizes Viewport slightly
        """
        import random
        
        # 1. Deep Clean State
        try:
             if self.context:
                await self.context.clear_cookies()
                await self.context.clear_permissions()
                # Clear storage via CDP for depth
                try: 
                    if not self.page or self.page.is_closed(): return
                    client = await self.context.new_cdp_session(self.page)
                    await client.send('Storage.clearDataForOrigin', {'origin': '*', 'storageTypes': 'all'})
                    await client.detach() # Clean up
                except: pass
        except: pass
        
        # 2. Select High-Quality User-Agent
        uas = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0'
        ]
        new_ua = random.choice(uas)
        if self.context:
            await self.context.set_extra_http_headers({
                'User-Agent': new_ua,
                'Accept-Language': 'en-US,en;q=0.9',
                'Sec-Ch-Ua': '"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"',
                'Sec-Ch-Ua-Mobile': '?0',
                'Sec-Ch-Ua-Platform': '"Windows"'
            })

        # 3. Inject Advanced Fingerprinting Protection
        if self.page:
            try:
                await self.page.add_init_script("""
                    (() => {
                        const safeDefine = (obj, prop, value) => {
                            try {
                                Object.defineProperty(obj, prop, {
                                    get: () => value,
                                    configurable: true 
                                });
                            } catch(e) {}
                        };

                        // 1. Mock Hardware/Memory
                        safeDefine(navigator, 'hardwareConcurrency', 8);
                        safeDefine(navigator, 'deviceMemory', 8);
                        
                        // 2. Mock WebGL Vendor (NVIDIA)
                        try {
                            const getParameter = WebGLRenderingContext.prototype.getParameter;
                            WebGLRenderingContext.prototype.getParameter = function(parameter) {
                                // UNMASKED_VENDOR_WEBGL
                                if (parameter === 37445) return 'Google Inc. (NVIDIA)';
                                // UNMASKED_RENDERER_WEBGL
                                if (parameter === 37446) return 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3070 Direct3D11 vs_5_0 ps_5_0, D3D11)';
                                return getParameter.apply(this, arguments);
                            };
                        } catch(e) {}
                        
                        // 3. Canvas Noise (Anti-Fingerprinting) - Gentler
                        try {
                            const toBlob = HTMLCanvasElement.prototype.toBlob;
                            const getImageData = CanvasRenderingContext2D.prototype.getImageData;
                            
                            // Only apply noise occasionally to avoid breaking visuals
                            const noise = () => Math.floor(Math.random() * 4) - 2; 
                            
                            CanvasRenderingContext2D.prototype.getImageData = function(x, y, w, h) {
                                const image = getImageData.apply(this, arguments);
                                try {
                                    // Apply to only 10% of pixels to save perf
                                    for (let i = 0; i < image.data.length; i += 40) { 
                                        image.data[i] = image.data[i] + noise();
                                    }
                                } catch(e) {}
                                return image;
                            };
                        } catch(e) {}
                        
                        // 4. Behavioral: Random Mouse Movements (Humanizer)
                        try {
                            window.addEventListener('load', function() {
                                setInterval(function() {
                                    var x = Math.floor(Math.random() * window.innerWidth);
                                    var y = Math.floor(Math.random() * window.innerHeight);
                                    var event = new MouseEvent('mousemove', {
                                        view: window,
                                        bubbles: true,
                                        cancelable: true,
                                        clientX: x,
                                        clientY: y
                                    });
                                    document.dispatchEvent(event);
                                }, 3000);
                            });
                        } catch(e) {}
                    })();
                """)
            except: pass
        
        self.log_message.emit(f"<span style='color:#00f3ff'>[Stealth] Identity Rotated (UA: {new_ua[:25]}... | GPU: RTX 3070 | Human Behavior: Active)</span>")
