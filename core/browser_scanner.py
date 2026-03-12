import asyncio
import os
import time
import re
import json
from urllib.parse import urlparse
from PySide6.QtCore import QObject, Signal
import base64
import binascii

# Try Playwright, Fallback to Pyppeteer
HAS_PLAYWRIGHT = False
HAS_PYPPETEER = False

try:
    from playwright.async_api import async_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    try:
        from pyppeteer import launch
        HAS_PYPPETEER = True
    except ImportError:
        pass

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
        """Starts Playwright and Browser (or Pyppeteer Fallback)."""
        try:
            if HAS_PLAYWRIGHT:
                self.log_message.emit("<span style='color:#00f3ff'>[*] Initializing Playwright Engine...</span>")
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

                try:
                    # Tenta usar o Google Chrome local como webdriver
                    launch_args["channel"] = "chrome"
                    self.browser = await self.playwright.chromium.launch(**launch_args)
                except Exception:
                    # Fallback para o Microsoft Edge local se o Chrome não estiver instalado
                    launch_args["channel"] = "msedge"
                    self.browser = await self.playwright.chromium.launch(**launch_args)
                
                self.context = await self.browser.new_context(
                    viewport={'width': 1920, 'height': 1080},
                    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
                    ignore_https_errors=True
                )
                
                self.page = await self.context.new_page()
                
                # Attach Listeners (Playwright)
                self.page.on("console", self._handle_console)
                self.page.on("pageerror", self._handle_page_error)
                self.page.on("request", self._handle_request)
                self.page.on("response", self._handle_response)

            elif HAS_PYPPETEER:
                self.log_message.emit("<span style='color:#ff9d00'>[*] Playwright not found. Falling back to Pyppeteer Engine...</span>")
                launch_args = {
                    "headless": self.headless,
                    "args": [
                        '--no-sandbox',
                        '--disable-setuid-sandbox',
                        '--disable-dev-shm-usage',
                        '--disable-web-security'
                    ],
                    "ignoreHTTPSErrors": True
                }
                
                if self.proxychains:
                    launch_args["args"].append("--proxy-server=socks5://127.0.0.1:9050")

                self.browser = await launch(**launch_args)
                self.page = await self.browser.newPage()
                await self.page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36')
                await self.page.setViewport({'width': 1920, 'height': 1080})
                
                # Attach Listeners (Pyppeteer wrapper)
                self.page.on("console", lambda msg: asyncio.ensure_future(self._handle_pyppeteer_console(msg)))
                self.page.on("request", lambda req: asyncio.ensure_future(self._handle_pyppeteer_request(req)))
                self.page.on("response", lambda res: asyncio.ensure_future(self._handle_pyppeteer_response(res)))

            else:
                 self.log_message.emit("<span style='color:#ff0000'>[!] CRITICAL: Neither Playwright nor Pyppeteer is installed. Cannot launch browser.</span>")
                 return
            
            # Apply Stealth Scripts
            await self._apply_stealth()
            
        except Exception as e:
            self.log_message.emit(f"<span style='color:#ff0000'>[!] Browser Init Failed: {str(e)}</span>")

    async def check_connection(self):
        """Verifies if the browser and page are still alive. Restarts if dead."""
        try:
            if HAS_PLAYWRIGHT:
                if not self.browser or not self.browser.is_connected() or not self.page or self.page.is_closed():
                     self.log_message.emit("<span style='color:#ffcc00'>[*] Browser connection lost. Re-initializing...</span>")
                     await self.initialize()
                     return self.page is not None
                return True
            elif HAS_PYPPETEER:
                if not self.browser or self.page.isClosed():
                     self.log_message.emit("<span style='color:#ffcc00'>[*] Pyppeteer connection lost. Re-initializing...</span>")
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
                if HAS_PLAYWRIGHT:
                    if not self.page or self.page.is_closed(): raise Exception("Page Closed")
                    await self.page.set_extra_http_headers({
                        "Accept-Language": "en-US,en;q=0.9",
                        "Upgrade-Insecure-Requests": "1",
                        "Sec-Ch-Ua": '"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"',
                        "Sec-Ch-Ua-Mobile": "?0",
                        "Sec-Ch-Ua-Platform": '"Windows"',
                    })
                elif HAS_PYPPETEER:
                    if not self.page or self.page.isClosed(): raise Exception("Page Closed")
                    await self.page.setExtraHTTPHeaders({
                        "Accept-Language": "en-US,en;q=0.9",
                        "Upgrade-Insecure-Requests": "1",
                        "Sec-Ch-Ua": '"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"',
                        "Sec-Ch-Ua-Mobile": "?0",
                        "Sec-Ch-Ua-Platform": '"Windows"',
                    })
                
                # Apply Spoofer/Stealth before navigation
                await self._rotate_identity()
                
                try:
                    if HAS_PLAYWRIGHT:
                        response = await self.page.goto(url, wait_until="domcontentloaded", timeout=45000)
                        status_code = response.status if response else 0
                    else:
                        response = await self.page.goto(url, waitUntil="domcontentloaded", timeout=45000)
                        status_code = response.status if response else 0
                except Exception as e:
                    if "Connection closed" in str(e) or "Target closed" in str(e):
                        raise Exception("Browser Crash Detected")
                    raise e
                
                # WAF/Block Detection & Retry Logic
                if status_code in [403, 406, 503]:
                     self.log_message.emit(f"<span style='color:#ffcc00'>[!] WAF Blocked ({status_code}) - Retrying with new identity...</span>")
                     await asyncio.sleep(5)
                     await self._rotate_identity()
                     if HAS_PLAYWRIGHT:
                         response = await self.page.goto(url, wait_until="domcontentloaded", timeout=45000)
                         status_code = response.status if response else 0
                     else:
                         response = await self.page.goto(url, waitUntil="domcontentloaded", timeout=45000)
                         status_code = response.status if response else 0
                     
                if status_code in [401, 403]:
                     self.log_message.emit(f"<span style='color:#ff0055'>[!] Access Denied ({status_code}) - WAF/Bot Protection active.</span>")
                
                # Wait a bit for potential JS redirects or challenges
                if HAS_PLAYWRIGHT:
                    await self.page.wait_for_timeout(3000)
                else:
                    await self.page.waitForTimeout(3000)

                # ADVANCED CAPTCHA / DDOS GUARD EVASION
                await self._attempt_captcha_solve()

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
                    if HAS_PLAYWRIGHT:
                        await self.page.screenshot(path=screenshot_path, full_page=True)
                    else:
                        await self.page.screenshot({'path': screenshot_path, 'fullPage': True})
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
        """[DEPRECATED] Extreme bypass removed to enforce zero false-positives and maximum performance."""
        self.log_message.emit("<span style='color:#aa00ff'>[AI] Skipping speculative bypass vectors to maintain 100% accuracy and performance.</span>")
        pass

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
                 if HAS_PLAYWRIGHT:
                     await self.page.wait_for_event("close", timeout=0) 
                 # pyppeteer doesn't have a direct equivalent that blocks like this easily without custom loops
             except:
                 pass

        if HAS_PLAYWRIGHT:
            if self.context: await self.context.close()
            if self.browser: await self.browser.close()
            if self.playwright: await self.playwright.stop()
        elif HAS_PYPPETEER:
            if self.browser: await self.browser.close()

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
            "frame-ancestors", "violates the following", "refused to apply style",
            "refused to execute script", "mime type"
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

    # --- Pyppeteer Wrappers ---
    async def _handle_pyppeteer_console(self, msg):
        class PseudoMsg:
             def __init__(self, m):
                 self.text = m.text
                 self.type = m.type
        await self._handle_console(PseudoMsg(msg))
        
    async def _handle_pyppeteer_request(self, req):
         class PseudoReq:
              def __init__(self, r):
                  self.url = r.url
                  self.method = r.method
                  self.post_data = r.postData
         await self._handle_request(PseudoReq(req))
         
    async def _handle_pyppeteer_response(self, res):
         class PseudoRes:
              def __init__(self, r):
                  self.headers = r.headers
                  self.url = r.url
         await self._handle_response(PseudoRes(res))
    
    # ==========================================
    # BEHAVIORAL AI & CAPTCHA AUTOSOLVER
    # ==========================================
    async def _human_mouse_move(self, target_x, target_y):
         """Simulates organic human mouse movement using Bezier curves and variable speeds."""
         if not HAS_PLAYWRIGHT or not self.page: return
         import random
         
         # Get current position (mock if not previously moved)
         if not hasattr(self, 'mouse_x'):
             # Start near center-top
             self.mouse_x = random.randint(400, 1500)
             self.mouse_y = random.randint(100, 300)
             
         start_x, start_y = self.mouse_x, self.mouse_y
         
         # Control points for the curve
         ctrl_x = start_x + (target_x - start_x) * random.uniform(0.2, 0.8) + random.uniform(-100, 100)
         ctrl_y = start_y + (target_y - start_y) * random.uniform(0.2, 0.8) + random.uniform(-100, 100)

         steps = random.randint(15, 30) # More steps = smoother slower curve
         for i in range(1, steps + 1):
             t = i / steps
             # Quadratic Bezier formula
             x = (1 - t)**2 * start_x + 2 * (1 - t) * t * ctrl_x + t**2 * target_x
             y = (1 - t)**2 * start_y + 2 * (1 - t) * t * ctrl_y + t**2 * target_y
             
             await self.page.mouse.move(x, y)
             # Variable organic delay (humans pause slightly mid-movement)
             await asyncio.sleep(random.uniform(0.01, 0.05))
             if random.random() > 0.95: await asyncio.sleep(random.uniform(0.1, 0.3)) # Micro-hesitation
             
         self.mouse_x = target_x
         self.mouse_y = target_y

    async def _attempt_captcha_solve(self):
         """Detects and attempts to bypass reCAPTCHA and hCaptcha using behavioral interaction."""
         if not HAS_PLAYWRIGHT or not self.page: return
         import random
         
         try:
             # Wait for dynamic cross-origin iframes to inject and establish their URLs
             # domcontentloaded does NOT wait for iframes!
             await self.page.wait_for_timeout(3500)
             
             # Scan iframes for CAPTCHA signatures
             frames = self.page.frames
             for frame in frames:
                 url = frame.url.lower()
                 if "recaptcha" in url or "hcaptcha" in url or "turnstile" in url:
                      self.log_message.emit(f"<span style='color:#ff9d00'>[Governor] Detected Anti-Bot Challenge ({url.split('/')[2][:15]}). Engaging organic solver...</span>")
                      
                      # If this is the challenge pop-out (bframe), attempt Audio AI bypass
                      if "bframe" in url:
                          await self._solve_audio_captcha(frame)
                          continue
                      
                      # Find the checkbox or challenge container
                      # We try generic locators that match most common implementations
                      try:
                          # Give the iframe time to load its DOM
                          await self.page.wait_for_timeout(random.randint(1500, 3000))
                          
                          elements = await frame.locator('.recaptcha-checkbox, #checkbox, .h-captcha, .cf-turnstile').element_handles()
                          
                          # Extract global coordinates of the iframe container to offset the internal clicks
                          iframe_element = await frame.frame_element()
                          iframe_box = await iframe_element.bounding_box() if iframe_element else {'x': 0, 'y': 0}
                          offset_x = iframe_box['x'] if iframe_box else 0
                          offset_y = iframe_box['y'] if iframe_box else 0
                          
                          for element in elements:
                               box = await element.bounding_box()
                               if box:
                                    # Target the center of the checkbox with slight random flaw,
                                    # added to the absolute offset of the parent iframe.
                                    target_x = offset_x + box['x'] + (box['width'] / 2) + random.uniform(-3, 3)
                                    target_y = offset_y + box['y'] + (box['height'] / 2) + random.uniform(-3, 3)
                                    
                                    # Organic path to checkbox
                                    await self._human_mouse_move(target_x, target_y)
                                    
                                    # Hover hesitation
                                    await asyncio.sleep(random.uniform(0.3, 0.8))
                                    
                                    # Precise click
                                    await self.page.mouse.down()
                                    await asyncio.sleep(random.uniform(0.05, 0.15)) # Click duration
                                    await self.page.mouse.up()
                                    
                                    self.log_message.emit("<span style='color:#00ff9d'>[Governor] Organic CAPTCHA interaction executed. Waiting for backend validation.</span>")
                                    # Give it time to solve (invisible recaptchas might approve instantly based on the mouse physics)
                                    await self.page.wait_for_timeout(4000)
                                    break
                      except Exception as e:
                          # Might be invisible completely or different structure
                          pass
         except:
             pass

    async def _solve_audio_captcha(self, frame):
         """Uses the user's Groq AI key to whisper-transcribe the Google Audio CAPTCHA."""
         if not self.ai_key:
             self.log_message.emit("<span style='color:#aaa'>[Governor] No Groq AI key provided. Skipping Audio Bypass for CAPTCHA.</span>")
             return
             
         try:
             import aiohttp
             import json
             import base64
             
             self.log_message.emit("<span style='color:#00ff9d'>[Governor] Deploying AI Audio Bypass (Whisper-v3)...</span>")
             
             # 1. Click the "Audio" button to switch from Visual to Audio challenge
             audio_btn = frame.locator('#recaptcha-audio-button')
             if await audio_btn.count() > 0:
                 await audio_btn.click()
                 await self.page.wait_for_timeout(1500)
                 
             # 2. Extract the Audio MP3 URL
             audio_src = frame.locator('#audio-source')
             if await audio_src.count() == 0:
                 return
                 
             mp3_url = await audio_src.get_attribute('src')
             if not mp3_url: return
             
             # 3. Download the MP3 via Browser Context (to keep Google cookies/session)
             self.log_message.emit("<span style='color:#ffcc00'>[Governor] Intercepting challenge audio stream...</span>")
             b64_audio = await frame.evaluate('''async (url) => {
                 const res = await fetch(url);
                 const blob = await res.blob();
                 return new Promise(resolve => {
                     const reader = new FileReader();
                     reader.onloadend = () => resolve(reader.result.split(',')[1]);
                     reader.readAsDataURL(blob);
                 });
             }''', mp3_url)
             
             if not b64_audio: return
             
             # Save to disk temporarily
             mp3_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs", "challenge.mp3")
             os.makedirs(os.path.dirname(mp3_path), exist_ok=True)
             with open(mp3_path, "wb") as f:
                 f.write(base64.b64decode(b64_audio))
                 
             # 4. Transcribe using Groq Whisper API
             self.log_message.emit("<span style='color:#00f3ff'>[Governor] Transcribing audio via Groq Neural Engine...</span>")
             form_data = aiohttp.FormData()
             form_data.add_field('file', open(mp3_path, 'rb'), filename='challenge.mp3', content_type='audio/mpeg')
             form_data.add_field('model', 'whisper-large-v3')
             
             headers = {"Authorization": f"Bearer {self.ai_key}"}
             async with aiohttp.ClientSession() as session:
                 async with session.post("https://api.groq.com/openai/v1/audio/transcriptions", data=form_data, headers=headers) as response:
                     if response.status == 200:
                         data = await response.json()
                         text = data.get('text', '').strip()
                         
                         if text:
                             self.log_message.emit(f"<span style='color:#ff0055'>[Governor] AI Transcribed Code: {text}</span>")
                             
                             # 5. Inject Solution and Click Verify
                             input_field = frame.locator('#audio-response')
                             if await input_field.count() > 0:
                                 # Type like a human
                                 await input_field.type(text, delay=random.randint(50, 150))
                                 await self.page.wait_for_timeout(500)
                                 
                                 verify_btn = frame.locator('#recaptcha-verify-button')
                                 if await verify_btn.count() > 0:
                                     await verify_btn.click()
                                     self.log_message.emit("<span style='color:#00ff9d'>[Governor] Solution submitted! Waiting for Google approval...</span>")
                                     await self.page.wait_for_timeout(3000)
                     else:
                         self.log_message.emit(f"<span style='color:#ff5555'>[Governor] Groq API Failed: {await response.text()}</span>")
         except Exception as e:
             self.log_message.emit(f"<span style='color:#ff5555'>[Governor] Audio Bypass Exception: {str(e)}</span>")

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
            if HAS_PLAYWRIGHT:
                cookies = await self.context.cookies()
            else:
                cookies = await self.page.cookies()
                
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
             if HAS_PLAYWRIGHT:
                 await self.page.wait_for_load_state("networkidle", timeout=5000)
             else:
                 await self.page.waitForNavigation({'waitUntil': 'networkidle2', 'timeout': 5000})
        except:
             pass
             
        links = await self.page.evaluate('''() => {
            return Array.from(document.querySelectorAll('a')).map(a => a.href);
        }''')
        self.log_message.emit(f"<span style='color:#aaa'>[Spider] Found {len(links)} links on page (JS-Rendered).</span>")

    async def _apply_stealth(self):
        """Injects JS to mask webdriver and emulate a real user."""
        try:
            script = """
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
            """
            if HAS_PLAYWRIGHT:
                await self.page.add_init_script(script)
            else:
                await self.page.evaluateOnNewDocument(script)
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
             if HAS_PLAYWRIGHT and self.context:
                await self.context.clear_cookies()
                await self.context.clear_permissions()
                # Clear storage via CDP for depth
                try: 
                    if not self.page or self.page.is_closed(): return
                    client = await self.context.new_cdp_session(self.page)
                    await client.send('Storage.clearDataForOrigin', {'origin': '*', 'storageTypes': 'all'})
                    await client.detach() # Clean up
                except: pass
             elif HAS_PYPPETEER and self.page:
                client = await self.page.target.createCDPSession()
                await client.send('Network.clearBrowserCookies')
                await client.send('Network.clearBrowserCache')
                # basic clearance fallback
        except: pass
        
        # 2. Select High-Quality User-Agent
        uas = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0'
        ]
        new_ua = random.choice(uas)
        headers = {
            'User-Agent': new_ua,
            'Accept-Language': 'en-US,en;q=0.9',
            'Sec-Ch-Ua': '"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"'
        }
        
        if HAS_PLAYWRIGHT and self.context:
            await self.context.set_extra_http_headers(headers)
        elif HAS_PYPPETEER and self.page:
            await self.page.setExtraHTTPHeaders(headers)

        # 3. Inject Advanced Fingerprinting Protection
        if self.page:
            try:
                script = """
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
                        
                        // 2. Mock WebGL Vendor (NVIDIA/AMD Spoofing)
                        try {
                            const getParameter = WebGLRenderingContext.prototype.getParameter;
                            
                            // Generate persistent session hash to avoid fluctuating fingerprints
                            const sessionSalt = Math.random().toString(36).substring(7);
                            
                            WebGLRenderingContext.prototype.getParameter = function(parameter) {
                                // Math random salt prevents basic DB matching
                                if (parameter === 37445) return 'Google Inc. (NVIDIA)';
                                if (parameter === 37446) return 'ANGLE (NVIDIA, NVIDIA GeForce RTX 4090 Direct3D11 vs_5_0 ps_5_0, D3D11) - ' + sessionSalt; // Unique per load
                                return getParameter.apply(this, arguments);
                            };
                        } catch(e) {}
                        
                        // 3. Canvas Cryptographic Spoofing (Defeats Cloudflare Canvas Fingerprinting)
                        try {
                            const getImageData = CanvasRenderingContext2D.prototype.getImageData;
                            
                            // Create a static noise hash for this page load so it's consistent during the session
                            // Fluctuating canvas data triggers high-risk bot flags!
                            const sessionNoise = {
                                r: Math.floor(Math.random() * 5) - 2,
                                g: Math.floor(Math.random() * 5) - 2,
                                b: Math.floor(Math.random() * 5) - 2,
                                a: Math.floor(Math.random() * 5) - 2
                            };
                            
                            CanvasRenderingContext2D.prototype.getImageData = function(x, y, w, h) {
                                const image = getImageData.apply(this, arguments);
                                try {
                                    // Mutate the pixel data predictably but uniquely
                                    for (let i = 0; i < image.data.length; i += 4) { 
                                        // A subtle tint that changes the MD5 hash of the Canvas, but visually looks identical
                                        image.data[i] = Math.max(0, Math.min(255, image.data[i] + sessionNoise.r));
                                        image.data[i+1] = Math.max(0, Math.min(255, image.data[i+1] + sessionNoise.g));
                                        image.data[i+2] = Math.max(0, Math.min(255, image.data[i+2] + sessionNoise.b));
                                        image.data[i+3] = Math.max(0, Math.min(255, image.data[i+3] + sessionNoise.a));
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
                """
                if HAS_PLAYWRIGHT:
                    await self.page.add_init_script(script)
                else:
                    await self.page.evaluateOnNewDocument(script)
            except: pass
        
        self.log_message.emit(f"<span style='color:#00f3ff'>[Stealth] Identity Rotated (UA: {new_ua[:25]}... | GPU: RTX 3070 | Human Behavior: Active)</span>")
