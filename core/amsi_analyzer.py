import asyncio
import logging
from typing import Dict, Any

class AMSIAnalyzer:
    """
    NexusScanner Module: AMSI & WAF Detection Engine
    
    This module is designed for ethical auditing and mapping of server-side 
    defenses. It does NOT exploit systems, but rather sends standardized, 
    harmless test signatures to determine if the target infrastructure integrates 
    with Windows AMSI (Antimalware Scan Interface) or robust Web Application Firewalls.
    """
    def __init__(self, session):
        self.session = session
        
        # Industry-standard strings used strictly for triggering and testing defense mechanisms.
        # These do not execute code and are entirely harmless.
        self.test_signatures = {
            # Standard EICAR Antivirus Test File signature
            "EICAR_TEST": r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
            
            # Common string that often triggers AMSI in PowerShell/IIS environments if logged
            "AMSI_TRIGGER_TEST": "Invoke-Expression 'AMSI_Test_String_For_Auditing'",
            
            # Generic webshell behavioral test string (eval detection)
            "WEBSHELL_HEURISTIC_TEST": "eval(base64_decode('QXVkaXRfVGVzdF9TdHJpbmc='))"
        }

    async def run_detection(self, target_url: str) -> Dict[str, Any]:
        """
        Actively probes the target URL with benign signatures to map security behaviors.
        """
        results = {
            "amsi_detected": False,
            "waf_detected": False,
            "blocked_signatures": [],
            "baseline_status": 200
        }
        
        # 1. Establish baseline (normal request) to rule out regular 403s
        try:
            async with self.session.get(target_url, timeout=5) as baseline:
                results["baseline_status"] = baseline.status
        except Exception:
            return results # Target down or unreachable

        # 2. Inject test signatures to observe deviation from baseline
        for name, signature in self.test_signatures.items():
            try:
                # We inject the signature harmlessly into the User-Agent and a dummy parameter
                headers = {"User-Agent": f"NexusAuditor {signature}"}
                params = {"test_query": signature}
                
                async with self.session.get(target_url, headers=headers, params=params, timeout=5) as response:
                    content = await response.text()
                    
                    # Logic: If baseline was OK, but the signature triggers a 403/406 or drops the connection
                    if response.status in [403, 406] and results["baseline_status"] not in [403, 406]:
                        results["blocked_signatures"].append(name)
                        
                        # Differentiate between generic WAF block and specific Antimalware block indicators
                        content_lower = content.lower()
                        if "malware" in content_lower or "virus" in content_lower or "amsi" in content_lower:
                            results["amsi_detected"] = True
                        else:
                            results["waf_detected"] = True

            except asyncio.TimeoutError:
                # Stealth drops (silent connection termination) usually indicate aggressive IPS/AMSI killing the socket.
                results["blocked_signatures"].append(name)
            except Exception as e:
                logging.debug(f"AMSI probe error on {name}: {str(e)}")
                
        return results

    def format_report(self, results: Dict[str, Any]) -> str:
        """Formats the detection results into an auditor-friendly string."""
        if not results["blocked_signatures"]:
            return "No integrated AMSI/WAF defense active against standard parameter inspection."
        
        report = []
        if results["amsi_detected"]:
            report.append("[+] Antimalware Scan Interface (AMSI) integration strongly suspected.")
        if results["waf_detected"]:
            report.append("[+] Web Application Firewall (WAF) rule trigger detected.")
            
        report.append(f"Blocked Test Signatures: {', '.join(results['blocked_signatures'])}")
        return " | ".join(report)
