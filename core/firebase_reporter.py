import firebase_admin
from firebase_admin import credentials, db
import os
import json
from datetime import datetime

class FirebaseReporter:
    def __init__(self, key_path):
        self.key_path = key_path
        self.app = None
        self._initialize_app()

    def _initialize_app(self):
        try:
            if not firebase_admin._apps:
                cred = credentials.Certificate(self.key_path)
                # Parse JSON to extract project id dynamically if needed
                with open(self.key_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    project_id = data.get('project_id', 'login-66783')
                
                self.app = firebase_admin.initialize_app(cred, {
                    'databaseURL': f'https://{project_id}-default-rtdb.firebaseio.com'
                })
        except Exception:
            # Silence "File not found" errors as it's an optional feature
            pass

    def send_report(self, target_url, findings):
        if not firebase_admin._apps:
            print("Firebase not initialized.")
            return False

        try:
            ref = db.reference('scans')
            
            # Format data
            report_data = {
                "target": target_url,
                "timestamp": datetime.now().isoformat(),
                "findings_count": len(findings),
                "critical_count": sum(1 for f in findings if getattr(f, 'severity', '') == 'CRITICAL'),
                "findings": list()
            }
            
            for f in findings:
                finding_dict = {
                    "severity": getattr(f, 'severity', 'UNKNOWN'),
                    "type": getattr(f, 'vuln_type', 'Unknown'),
                    "target_url": getattr(f, 'target', ''),
                    "impact": getattr(f, 'impact', '')
                }
                report_data["findings"].append(finding_dict)

            # Push to database
            new_scan_ref = ref.push()
            new_scan_ref.set(report_data)
            print(f"Report successfully uploaded to Firebase: {new_scan_ref.key}")
            return True
        except Exception as e:
            print(f"Failed to upload report to Firebase: {e}")
            return False
