
import re
import os
import time
from urllib.parse import urlparse

class CredentialDumper:
    """
    Advanced system for detecting, extracting, and dumping sensitive credentials
    and database information from HTTP responses.
    """
    def __init__(self, output_dir="scans/loot"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            
        self.signatures = {
            "SQL Dump": [
                r"CREATE TABLE", r"INSERT INTO", r"DROP TABLE", 
                r"-- MySQL dump", r"pg_dump", r"sqlite_format"
            ],
            "Environment Config": [
                r"APP_KEY=", r"DB_PASSWORD=", r"AWS_SECRET_ACCESS_KEY=",
                r"FTP_PASSWORD=", r"MAIL_PASSWORD="
            ],
            "Shadow File": [
                r"root:\$[16]\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+:",
                r"www-data:[x*]:"
            ],
            "FTP Config": [
                r"ftp://[a-zA-Z0-9_]+:[a-zA-Z0-9_@#$%^&*]+@",
                r"<Host>.*</Host>.*<User>.*</User>.*<Pass>.*</Pass>", # FileZilla
                r"anon_upload_enable=YES"
            ],
            "SSH Keys": [
                r"-----BEGIN OPENSSH PRIVATE KEY-----",
                r"-----BEGIN RSA PRIVATE KEY-----"
            ]
        }

    def analyze(self, url, content):
        """
        Analyzes content for sensitive dumps and saves them if found.
        Returns a tuple (bool_found, finding_type, finding_summary).
        """
        if not content: return False, None, None
        
        # Binary check (skip images/etc but keep text-like binaries)
        if len(content) > 5242880: # Skip > 5MB to avoid hang
            return False, None, None

        text_content = ""
        if isinstance(content, str):
            text_content = content
        else:
            try:
                text_content = content.decode('utf-8', errors='ignore')
            except:
                return False, None, None

        for dump_type, sigs in self.signatures.items():
            for sig in sigs:
                if re.search(sig, text_content, re.IGNORECASE):
                    # CONFIRMED HIT
                    filename = self._save_dump(url, dump_type, text_content)
                    preview = text_content[:200].replace("\n", " ")
                    return True, dump_type, f"Saved to {filename} | Preview: {preview}..."

        return False, None, None

    def _save_dump(self, url, dump_type, content):
        """Saves the dumped content to a file."""
        parsed = urlparse(url)
        hostname = parsed.hostname or "unknown"
        clean_host = "".join([c if c.isalnum() or c in ".-" else "_" for c in hostname])
        clean_type = dump_type.replace(" ", "_").lower()
        timestamp = int(time.time())
        
        # Structure: scans/loot/<hostname>/<type>_<timestamp>.txt
        host_dir = os.path.join(self.output_dir, clean_host)
        if not os.path.exists(host_dir):
            os.makedirs(host_dir)
            
        filename = f"{clean_type}_{timestamp}.txt"
        filepath = os.path.join(host_dir, filename)
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(f"URL: {url}\n")
            f.write(f"TYPE: {dump_type}\n")
            f.write(f"TIME: {time.ctime()}\n")
            f.write("-" * 50 + "\n")
            f.write(content)
            
        # Also append to master loot list
        master_log = os.path.join(self.output_dir, "master_loot.txt")
        with open(master_log, "a", encoding="utf-8") as f:
            f.write(f"[{time.ctime()}] {dump_type} found at {url} -> {filepath}\n")
            
        return filepath
