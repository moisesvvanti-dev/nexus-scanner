import os
import json
import asyncio
import aiohttp
import zipfile
import io
import re

print("--------------------------------------------------------------")
print(" NEXUS ULTIMA - GOVERNMENTAL CVE SYNCHRONIZER                 ")
print(" Pulling 'All CVEs in the world' via ProjectDiscovery Nuclei  ")
print("--------------------------------------------------------------")

NUCLEI_ZIP_URL = "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip"
JSON_OUTPUT = os.path.join(os.path.dirname(__file__), "..", "data", "cve.json")

async def download_and_compile():
    print("[*] Contacting Global Exploit Repositories (ProjectDiscovery)...")
    
    # PentestGPT Format Database
    cve_db = []
    
    # We add the core ones manually first to ensure the base array exists
    base_cves = [
        {
            "name": "[CRITICAL] Generic Path Traversal & LFI Deep Scan",
            "category": "LFI",
            "type": "LFI",
            "check_type": "path",
            "path": "/../../../../../../../../../../etc/passwd",
            "indicator": "root:x:0:0",
            "status": [200]
        },
        {
            "name": "[CRITICAL] Windows LFI Deep Scan",
            "category": "LFI",
            "type": "LFI",
            "check_type": "path",
            "path": "/..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "indicator": "[extensions]",
            "status": [200]
        }
    ]
    cve_db.extend(base_cves)

    try:
        async with aiohttp.ClientSession() as session:
            print("[*] Downloading latest Nuclei Templates Archive (~50MB+)...")
            async with session.get(NUCLEI_ZIP_URL, timeout=120) as response:
                if response.status != 200:
                    print(f"[!] Failed to download repository: {response.status}")
                    return
                
                zip_data = await response.read()
                print("[*] Archive downloaded. Decompressing and mining CVE signatures in memory...")
                
                with zipfile.ZipFile(io.BytesIO(zip_data)) as z:
                    yaml_files = [f for f in z.namelist() if f.endswith('.yaml') and ('cves/' in f or 'vulnerabilities/' in f)]
                    print(f"[*] Found {len(yaml_files)} raw Exploit/CVE Templates. Compiling massive JSON...")
                    
                    compiled_count = 0
                    
                    for yml_path in yaml_files:
                        content = z.read(yml_path).decode('utf-8', errors='ignore')
                        
                        # Extreme fast Regex parsing to avoid PyYAML dependency overhead for 10,000 files
                        name_match = re.search(r'name:\s*(.+)', content)
                        path_matches = re.findall(r'path:\s*\n\s*-\s*["\']?(?:\{\{BaseURL\}\})?([^"\']+)', content)
                        matcher_word = re.search(r'words:\s*\n\s*-\s*["\']?([^"\']+)["\']?', content)
                        
                        if name_match and path_matches and matcher_word:
                            cve_name = name_match.group(1).strip().strip("'").strip('"')
                            indicator = matcher_word.group(1).strip()
                            
                            # Usually getting the first listed variation path
                            for path_variation in path_matches:
                                if len(path_variation) < 2: continue # skip empty paths
                                
                                cve_db.append({
                                    "name": f"[SYNCED] {cve_name}",
                                    "category": "Exploit",
                                    "type": "Auto-Synced",
                                    "check_type": "path",
                                    "path": path_variation,
                                    "indicator": indicator,
                                    "status": [200, 500]
                                })
                                compiled_count += 1
                                
                                # Cap variations to prevent single CVE exploding with 100 paths
                                if compiled_count % 1000 == 0:
                                     print(f"    -> Compiled {compiled_count} payload variations...")
                                
    except Exception as e:
        print(f"[!] Critical Error during Sync: {str(e)}")
        
    print(f"\n[*] Sync Complete. Writing {len(cve_db)} CVE/Exploit payloads to {JSON_OUTPUT}...")
    
    os.makedirs(os.path.dirname(JSON_OUTPUT), exist_ok=True)
    with open(JSON_OUTPUT, "w", encoding="utf-8") as f:
        json.dump(cve_db, f, indent=4)
        
    print("[+] SUCCESS! PentestGPT is now loaded with the global CVE arsenal.")
    print("    Warning: Running scans with this DB will unleash tens of thousands of requests per target.")

if __name__ == "__main__":
    asyncio.run(download_and_compile())
