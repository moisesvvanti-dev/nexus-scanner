import aiohttp
import asyncio
import re

class SubdomainEnumerator:
    def __init__(self, domain):
        self.domain = domain
        self.found_subdomains = set()

    async def run(self):
        """Queries crt.sh to find subdomains."""
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data:
                            name_value = entry['name_value']
                            subdomains = name_value.split('\n')
                            for sub in subdomains:
                                if sub and '*' not in sub and sub.endswith(self.domain):
                                    self.found_subdomains.add(sub)
        except:
            pass
        return list(self.found_subdomains)

class HackerTargetEnumerator:
    def __init__(self, domain):
        self.domain = domain
        
    async def run(self):
        """Queries HackerTarget API for subdomains."""
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        subdomains = set()
        try:
             async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as response:
                    if response.status == 200:
                        text = await response.text()
                        for line in text.splitlines():
                            parts = line.split(',')
                            if parts:
                                sub = parts[0]
                                if sub and sub != self.domain and self.domain in sub:
                                    subdomains.add(sub)
        except:
            pass
        return list(subdomains)

class UberRecon:
    def __init__(self):
        self.api_url = "https://appsec-analysis.uber.com/public/bugbounty/ListDomains"

    async def fetch_assets(self, limit=50):
        """Fetches in-scope domains from Uber's official Asset Recon API."""
        assets = []
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.api_url}?offset=0&limit={limit}"
                async with session.get(url, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        # Handling potential response formats
                        if isinstance(data, list): # Expected format
                            for entry in data:
                                if isinstance(entry, str):
                                    assets.append(entry)
                                elif isinstance(entry, dict) and 'asset' in entry: # e.g. {"asset": "uber.com"}
                                    assets.append(entry['asset'])
                                elif isinstance(entry, dict) and 'domain' in entry:
                                    assets.append(entry['domain'])
        except Exception as e:
            pass
        return assets

class CloudBucketEnumerator:
    def __init__(self, domain):
        self.domain = domain
        self.base_name = domain.split('.')[0]
        self.permutations = [
            self.base_name,
            f"{self.base_name}-dev",
            f"{self.base_name}-prod",
            f"{self.base_name}-staging",
            f"{self.base_name}-backup",
            f"{self.base_name}-assets",
            f"{self.base_name}-static",
            f"{self.base_name}.com",
            f"www.{self.base_name}"
        ]

    async def run(self):
        """Checks for open cloud buckets (AWS, Azure, GCP)."""
        results = []
        async with aiohttp.ClientSession() as session:
            for name in self.permutations:
                # AWS S3
                s3_url = f"http://{name}.s3.amazonaws.com"
                await self._check_bucket(session, s3_url, "AWS S3", results)
                
                # Azure Blob
                az_url = f"https://{name}.blob.core.windows.net/container" # Check root/container
                await self._check_bucket(session, az_url, "Azure Blob", results)
                
                # GCP Storage
                gcp_url = f"https://storage.googleapis.com/{name}"
                await self._check_bucket(session, gcp_url, "GCP Bucket", results)
        return results

    async def _check_bucket(self, session, url, provider, results):
        try:
            async with session.get(url, timeout=3) as r:
                if r.status == 200:
                    results.append(f"{provider}: {url} (OPEN/PUBLIC)")
                elif r.status == 403:
                     # 403 means it exists but is private - still valuable intel
                    results.append(f"{provider}: {url} (Protected/Exists)")
        except:
            pass

class TakeoverDetector:
    def __init__(self):
        self.fingerprints = {
            "github.io": "GitHub Pages",
            "herokuapp.com": "Heroku",
            "s3.amazonaws.com": "AWS S3",
            "azurewebsites.net": "Azure App Service",
            "cloudapp.net": "Azure Cloud Service",
            "wordpress.com": "WordPress",
            "pantheon.io": "Pantheon",
            "readme.io": "Readme.io",
            "ghost.io": "Ghost"
        }

    async def check(self, domain):
        """Checks if a subdomain has a dangling CNAME leading to takeover."""
        cname = await self._get_cname(domain)
        if not cname: return None

        for finger, service in self.fingerprints.items():
            if finger in cname:
                # We found a CNAME to a cloud provider. 
                # To verify takeover, we'd check if the endpoint returns a 404/NXDOMAIN.
                # For safety/simplicity, we just report the Potential Takeover for now.
                return f"Potential {service} Takeover (CNAME: {cname})"
        return None

    async def _get_cname(self, domain):
        """Uses Google DNS API to fetch CNAME (No local deps)."""
        url = f"https://dns.google/resolve?name={domain}&type=CNAME"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=5) as r:
                    if r.status == 200:
                        data = await r.json()
                        if 'Answer' in data:
                            for ans in data['Answer']:
                                if ans['type'] == 5: # CNAME
                                    return ans['data'].strip('.')
        except:
            pass
        return None
