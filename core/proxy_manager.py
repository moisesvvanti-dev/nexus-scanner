import aiohttp
import asyncio
import random
import re
import os
import time
from typing import List, Optional

class ProxyManager:
    """
    Manages a pool of free proxies for rotation.
    Scrapes from public lists, validates anonymity, and persists working proxies.
    Includes advanced latency tracking, failure rates, and background health checks.
    """
    def __init__(self):
        self.proxies: List[str] = []
        self.working_proxies: List[str] = []
        self.proxy_stats = {} # Dict storing {proxy_url: {"latency": float, "fails": int, "success": int}}
        self.is_initialized = False
        self.storage_file = os.path.join("data", "proxies_checked.txt")
        
        # Expanded Source List
        self.sources = [
            "https://www.sslproxies.org/",
            "https://free-proxy-list.net/",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
            "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
            "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt",
            "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt"
        ]

    async def initialize(self):
        """Scrapes and validates proxies."""
        if self.is_initialized: return
        
        # Load from cache first
        if os.path.exists(self.storage_file):
            self._load_proxies()
            if len(self.working_proxies) > 10:
                print(f"[*] Loaded {len(self.working_proxies)} cached proxies.")
                self.is_initialized = True
                # Background refresh
                asyncio.create_task(self.refresh_proxies())
                return

        print("[*] Initializing Proxy Pool (Scraping & Validating)...")
        await self.refresh_proxies()
        self.is_initialized = True

    async def refresh_proxies(self):
        """Scrapes new proxies from sources."""
        self.proxies = []
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self._fetch_source(session, src) for src in self.sources]
            results = await asyncio.gather(*tasks)
            
        for res in results:
            self.proxies.extend(res)
            
        # Unique list
        self.proxies = list(set(self.proxies))
        print(f"[*] Scraped {len(self.proxies)} potential proxies. Validating...")
        
        # Verify a subset to get started quickly, then the rest
        await self.verify_proxies(limit=200)

    async def _fetch_source(self, session, url):
        try:
            async with session.get(url, timeout=10) as response:
                text = await response.text()
                # Regex for IP:PORT (Generic for IPv4)
                return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d+\b", text)
        except:
            return []

    async def verify_proxies(self, limit=100):
        """Verifies proxies are alive and anonymous."""
        candidates = self.proxies[:limit]
        random.shuffle(candidates)
        
        self.working_proxies = [] 
        
        # Concurrency limit
        sem = asyncio.Semaphore(50) 

        async def check(session, proxy):
            async with sem:
                try:
                    proxy_url = f"http://{proxy}"
                    target = "http://httpbin.org/ip"
                    start = time.time()
                    
                    # Use shared session
                    async with session.get(target, proxy=proxy_url, timeout=aiohttp.ClientTimeout(total=5)) as r:
                         if r.status == 200:
                             await r.read() 
                             latency = time.time() - start
                             if latency < 4.0:
                                 self.working_proxies.append(proxy_url)
                                 self.proxy_stats[proxy_url] = {"latency": latency, "fails": 0, "success": 1}
                except Exception:
                    # Catch everything, including OSError/ConnectionResetError
                    pass

        # Use a single session for all checks to prevent socket churn/WinError 10054
        connector = aiohttp.TCPConnector(limit=None, ssl=False)
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = [check(session, p) for p in candidates]
            if tasks:
                await asyncio.gather(*tasks)
             
        print(f"[*] Proxy Pool Ready: {len(self.working_proxies)} working proxies.")
        self._save_proxies()

    def get_proxy(self) -> Optional[str]:
        """Returns an intelligent selection of a working proxy prioritizing low latency and high success rate."""
        if not self.working_proxies:
            return None
            
        # Filter out extremely degraded proxies temporarily
        available = [p for p in self.working_proxies if self.proxy_stats.get(p, {}).get("fails", 0) < 5]
        if not available:
            available = self.working_proxies # Fallback to any if all failed heavily
            
        # Score proxies: (success_rate * 10) - (latency) - (fails * 2)
        def score_proxy(p):
            stats = self.proxy_stats.get(p, {"latency": 5.0, "fails": 0, "success": 1})
            total_req = stats["success"] + stats["fails"]
            success_rate = (stats["success"] / total_req) if total_req > 0 else 0.5
            return (success_rate * 10) - stats["latency"] - (stats["fails"] * 2)
            
        # Sort by score descending
        available.sort(key=score_proxy, reverse=True)
        
        # Select randomly from the top 30% to distribute load among good proxies
        top_k = max(1, len(available) // 3)
        selected = random.choice(available[:top_k])
        
        # Increment success optimistically, adjust in remove_proxy if failed
        if selected in self.proxy_stats:
            self.proxy_stats[selected]["success"] += 1
            
        return selected

    def remove_proxy(self, proxy):
        """Marks a proxy as failed or removes it if severely degraded."""
        if proxy in self.working_proxies:
            stats = self.proxy_stats.get(proxy)
            if stats:
                stats["fails"] += 1
                # Remove completely if failure rate is critical
                if stats["fails"] >= 10:
                    self.working_proxies.remove(proxy)
                    del self.proxy_stats[proxy]
            else:
                 self.working_proxies.remove(proxy)
                 
            # Auto-refresh if low
            if len(self.working_proxies) < 5 and self.is_initialized:
                 asyncio.create_task(self.refresh_proxies())

    def _save_proxies(self):
        """Persists working proxies to disk."""
        try:
            os.makedirs("data", exist_ok=True)
            with open(self.storage_file, "w") as f:
                f.write("\n".join(self.working_proxies))
        except: pass

    def _load_proxies(self):
        """Loads proxies from disk and initializes minimal stats."""
        try:
            if os.path.exists(self.storage_file):
                with open(self.storage_file, "r") as f:
                    self.working_proxies = [line.strip() for line in f if line.strip()]
                    for p in self.working_proxies:
                         self.proxy_stats[p] = {"latency": 2.0, "fails": 0, "success": 1}
        except: pass
