import aiohttp
import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs

class WebCrawler:
    def __init__(self, start_url):
        self.start_url = start_url
        self.visited = set()
        self.params_found = [] # List of URLs with parameters
        self.login_pages = set() # Store pages with password inputs
        self.assets = set() # Store JS, CSS, JSON files

    async def crawl(self, session, depth=2):
        """Crawls the website to find parameters for fuzzing."""
        # 1. Parse Robots.txt
        await self._parse_robots(session)
        # 2. Parse Sitemap.xml
        await self._parse_sitemap(session)
        
        to_visit = [(self.start_url, 0)]
        domain = urlparse(self.start_url).netloc

        while to_visit:
            url, current_depth = to_visit.pop(0)
            if url in self.visited or current_depth > depth:
                continue
            
            self.visited.add(url)
            
            try:
                async with session.get(url, timeout=5) as response:
                    if response.status == 200:
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        
                        # Extract links
                        for link in soup.find_all('a', href=True):
                            full_url = urljoin(url, link['href'])
                            parsed = urlparse(full_url)
                            
                            # Only crawl same domain
                            if parsed.netloc == domain:
                                if full_url not in self.visited:
                                    to_visit.append((full_url, current_depth + 1))
                                
                                # Check for parameters
                                    self.params_found.append(full_url)
                                    
                                    # PRIORITIZE ELEMENTOR (Targeted Recon)
                                    if "elementor" in full_url.lower():
                                         self.params_found.insert(0, full_url) # Move to front of queue
                        
                        # Extract ASSETS (Scripts, CSS)
                        # Scripts
                        for script in soup.find_all('script', src=True):
                             asset_url = urljoin(url, script['src'])
                             if urlparse(asset_url).netloc == domain: # Keep it local-ish or allow CDN? 
                                  # Secrets can be in main domain JS. Cloud keys often in app.js
                                  self.assets.add(asset_url)

                        # CSS / JSON / Other links
                        for link in soup.find_all('link', href=True):
                             # Stylesheets or preloads
                             asset_url = urljoin(url, link['href'])
                             if urlparse(asset_url).netloc == domain:
                                  self.assets.add(asset_url)
                        
                        # Extract forms (often hidden attack surface)
                        for form in soup.find_all('form', action=True):
                            action = urljoin(url, form['action'])
                            self.params_found.append(action) # Treat action as fuzz target
                            
                            # Extract inputs to build a better fuzzing list (optional, can be expanded)
                            inputs = form.find_all(['input', 'textarea', 'select'])
                            input_names = [i.get('name') for i in inputs if i.get('name')]
                            
                            # Check for Password Fields
                            has_password = any(i.get('type') == 'password' for i in inputs)
                            if has_password:
                                self.login_pages.add(action)
                                self.login_pages.add(url) # Also add the page hosting the form

                            if input_names and '?' not in action:
                                # Construct a dummy GET request for fuzzing if it's a GET form or we want to force it
                                query = "&".join([f"{name}=FUZZ" for name in input_names])
                                self.params_found.append(f"{action}?{query}")

            except:
                pass
        
        return list(set(self.params_found))

    async def _parse_robots(self, session):
        try:
            robots_url = urljoin(self.start_url, "/robots.txt")
            async with session.get(robots_url, timeout=5) as response:
                if response.status == 200:
                    content = await response.text()
                    for line in content.splitlines():
                        if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                            path = line.split(":", 1)[1].strip()
                            if path and "/" in path:
                                if "*" in path: continue # Skip templates
                                full_url = urljoin(self.start_url, path)
                                self.params_found.append(full_url)
        except:
            pass

    async def _parse_sitemap(self, session):
        try:
            sitemap_url = urljoin(self.start_url, "/sitemap.xml")
            async with session.get(sitemap_url, timeout=5) as response:
                if response.status == 200:
                    content = await response.text()
                    soup = BeautifulSoup(content, 'xml')
                    for loc in soup.find_all('loc'):
                        self.params_found.append(loc.text.strip())
        except:
            pass
