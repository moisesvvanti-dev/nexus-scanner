import asyncio
import re
import socket
from urllib.parse import urlparse, urljoin
import aiohttp
from bs4 import BeautifulSoup
import dns.resolver
from PySide6.QtCore import QThread, Signal

class NetworkAnalyzerCore(QThread):
    status_update = Signal(str)
    route_found = Signal(str)
    url_found = Signal(str)
    vulnerability_found = Signal(str)
    finished = Signal()
    
    def __init__(self, target_url):
        super().__init__()
        self.target_url = target_url
        self.running = False
        self.routes = set()
        self.urls = set()
        self.vulnerabilities = set()
        
    def run(self):
        self.running = True
        try:
            self.status_update.emit("Starting comprehensive network analysis...")
            asyncio.run(self._analyze_network())
        except Exception as e:
            self.status_update.emit(f"Analysis error: {str(e)}")
        finally:
            self.running = False
            self.finished.emit()
    
    async def _analyze_network(self):
        # Get all resources
        await self._get_resources(self.target_url)
        
        # Analyze DNS records
        if self.running:
            await self._analyze_dns()
        
        # Check for CORS misconfigurations
        if self.running:
            await self._check_cors()
        
        # Check for open ports
        if self.running:
            await self._check_open_ports()
        
        # Report findings
        self.status_update.emit(f"Network analysis complete. Found {len(self.routes)} routes and {len(self.urls)} URLs")
        
        if self.vulnerabilities:
            self.status_update.emit(f"Vulnerabilities found: {', '.join(self.vulnerabilities)}")
    
    async def _get_resources(self, url):
        """Get all resources from the target URL"""
        try:
            # Fix URL prefix if missing
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url

            # Get HTML content
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(url, timeout=10) as response:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    # Extract all URLs from HTML
                    for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe']):
                        if 'href' in tag.attrs:
                            self.urls.add(tag['href'])
                            self.url_found.emit(tag['href'])
                        if 'src' in tag.attrs:
                            self.urls.add(tag['src'])
                            self.url_found.emit(tag['src'])
                    
                    # Extract JavaScript URLs
                    js_pattern = re.compile(r'https?://[^\'"\)]+')
                    js_matches = js_pattern.findall(html)
                    for js_match in js_matches:
                        self.urls.add(js_match)
                        self.url_found.emit(js_match)
                    
                    # Extract WebSocket connections
                    ws_pattern = re.compile(r'wss?://[^\'"\)]+')
                    ws_matches = ws_pattern.findall(html)
                    for ws_match in ws_matches:
                        self.urls.add(ws_match)
                        self.url_found.emit(ws_match)
                    
                    # Extract API endpoints
                    api_pattern = re.compile(r'/api/[^\'"\)]+')
                    api_matches = api_pattern.findall(html)
                    for api_match in api_matches:
                        self.routes.add(api_match)
                        self.route_found.emit(api_match)
                    
                    # Extract GraphQL endpoints
                    graphql_pattern = re.compile(r'/graphql')
                    graphql_matches = graphql_pattern.findall(html)
                    for graphql_match in graphql_matches:
                        self.routes.add(graphql_match)
                        self.route_found.emit(graphql_match)
                    
                    # Extract REST endpoints
                    rest_pattern = re.compile(r'/rest/[^\'"\)]+')
                    rest_matches = rest_pattern.findall(html)
                    for rest_match in rest_matches:
                        self.routes.add(rest_match)
                        self.route_found.emit(rest_match)
        except Exception as e:
            self.status_update.emit(f"Error analyzing resources: {str(e)}")
    
    async def _analyze_dns(self):
        """Analyze DNS records for the target domain"""
        try:
            domain = urlparse(self.target_url).netloc
            if not domain:
                domain = self.target_url.replace("https://", "").replace("http://", "").split("/")[0]

            self.status_update.emit(f"Analyzing DNS for: {domain}")
            
            try:
                dns_records = dns.resolver.resolve(domain, 'A')
                for record in dns_records:
                    self.status_update.emit(f"DNS record: {record.address}")
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                pass

            # Check for subdomains
            subdomain_pattern = re.compile(r'^([a-zA-Z0-9-]+)\.' + domain + '$')
            # This logic basically assumes finding subdomains out of the parsed domain list (often small).
            # A dictionary brute would be better, but we are copying existing feature.
            subdomain_matches = subdomain_pattern.findall(domain)
            for subdomain in subdomain_matches:
                url = f"https://{subdomain}.{domain}"
                self.urls.add(url)
                self.url_found.emit(url)
        except Exception as e:
            self.status_update.emit(f"DNS analysis error: {str(e)}")
    
    async def _check_cors(self):
        """Check for CORS misconfigurations"""
        try:
            cors_domains = [
                "*.example.com",
                "*.test.com",
                "*.dev.com",
                "*.local",
                "*.localhost"
            ]
            
            for domain in cors_domains:
                if not self.running: break
                test_url = f"https://{domain}"
                connector = aiohttp.TCPConnector(ssl=False)
                try:
                    async with aiohttp.ClientSession(connector=connector) as session:
                        # Adding Origin header to check CORS response
                        headers = {'Origin': test_url}
                        async with session.options(self.target_url, headers=headers, timeout=5) as response:
                            if 'access-control-allow-origin' in response.headers:
                                origin = response.headers['access-control-allow-origin']
                                if origin == '*' or origin == test_url:
                                    vuln = f"CORS misconfiguration allowing: {origin}"
                                    self.vulnerabilities.add(vuln)
                                    self.vulnerability_found.emit(vuln)
                except:
                    pass
        except Exception as e:
            self.status_update.emit(f"CORS check error: {str(e)}")
    
    async def _check_open_ports(self):
        """Check for open ports on the target domain"""
        try:
            domain = urlparse(self.target_url).netloc
            if not domain:
                domain = self.target_url.replace("https://", "").replace("http://", "").split("/")[0]

            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 8080, 8443]
            
            for port in common_ports:
                if not self.running: break
                try:
                    # Async port knock logic instead of aiohttp to pure ports (which fails for SSH e.g.)
                    fut = asyncio.open_connection(domain, port)
                    reader, writer = await asyncio.wait_for(fut, timeout=1.5)
                    self.status_update.emit(f"Open port found: {port}")
                    self.vulnerability_found.emit(f"Open Port Detect: {port}")
                    writer.close()
                    await writer.wait_closed()
                except:
                    pass
        except Exception as e:
            self.status_update.emit(f"Port check error: {str(e)}")
