
import asyncio
import aiohttp
import aiofiles
import os
import re
from urllib.parse import urlparse, urljoin, unquote, urlsplit
from bs4 import BeautifulSoup
from PySide6.QtCore import QObject, Signal
import mimetypes

class AsyncDownloader(QObject):
    log_message = Signal(str)
    progress_updated = Signal(int)
    finished = Signal()

    def __init__(self, start_url, output_dir, depth=1, concurrency=10):
        super().__init__()
        self.start_url = start_url
        self.output_dir = output_dir
        self.max_depth = int(depth)
        self.concurrency = int(concurrency)
        
        self.visited = set()
        self.queue = asyncio.Queue()
        self.session = None
        self.domain = urlparse(start_url).netloc
        self.is_running = False
        
        # Stats
        self.downloaded_count = 0
        self.failed_count = 0
        self.total_queued = 0

    async def start_download(self):
        self.is_running = True
        self.log_message.emit(f"<span style='color:#00f3ff'>[*] Starting Download: {self.start_url} (Depth: {self.max_depth})</span>")
        
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Relaxed limits for downloading assets
        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=False, ttl_dns_cache=300)
        timeout = aiohttp.ClientTimeout(total=60, connect=20, sock_read=30)
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36'
        }

        async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
            self.session = session
            
            # Start with the main URL
            await self.queue.put((self.start_url, 0))
            self.visited.add(self.start_url)
            self.total_queued += 1
            
            workers = [asyncio.create_task(self._worker()) for _ in range(self.concurrency)]
            
            # Wait until queue is fully processed
            await self.queue.join()
            
            for w in workers:
                w.cancel()
                
        self.log_message.emit(f"<span style='color:#00ff9d'>[+] Download Complete! Saved to {self.output_dir}</span>")
        self.finished.emit()

    async def stop(self):
        self.is_running = False
        self.log_message.emit("<span style='color:#ff0055'>[!] Download Aborted by User.</span>")

    async def _worker(self):
        while True:
            try:
                url, depth = await self.queue.get()
                if not self.is_running:
                    self.queue.task_done()
                    continue
                    
                await self._process_url(url, depth)
                self.queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.log_message.emit(f"<span style='color:#ff5555'>[Worker Error] {str(e)}</span>")
                try:
                    self.queue.task_done()
                except ValueError:
                    pass

    async def _process_url(self, url, depth):
        if not self.is_running: return

        try:
            # Determine filename
            rel_path, filename = self._get_path_info(url)
            filepath = os.path.join(self.output_dir, rel_path)
            
            # Create subdirs
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            # Skip if already exists (resume capability basic)
            if os.path.exists(filepath):
                self.downloaded_count += 1
                return

            retry_count = 3
            for attempt in range(retry_count):
                try:
                    async with self.session.get(url) as response:
                        if response.status == 200:
                            content = await response.read()
                            content_type = response.headers.get('Content-Type', '').lower()
                            
                            if 'text/html' in content_type:
                                # Process HTML: Rewrite links + Find assets
                                try:
                                    text_content = content.decode('utf-8', errors='ignore')
                                    new_content = await self._parse_html(url, text_content, depth)
                                    async with aiofiles.open(filepath, mode='wb') as f:
                                        await f.write(new_content.encode('utf-8'))
                                except Exception as parse_error:
                                     # Fallback to raw save if parsing fails
                                     async with aiofiles.open(filepath, mode='wb') as f:
                                        await f.write(content)

                            else:
                                # Binary/Asset
                                async with aiofiles.open(filepath, mode='wb') as f:
                                    await f.write(content)
                                    
                            self.downloaded_count += 1
                            if self.downloaded_count % 5 == 0:
                                self.progress_updated.emit(self.downloaded_count)
                            break # Success
                        else:
                            if attempt == retry_count - 1:
                                self.failed_count += 1
                                self.log_message.emit(f"<span style='color:#ff5555'>[Fail] {response.status} - {url}</span>")
                            
                except Exception:
                    if attempt == retry_count - 1:
                        self.failed_count += 1
                    await asyncio.sleep(1)

        except Exception as e:
            self.failed_count += 1
            # self.log_message.emit(f"<span style='color:#ff5555'>[Error] {url}: {str(e)}</span>")

    async def _parse_html(self, base_url, content, depth):
        soup = BeautifulSoup(content, 'html.parser') # lxml is faster if available
        
        tags = {
            'a': 'href',
            'link': 'href',
            'script': 'src',
            'img': 'src',
            'source': 'src',
            'video': 'src',
            'iframe': 'src'
        }
        
        for tag_name, attr in tags.items():
            for tag in soup.find_all(tag_name):
                link = tag.get(attr)
                if not link or link.startswith('#') or link.startswith('javascript:'): 
                    continue
                
                full_url = urljoin(base_url, link)
                parsed = urlparse(full_url)
                
                # Filter: Internal Domain Only
                if parsed.netloc == self.domain or not parsed.netloc:
                    
                    # Decouple asset check
                    is_asset = tag_name in ['img', 'script', 'link', 'source', 'video']
                    
                    if full_url not in self.visited:
                        # Logic: Always download assets. Only follow links if depth allows.
                        if is_asset or depth < self.max_depth:
                            self.visited.add(full_url)
                            await self.queue.put((full_url, depth + 1 if not is_asset else depth))
                            self.total_queued += 1
                    
                    # REWRITE LINK to relative local path
                    rel_link = self._compute_relative_link(base_url, full_url)
                    tag[attr] = rel_link
                
        return str(soup)

    def _get_path_info(self, url):
        """Converts URL to a safe local file path structure."""
        parsed = urlparse(url)
        path = unquote(parsed.path)
        
        if not path or path == '/':
            path = '/index.html'
        elif path.endswith('/'):
            path += 'index.html'
            
        # If no extension, assume html
        if not os.path.splitext(path)[1]:
            path += '/index.html'
            
        # Remove leading slash
        path = path.lstrip('/')
        
        return path, os.path.basename(path)

    def _compute_relative_link(self, source_url, target_url):
        source_path, _ = self._get_path_info(source_url)
        target_path, _ = self._get_path_info(target_url)
        
        source_dir = os.path.dirname(source_path)
        
        # Calculate relative path
        try:
            rel_path = os.path.relpath(target_path, source_dir)
            return rel_path.replace(os.sep, '/') 
        except ValueError:
            return target_url
