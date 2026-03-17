import sys
import asyncio
import re
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QPushButton, 
    QTextEdit, QProgressBar, QLabel, QHBoxLayout, QMessageBox, QFileDialog, QCheckBox,
    QStackedWidget, QFrame, QSizePolicy, QLineEdit, QApplication, QGraphicsDropShadowEffect,
    QComboBox, QInputDialog
)
from PySide6.QtCore import Slot, Qt, QSize, QTimer
from PySide6.QtGui import QIcon, QAction, QColor

try:
    from .styles import MAIN_STYLE, LOG_STYLE
    from .widgets import (
        ResultsTable, DashboardStats, GlowButton, 
        FundsWidget, SensitiveDataWidget, ProxyWidget, PayloadsWidget, ScriptLabWidget, AMSIWidget,
        MarauderWidget
    )
    from core.scanner import NexusScanner
    from core.reporter import ReportGenerator
    from core.integrations import SupabaseHandler
    from core.firebase_reporter import FirebaseReporter
    from .downloader import DownloaderWidget
    from .dork_widget import DorkWidget
    from .network_widget import NetworkAnalyzerWidget
    from .supabase_widget import SupabaseWidget
    from .mirror_widget import MirrorWidget
    from .sqlmap_widget import SqlMapWidget
    from .port_scan_widget import PortScanWidget
    from .xss_scan_widget import XssScanWidget
    # from .ddos_widget import MHDDoSWidget # Lazy loaded
except ImportError:
    from gui.styles import MAIN_STYLE, LOG_STYLE
    from gui.widgets import (
        ResultsTable, DashboardStats, GlowButton, 
        FundsWidget, SensitiveDataWidget, ProxyWidget, PayloadsWidget, ScriptLabWidget, AMSIWidget,
        MarauderWidget
    )
    from core.scanner import NexusScanner
    from core.reporter import ReportGenerator
    from core.integrations import SupabaseHandler
    from core.firebase_reporter import FirebaseReporter
    from gui.downloader import DownloaderWidget # Import Downloader
    from gui.dork_widget import DorkWidget
    from gui.network_widget import NetworkAnalyzerWidget
    from gui.supabase_widget import SupabaseWidget
    from gui.mirror_widget import MirrorWidget
    from gui.sqlmap_widget import SqlMapWidget
    from gui.port_scan_widget import PortScanWidget
    from gui.xss_scan_widget import XssScanWidget
    # from gui.ddos_widget import MHDDoSWidget # Lazy loaded

class MainWindow(QMainWindow):
    def __init__(self, targets):
        super().__init__()
        self.targets = targets 
        self.scanner = None
        self.all_findings = []
        self.governor_backend_process = None
        
        # Initialize Firebase Reporter later when needed (Settings based)
        self.firebase = None
        self.scan_timer = QTimer(self)
        self.scan_elapsed = 0
        self.scan_timer.timeout.connect(self._update_timer)

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("NEXUS CYBER-OFFENSIVE SUITE v21.0 - ULTIMATE")
        self.resize(1400, 900)
        self.setStyleSheet(MAIN_STYLE)

        # Main Layout (Sidebar + Content)
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QHBoxLayout(main_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)

        # --- SIDEBAR ---
        self.sidebar = QWidget()
        self.sidebar.setObjectName("Sidebar")
        self.sidebar.setFixedWidth(250)
        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(0, 10, 0, 10)
        sidebar_layout.setSpacing(5)

        # Header in Sidebar
        header = QLabel("NEXUS")
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("font-family: 'Outfit', sans-serif; font-size: 26pt; font-weight: 800; color: #FFFFFF; margin-bottom: 10px;")
        sidebar_layout.addWidget(header)
        sidebar_layout.addSpacing(10)

        # Navigation Buttons
        self.btn_nav_dashboard = self.create_nav_button("○ Overview", 0)
        self.btn_nav_scan = self.create_nav_button("⊞ Scanner", 1)
        self.btn_nav_payloads = self.create_nav_button("◈ Payloads", 2)
        self.btn_nav_scriptlab = self.create_nav_button("⚡ Script Lab", 3)
        self.btn_nav_tools = self.create_nav_button("⚒ Tools", 4)
        self.btn_nav_marauder = self.create_nav_button("☠ Marauder", 16) # New dedicated tab
        self.btn_nav_converter = self.create_nav_button("⇄ Converter", 5)
        self.btn_nav_downloader = self.create_nav_button("⬇ Downloader", 6)
        self.btn_nav_dorks = self.create_nav_button("🔍 Dorks", 7)
        self.btn_nav_ddos = self.create_nav_button("🔥 Attack", 8)
        self.btn_nav_network = self.create_nav_button("🌐 Network", 9)
        self.btn_nav_supabase = self.create_nav_button("◆ Supabase", 10)
        self.btn_nav_mirror = self.create_nav_button("🪞 Mirror", 11)
        self.btn_nav_sqlmap = self.create_nav_button("💉 SQLMap", 12)
        self.btn_nav_portscan = self.create_nav_button("⚒ Port Scan", 13)
        self.btn_nav_xssscan = self.create_nav_button("💉 XSS Scan", 14)
        
        sidebar_layout.addWidget(self.btn_nav_dashboard)
        sidebar_layout.addWidget(self.btn_nav_scan)
        sidebar_layout.addWidget(self.btn_nav_payloads)
        sidebar_layout.addWidget(self.btn_nav_scriptlab)
        sidebar_layout.addWidget(self.btn_nav_tools)
        sidebar_layout.addWidget(self.btn_nav_marauder)
        sidebar_layout.addWidget(self.btn_nav_converter)
        sidebar_layout.addWidget(self.btn_nav_downloader)
        sidebar_layout.addWidget(self.btn_nav_dorks)
        sidebar_layout.addWidget(self.btn_nav_ddos)
        sidebar_layout.addWidget(self.btn_nav_network)
        sidebar_layout.addWidget(self.btn_nav_supabase)
        sidebar_layout.addWidget(self.btn_nav_mirror)
        sidebar_layout.addWidget(self.btn_nav_sqlmap)
        sidebar_layout.addWidget(self.btn_nav_portscan)
        sidebar_layout.addWidget(self.btn_nav_xssscan)
        # Settings at bottom
        sidebar_layout.addStretch()
        self.btn_settings = self.create_nav_button("⚙ Settings", 15)
        sidebar_layout.addWidget(self.btn_settings)

        # Version Info
        version = QLabel("v22.0  │  GOVERNOR EDITION")
        version.setAlignment(Qt.AlignCenter)
        version.setStyleSheet("color: rgba(255, 255, 255, 0.2); font-size: 8pt; margin-top: 10px;")
        sidebar_layout.addWidget(version)

        main_layout.addWidget(self.sidebar)

        # --- CONTENT AREA ---
        self.content_stack = QStackedWidget()
        main_layout.addWidget(self.content_stack)

        # Page 0: Dashboard
        self.page_dashboard = self.create_dashboard_page()
        self.content_stack.addWidget(self.page_dashboard)

        # Page 1: Scanner (Detailed)
        self.page_scan = self.create_scan_page()
        self.content_stack.addWidget(self.page_scan)
        
        # Page 2: Payloads
        self.page_payloads = self.create_payloads_page()
        self.content_stack.addWidget(self.page_payloads)

        # Page 3: Script Lab
        self.page_scriptlab = self.create_scriptlab_page()
        self.content_stack.addWidget(self.page_scriptlab)

        # Page 4: Tools
        self.page_tools = self.create_tools_page()
        self.content_stack.addWidget(self.page_tools)

        # Page 5: Converter
        self.page_converter = self.create_converter_page()
        self.content_stack.addWidget(self.page_converter)

        # Page 6: Downloader
        self.page_downloader = self.create_downloader_page()
        self.content_stack.addWidget(self.page_downloader)

        # Page 7: Dorks
        self.page_dorks = self.create_dork_page()
        self.content_stack.addWidget(self.page_dorks)

        # Page 8: MHDDoS
        self.page_ddos = self.create_ddos_page()
        self.content_stack.addWidget(self.page_ddos)
        
        # Page 9: Network Analyzer
        self.page_network = self.create_network_page()
        self.content_stack.addWidget(self.page_network)
        
        # Page 10: Supabase Exploitation
        self.page_supabase = self.create_supabase_page()
        self.content_stack.addWidget(self.page_supabase)
        
        # Page 11: Mirror Proxy
        self.page_mirror = self.create_mirror_page()
        self.content_stack.addWidget(self.page_mirror)

        # Page 12: SQLMap
        self.page_sqlmap = self.create_sqlmap_page()
        self.content_stack.addWidget(self.page_sqlmap)
        
        # Page 13: Port Scan
        self.page_portscan = self.create_portscan_page()
        self.content_stack.addWidget(self.page_portscan)
        
        # Page 14: XSS Scan
        self.page_xssscan = self.create_xssscan_page()
        self.content_stack.addWidget(self.page_xssscan)
        
        # Page 15: Settings
        self.page_settings = self.create_settings_page()
        self.content_stack.addWidget(self.page_settings)
        
        # Page 16: Marauder (Dedicated)
        self.page_marauder = MarauderWidget()
        self.content_stack.addWidget(self.page_marauder)
        
        # Default Page
        self.btn_nav_dashboard.setChecked(True)

    def create_nav_button(self, text, index):
        btn = QPushButton(text)
        btn.setObjectName("SidebarButton")
        btn.setCheckable(True)
        btn.setAutoExclusive(True)
        btn.setMinimumHeight(38)
        # Fix lambda signal issue by accepting the checked arg (lambda x: ...)
        btn.clicked.connect(lambda _, idx=index: self.switch_page(idx))
        return btn

    def switch_page(self, index):
        self.content_stack.setCurrentIndex(index)
        # Auto-configure Script Lab and Dorks AI when navigating to them
        if index in [3, 7] and hasattr(self, 'txt_ai_key'):
            api_key = self.txt_ai_key.text().strip()
            model = self.combo_ai_model.currentText()
            if api_key:
                from core.ai_assistant import AIAssistant
                ai = AIAssistant(api_key, model)
                if index == 3 and hasattr(self, 'scriptlab_widget') and not self.scriptlab_widget.ai_assistant:
                    self.scriptlab_widget.set_ai_assistant(ai)
                if index == 7 and hasattr(self, 'dorks_widget') and not self.dorks_widget.ai_assistant:
                    self.dorks_widget.set_ai_assistant(ai)
                    self.dorks_widget.set_target(self.txt_target.toPlainText().strip())

    def create_dashboard_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        
        # 3. Widgets Layout
        widgets_layout = QHBoxLayout()
        widgets_layout.setSpacing(15)

        self.stats = DashboardStats()
        self.apply_glow_effect(self.stats, QColor(0, 243, 255, 60))
        
        self.funds = FundsWidget()
        self.apply_glow_effect(self.funds, QColor(0, 255, 157, 40))
        # Header area
        header_layout = QHBoxLayout()
        title = QLabel("NEXUS CYBER-OFFENSIVE SUITE")
        title.setStyleSheet("font-size: 24pt; font-weight: bold; color: #FFFFFF;")
        
        header_layout.addWidget(title)
        
        # Profile Combo inside Header
        combo_layout = QHBoxLayout()
        lbl_profile = QLabel("SCAN PROFILE:")
        lbl_profile.setStyleSheet("color: #00f3ff; font-weight: bold; font-size: 10pt;")
        self.combo_profile = QComboBox()
        self.combo_profile.addItems(["Quick Recon", "Standard Audit", "Deep Pentest", "Stealth Mode", "Governor Mode (Ultra Stealth)", "Nexus Marauder (Auto-Purchase)"])
        self.combo_profile.currentIndexChanged.connect(self.on_profile_changed)
        
        combo_layout.addWidget(lbl_profile)
        combo_layout.addWidget(self.combo_profile)
        combo_layout.addStretch()
        header_layout.addLayout(combo_layout)
        
        layout.addLayout(header_layout)
        
        # Stats Row
        stats_row = QHBoxLayout()
        self.stats = DashboardStats()
        stats_row.addWidget(self.stats, stretch=3)
        self.funds = FundsWidget()
        stats_row.addWidget(self.funds, stretch=1)
        layout.addLayout(stats_row)
        
        # Action Row
        action_row = QHBoxLayout()
        
        # Target Input Multi-line
        self.txt_target = QTextEdit()
        self.txt_target.setPlaceholderText("Enter target domain or IP (e.g. target.com)\nSeparate multiple targets by newline...")
        self.txt_target.setMaximumHeight(80)
        action_row.addWidget(self.txt_target, stretch=2)
        
        self.btn_start = QPushButton("▶ INITIATE ATTACK SEQUENCE")
        self.btn_start.setObjectName("ActionRed")
        self.btn_start.setMinimumHeight(50)
        self.btn_start.clicked.connect(self.start_scan)
        
        self.btn_stop = QPushButton("⏹ ABORT")
        self.btn_stop.setEnabled(False)
        self.btn_stop.setMinimumHeight(50)
        self.btn_stop.clicked.connect(self.stop_scan)
        
        action_row.addWidget(self.btn_start, stretch=1)
        action_row.addWidget(self.btn_stop)
        
        layout.addLayout(action_row)
        
        # Checkboxes
        chk_layout = QHBoxLayout()
        self.chk_deep = QCheckBox("DEEP_SCAN_PROTOCOL (Crawl depth 5)")
        self.chk_deep.setStyleSheet("color: #ffcc00;")
        self.chk_headless = QCheckBox("HEADLESS_MODE (JS Render)")
        self.chk_headless.setStyleSheet("color: #00f3ff;")
        self.chk_headless.setChecked(True)
        self.chk_proxychains = QCheckBox("PROXYCHAINS (Tor/SOCKS)")
        self.chk_proxychains.setStyleSheet("color: #ff0055;")
        
        chk_layout.addWidget(self.chk_deep)
        chk_layout.addWidget(self.chk_headless)
        chk_layout.addWidget(self.chk_proxychains)
        chk_layout.addStretch()
        layout.addLayout(chk_layout)
        
        # Progress Bar & Timer
        prog_layout = QVBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("SYSTEM IDLE 0%")
        prog_layout.addWidget(self.progress_bar)
        
        # Add a label for elapsed time
        self.lbl_elapsed = QLabel("Elapsed: 00:00")
        self.lbl_elapsed.setStyleSheet("color: #aaa; font-size: 9pt;")
        self.lbl_elapsed.setAlignment(Qt.AlignRight)
        prog_layout.addWidget(self.lbl_elapsed)
        
        layout.addLayout(prog_layout)
        
        # Log Console
        self.log_console = QTextEdit()
        self.log_console.setReadOnly(True)
        self.log_console.setObjectName("LogConsole")
        
        # Apply strict CSS internally for terminal feel
        self.log_console.setStyleSheet("""
            QTextEdit {
                background-color: rgba(10, 10, 15, 0.9);
                color: #c8ffd4;
                border: 1px solid rgba(0, 255, 157, 0.2);
                border-radius: 8px;
                font-family: 'Consolas', monospace;
                font-size: 9pt;
                padding: 10px;
            }
        """)
        
        layout.addWidget(self.log_console)
        
        # Bottom action bar
        actions = QHBoxLayout()
        btn_clear = GlowButton("CLEAR LOGS", "#666")
        btn_clear.clicked.connect(lambda: self.log_console.clear())
        btn_export = GlowButton("⬇ EXPORT REPORT", "#00f3ff")
        btn_export.clicked.connect(self.export_report)
        
        actions.addWidget(btn_clear)
        actions.addStretch()
        actions.addWidget(btn_export)
        layout.addLayout(actions)
        
        # 4. Results Table
        self.results_table = ResultsTable()
        self.apply_glow_effect(self.results_table, QColor(0, 243, 255, 30))
        layout.addWidget(self.results_table)
        
        return page

    def create_scan_page(self):
        # Currently the scan relies on dashboard for initialization
        # but provides proxy/settings here.
        page = QWidget()
        layout = QHBoxLayout(page)
        
        # Proxy Widget
        self.proxy_widget = ProxyWidget()
        self.apply_glow_effect(self.proxy_widget, QColor(255, 0, 85, 40))
        
        # Sensitive Data Widget
        self.sensitive_widget = SensitiveDataWidget()
        self.apply_glow_effect(self.sensitive_widget, QColor(0, 243, 255, 40))
        
        layout.addWidget(self.proxy_widget)
        layout.addWidget(self.sensitive_widget)
        
        return page

    def create_payloads_page(self):
        self.payloads_widget = PayloadsWidget()
        return self.payloads_widget

    def on_profile_changed(self, index):
        profile = self.combo_profile.currentText()
        try:
            if profile == "Quick Recon":
                self.chk_deep.setChecked(False)
                self.proxy_widget.chk_bypass.setChecked(False)
                self.chk_proxychains.setChecked(False)
            elif profile == "Standard Audit":
                self.chk_deep.setChecked(True)
                self.proxy_widget.chk_bypass.setChecked(True)
                self.chk_proxychains.setChecked(False)
            elif profile == "Deep Pentest":
                self.chk_deep.setChecked(True)
                self.proxy_widget.chk_bypass.setChecked(True)
                self.chk_proxychains.setChecked(False)
            elif profile == "Stealth Mode":
                self.chk_deep.setChecked(True)
                self.proxy_widget.chk_bypass.setChecked(True)
                self.chk_proxychains.setChecked(True)
            elif profile == "Governor Mode (Ultra Stealth)":
                self.chk_deep.setChecked(True)
                self.proxy_widget.chk_bypass.setChecked(True)
                self.chk_proxychains.setChecked(True)
                if hasattr(self, 'chk_headless'): self.chk_headless.setChecked(True)
                if hasattr(self.proxy_widget, 'chk_strict'): self.proxy_widget.chk_strict.setChecked(False)  # More aggressive
                if hasattr(self.proxy_widget, 'chk_timeout'): self.proxy_widget.chk_timeout.setChecked(True)
                if hasattr(self.proxy_widget, 'chk_req_smuggle'): self.proxy_widget.chk_req_smuggle.setChecked(True)
                if hasattr(self.proxy_widget, 'chk_403_bypass'): self.proxy_widget.chk_403_bypass.setChecked(True)
                if hasattr(self.proxy_widget, 'chk_header_rot'): self.proxy_widget.chk_header_rot.setChecked(True)
                if hasattr(self.proxy_widget, 'chk_auto_tune'): self.proxy_widget.chk_auto_tune.setChecked(True)
            elif profile == "Nexus Marauder (Auto-Purchase)":
                self.chk_deep.setChecked(True)
                self.proxy_widget.chk_bypass.setChecked(True)
                self.chk_proxychains.setChecked(False)
                if hasattr(self, 'chk_headless'): self.chk_headless.setChecked(False)  # MUST be non-headless
                QMessageBox.information(self, "Marauder Mode", "Nexus Marauder engaged. A visible browser will launch to automate inventory depletion and checkout.")
        except AttributeError:
            pass # Widget not loaded yet

    @Slot()
    def start_marauder(self):
        """Launches the automated purchase sequence."""
        target = self.txt_target.toPlainText().strip()
        if not target:
            QMessageBox.warning(self, "Target Missing", "Please enter a target URL for Marauder Mode.")
            return

        # Simple login picker (could be in settings)
        user, ok1 = QInputDialog.getText(self, "Marauder Auth", "Enter Login/User:")
        pwd, ok2 = QInputDialog.getText(self, "Marauder Auth", "Enter Password:", QLineEdit.Password)
        
        if not (ok1 and ok2): return

        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        
        from core.browser_scanner import BrowserScanner
        self.browser_scanner = BrowserScanner(target, headless=False)
        self.browser_scanner.log_message.connect(self._log_terminal)
        
        asyncio.ensure_future(self.browser_scanner.run_marauder_sequence(target, user, pwd))

    @Slot()
    def _update_timer(self):
        self.scan_elapsed += 1
        mins, secs = divmod(self.scan_elapsed, 60)
        self.progress_bar.setFormat(f"SCANNING IN PROGRESS... %p% | Elapsed: {mins:02d}:{secs:02d}")

    def change_language(self, language):
        """Translates basic UI controls based on language selected."""
        trans_map = {
            "Português (Brasil)": {
                "INITIALIZE SCAN": "INICIAR VARREDURA", "ABORT OPERATION": "CANCELAR", "COPY FINDINGS": "COPIAR RESULTADOS",
                "DASHBOARD": "PAINEL", "SCANNER": "VARREDURA", "PAYLOADS": "CARGAS (PAYLOADS)", "TOOLS / PROXY": "FERRAMENTAS"
            },
            "Español": {
                "INITIALIZE SCAN": "INICIAR ESCANEO", "ABORT OPERATION": "CANCELAR", "COPY FINDINGS": "COPIAR RESULTADOS"
            },
            "Русский (Russian)": {
                "INITIALIZE SCAN": "НАЧАТЬ СКАНИРОВАНИЕ", "ABORT OPERATION": "ОТМЕНИТЬ", "COPY FINDINGS": "КОПИРОВАТЬ РЕЗУЛЬТАТЫ"
            }
        }
        
        lang_dict = trans_map.get(language, {})
        
        # Update quick action buttons
        self.btn_start.setText(lang_dict.get("INITIALIZE SCAN", "INITIALIZE SCAN"))
        self.btn_stop.setText(lang_dict.get("ABORT OPERATION", "ABORT OPERATION"))
        self.btn_copy.setText(lang_dict.get("COPY FINDINGS", "COPY FINDINGS"))

    def create_scan_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(12)
        
        # Header row
        header_row = QHBoxLayout()
        lbl = QLabel("◉ LIVE OPERATION LOGS")
        lbl.setStyleSheet("color: #00f3ff; font-weight: bold; font-size: 11pt; letter-spacing: 2px;")
        
        self.lbl_log_count = QLabel("0 entries")
        self.lbl_log_count.setStyleSheet("color: #445; font-size: 8pt;")
        
        header_row.addWidget(lbl)
        header_row.addStretch()
        header_row.addWidget(self.lbl_log_count)
        layout.addLayout(header_row)

        self.log_console = QTextEdit()
        self.log_console.setReadOnly(True)
        self.log_console.setStyleSheet(LOG_STYLE)
        layout.addWidget(self.log_console)
        
        # Bottom action bar
        actions = QHBoxLayout()
        btn_clear = GlowButton("CLEAR LOGS", "#666")
        btn_clear.clicked.connect(lambda: self.log_console.clear())
        btn_export = GlowButton("⬇ EXPORT REPORT", "#00f3ff")
        btn_export.clicked.connect(self.export_report)
        
        actions.addWidget(btn_clear)
        actions.addStretch()
        actions.addWidget(btn_export)
        layout.addLayout(actions)
        
        return page

    def apply_glow_effect(self, widget, color):
        """Applies a smooth hardware-accelerated drop shadow glow to Qt6 Widgets."""
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(25)
        shadow.setXOffset(0)
        shadow.setYOffset(0)
        shadow.setColor(color)
        widget.setGraphicsEffect(shadow)

    def create_tools_page(self):
        page = QWidget()
        layout = QHBoxLayout(page)
        
        # We need a splitter to comfortably fit the three tool panels
        from PySide6.QtWidgets import QSplitter
        splitter = QSplitter(Qt.Horizontal)
        
        # 1. Proxy / Evasion Settings
        self.proxy_widget = ProxyWidget()
        self.apply_glow_effect(self.proxy_widget, QColor(255, 0, 85, 40))
        splitter.addWidget(self.proxy_widget)
        
        # 2. Sensitive Data Viewer
        self.sensitive_widget = SensitiveDataWidget()
        self.apply_glow_effect(self.sensitive_widget, QColor(0, 243, 255, 40))
        splitter.addWidget(self.sensitive_widget)
        
        # 3. AMSI Analyzer Widget
        self.amsi_widget = AMSIWidget()
        self.apply_glow_effect(self.amsi_widget, QColor(157, 0, 255, 40))
        splitter.addWidget(self.amsi_widget)
        
        layout.addWidget(splitter)
        return page

    def create_converter_page(self):
        # Placeholder for converter, currently unused but linked to sidebar
        page = QWidget()
        layout = QVBoxLayout(page)
        lbl = QLabel("Converter Tools - Coming Soon")
        lbl.setStyleSheet("color: #888; font-size: 14pt;")
        layout.addWidget(lbl)
        return page

    def create_scriptlab_page(self):
        self.scriptlab_widget = ScriptLabWidget()
        return self.scriptlab_widget


    def connect_signals(self):
        if self.scanner:
            self.scanner.finding_found.connect(self.on_finding_found)
            self.scanner.log_message.connect(self.on_log_message)
            self.scanner.progress_updated.connect(self.on_progress_updated)
            self.scanner.scan_finished.connect(self.on_scan_finished)
            self.scanner.stats_updated.connect(self.on_stats_updated)
            self.scanner.sensitive_data_found.connect(self.on_sensitive_data)
            self.scanner.payload_generated.connect(self.on_payload_generated)

    @Slot()
    def start_scan(self):
        # Multi-target support
        target_text = self.txt_target.toPlainText().strip()
        
        # Divert to Marauder if selected
        if self.combo_profile.currentText() == "Nexus Marauder (Auto-Purchase)":
            self.start_marauder()
            return

        # Aggressive cleanup of accidentally pasted terminal prompts / paths
        target_text = re.sub(r'^[A-Z]:\\[^\n]*>', '', target_text, flags=re.MULTILINE).strip()
        
        scan_targets = []
        if target_text:
            for t in target_text.split('\n'):
                t = t.strip()
                if t:
                    # Strip local path trails if pasted like "target.com/C:\some\path"
                    if ">main.py" in t or t.endswith(".py"):
                        t = t.split('>')[0].split('/')[-1] # fallback attempt

                    if not t.startswith("http") and not t.startswith("https"): 
                        t = "https://" + t
                    scan_targets.append({"name": "Global Target", "url": t})

        if not scan_targets and not self.targets:
             QMessageBox.warning(self, "Error", "Target URL is required for initialization.")
             return
             
        if not scan_targets and self.targets:
            target_url = self.targets[0]['url']
            if not target_url.startswith("http"): target_url = "https://" + target_url
            scan_targets.append({"name": "Global Target", "url": target_url})

        self.btn_start.setEnabled(False)
        self.txt_target.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.progress_bar.setFormat("SCANNING IN PROGRESS... 0%")
        
        self.progress_bar.setValue(0)
        self.results_table.setRowCount(0)
        self.log_console.clear()
        self.sensitive_widget.list_widget.clear()
        self.all_findings = []
        self.stats.update_stats(0, 0, 0)
        
        self.scan_elapsed = 0
        self.scan_timer.start(1000)
        
        is_deep = self.chk_deep.isChecked()
        is_bypass = self.proxy_widget.chk_bypass.isChecked()
        is_headless = self.chk_headless.isChecked()
        is_proxychains = self.chk_proxychains.isChecked()
        is_strict = self.proxy_widget.chk_strict.isChecked()
        is_dynamic_timeout = self.proxy_widget.chk_timeout.isChecked()
        is_heuristic = self.proxy_widget.chk_heuristic.isChecked()
        is_smuggle = self.proxy_widget.chk_req_smuggle.isChecked()
        is_ssl_strip = self.proxy_widget.chk_ssl_strip.isChecked()
        is_dom_invader = self.proxy_widget.chk_dom_poll.isChecked()
        
        # New Evasion toggles
        is_403_bypass = self.proxy_widget.chk_403_bypass.isChecked()
        is_header_rot = self.proxy_widget.chk_header_rot.isChecked()
        is_auto_tune = self.proxy_widget.chk_auto_tune.isChecked()
        is_governor = (self.combo_profile.currentText() == "Governor Mode (Ultra Stealth)")
        
        # Get AI Config
        ai_key = self.txt_ai_key.text().strip()
        ai_model = self.combo_ai_model.currentText()
        
        self.scanner = NexusScanner(
            scan_targets, 
            deep_scan=is_deep, 
            bypass_mode=is_bypass, 
            headless=is_headless,
            proxychains=is_proxychains,
            strict_validation=is_strict,
            dynamic_timeout=is_dynamic_timeout,
            heuristic_mining=is_heuristic,
            req_smuggle=is_smuggle,
            ssl_strip=is_ssl_strip,
            dom_polling=is_dom_invader,
            active_403_bypass=is_403_bypass,
            header_rotation=is_header_rot,
            auto_tune=is_auto_tune,
            ai_key=ai_key,
            ai_model=ai_model,
            governor_mode=is_governor
        )
        self.connect_signals()

        # Also give Script Lab and Dorks access to the AI
        if ai_key:
            from core.ai_assistant import AIAssistant
            lab_ai = AIAssistant(ai_key, ai_model)
            if hasattr(self, 'scriptlab_widget'):
                self.scriptlab_widget.set_ai_assistant(lab_ai)
            if hasattr(self, 'dorks_widget'):
                self.dorks_widget.set_ai_assistant(lab_ai)
                self.dorks_widget.set_target(self.txt_target.toPlainText().strip())
        
        asyncio.ensure_future(self.scanner.run_scan())

    @Slot()
    def stop_scan(self):
        if self.scanner: self.scanner.stop_scan()
        if self.scan_timer.isActive(): self.scan_timer.stop()
        self.reset_controls()
        self.progress_bar.setFormat("ABORTED")

    def reset_controls(self):
        self.btn_start.setEnabled(True)
        self.txt_target.setEnabled(True)
        self.btn_stop.setEnabled(False)

    @Slot()
    def copy_all_findings(self):
        if not self.all_findings:
            QMessageBox.warning(self, "No Data", "No findings to copy.")
            return

        clipboard = QApplication.clipboard()
        report = "NEXUS SCANNER REPORT\n====================\n\n"
        for finding in self.all_findings:
             report += f"[{finding.severity}] {finding.vuln_type}\n"
             report += f"Target: {finding.target}\n"
             report += f"Impact: {finding.impact}\n"
             report += "-"*30 + "\n"
        
        try:
            clipboard.setText(report)
            QMessageBox.information(self, "Copied", "All findings copied to clipboard!")
        except Exception as e:
            QMessageBox.warning(self, "Clipboard Error", "Failed to access Windows Clipboard. Please try again.")

    @Slot()
    def export_report(self):
        if not self.all_findings: return
        
        file_path, filter_used = QFileDialog.getSaveFileName(
            self, 
            "Save Report", 
            "Nexus_Report.html", 
            "Interactive HTML Report (*.html);;Markdown Report (*.md)"
        )
        
        if file_path:
            generator = ReportGenerator(self.all_findings)
            
            is_governor = (self.combo_profile.currentText() == "Governor Mode (Ultra Stealth)")
            
            if file_path.endswith(".html"):
                content = generator.generate_html()
            elif is_governor or file_path.endswith("REPORT.md") or "RELATORIO" in file_path.upper():
                content = generator.generate_governor_report()
            else:
                content = generator.generate_markdown()
                
            with open(file_path, "w", encoding="utf-8") as f: 
                f.write(content)
                
            QMessageBox.information(self, "Success", f"Report saved to {file_path}")

    @Slot(object)
    def on_finding_found(self, finding):
        self.results_table.add_finding(finding)
        self.all_findings.append(finding)

    @Slot(str)
    def on_log_message(self, message):
        self.log_console.append(message)
        sb = self.log_console.verticalScrollBar()
        sb.setValue(sb.maximum())
        # Update log count
        if hasattr(self, 'lbl_log_count'):
            count = self.log_console.document().blockCount()
            self.lbl_log_count.setText(f"{count} entries")
            
        # Governor Mode Alert (Visual Highlight Flash)
        if "[Governor]" in message and "CRITICAL" in message:
            self._flash_console()

    def _flash_console(self):
        """Creates a subtle visual pulse in the console for extreme events."""
        original_style = self.log_console.styleSheet()
        flash_style = """
            QTextEdit {
                background-color: rgba(255, 0, 85, 0.4);
                color: #ffffff;
                border: 2px solid #ff0055;
            }
        """
        self.log_console.setStyleSheet(flash_style)
        # Restore after 300ms
        QTimer.singleShot(300, lambda: self.log_console.setStyleSheet(original_style))

    @Slot(str, str)
    def on_sensitive_data(self, title, content):
        self.sensitive_widget.add_data(title, content)

    @Slot(str, str)
    def on_payload_generated(self, url, script):
        if hasattr(self, 'payloads_widget'):
            self.payloads_widget.add_payload(url, script)

    @Slot(int)
    def on_progress_updated(self, value):
        self.progress_bar.setValue(value)
        
    @Slot(int, int, int)
    def on_stats_updated(self, total, critical, requests):
        self.stats.update_stats(total, critical, requests)

    @Slot()
    def on_scan_finished(self):
        if self.scan_timer.isActive(): self.scan_timer.stop()
        self.reset_controls()
        self.progress_bar.setFormat("TASK COMPLETE")
        
        # Send data to Firebase
        target_text = self.txt_target.toPlainText().strip()
        target_url = target_text.split('\n')[0] if target_text else (self.targets[0]['url'] if self.targets else "Unknown")
        
        if self.all_findings:
             # Lazy initialize firebase and check if path is set
             fb_path = self.txt_firebase_path.text().strip()
             if fb_path and self.firebase is None:
                 try:
                     self.firebase = FirebaseReporter(fb_path)
                 except Exception as e:
                     self.on_log_message(f"<span style='color:#ff5555'>[!] Firebase Auth Error: {str(e)}</span>")
                     
             if self.firebase:
                 self.on_log_message("<span style='color:#00f3ff'>[*] Uploading final report to Firebase...</span>")
                 success = self.firebase.send_report(target_url, self.all_findings)
                 if success:
                     self.on_log_message("<span style='color:#00ff9d'>[+] Firebase upload SUCCESS.</span>")
                 else:
                     self.on_log_message("<span style='color:#ff5555'>[!] Firebase upload FAILED. Check logs.</span>")
             else:
                 self.on_log_message("<span style='color:#aaaaaa'>[info] Firebase not configured. Skipping cloud upload.</span>")

        QMessageBox.information(self, "Scan Complete", "Operation finished successfully.")

        self.btn_stop.setEnabled(False)

    def create_converter_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(15)

        # Header
        header = QLabel("LOCALHOST REQUEST CONVERTER")
        header.setStyleSheet("font-size: 18pt; font-weight: bold; color: #00f3ff; font-family: 'Consolas';")
        layout.addWidget(header)

        desc = QLabel("Convert captured network requests (URLs/Headers) to use localhost for safe local analysis, or revert them back.")
        desc.setStyleSheet("color: #aaa; font-size: 10pt;")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        # Controls
        controls_layout = QHBoxLayout()
        
        self.txt_original_domain = QLineEdit()
        self.txt_original_domain.setPlaceholderText("Enter Original Domain (e.g., example.com) to Revert...")
        self.txt_original_domain.setStyleSheet(
            "background-color: #1e1e2e; color: #00ff9d; border: 1px solid #445; padding: 10px; font-family: 'Consolas';"
        )
        
        self.txt_local_port = QLineEdit()
        self.txt_local_port.setPlaceholderText("Local Port (e.g., 8080)...")
        self.txt_local_port.setText("8080")
        self.txt_local_port.setFixedWidth(150)
        self.txt_local_port.setStyleSheet(self.txt_original_domain.styleSheet())

        controls_layout.addWidget(QLabel("Domain:"))
        controls_layout.addWidget(self.txt_original_domain)
        controls_layout.addWidget(QLabel("Port:"))
        controls_layout.addWidget(self.txt_local_port)
        layout.addLayout(controls_layout)

        # Buttons
        btn_layout = QHBoxLayout()
        
        btn_to_local = QPushButton("CONVERT TO LOCALHOST ➡")
        btn_to_local.setFixedHeight(40)
        btn_to_local.setStyleSheet("background-color: #00f3ff; color: #000; font-weight: bold; border-radius: 5px;")
        btn_to_local.clicked.connect(self.convert_to_localhost)
        
        btn_to_original = QPushButton("⬅ REVERT TO ORIGINAL")
        btn_to_original.setFixedHeight(40)
        btn_to_original.setStyleSheet("background-color: #ff0055; color: #fff; font-weight: bold; border-radius: 5px;")
        btn_to_original.clicked.connect(self.revert_to_original)

        btn_layout.addWidget(btn_to_local)
        btn_layout.addWidget(btn_to_original)
        layout.addLayout(btn_layout)

        # Input / Output Areas
        io_layout = QHBoxLayout()
        
        # Left: Input
        input_layout = QVBoxLayout()
        self.txt_input = QTextEdit()
        self.txt_input.setPlaceholderText("PASTE Network Requests / URLs / Headers here...")
        self.txt_input.setStyleSheet(
            "background-color: #111; color: #eee; border: 1px solid #334; font-family: 'Consolas'; font-size: 10pt;"
        )
        input_layout.addWidget(QLabel("INPUT DATA:"))
        input_layout.addWidget(self.txt_input)
        
        # Right: Output
        output_layout = QVBoxLayout()
        self.txt_output = QTextEdit()
        self.txt_output.setPlaceholderText("Result will appear here...")
        self.txt_output.setStyleSheet(self.txt_input.styleSheet())
        output_layout.addWidget(QLabel("CONVERTED DATA:"))
        output_layout.addWidget(self.txt_output)
        
        io_layout.addLayout(input_layout)
        io_layout.addLayout(output_layout)
        layout.addLayout(io_layout)

        return page

    def convert_to_localhost(self):
        text = self.txt_input.toPlainText()
        if not text: return
        
        # 1. Auto-Detect Domain if not provided
        if not self.txt_original_domain.text():
            # Try Host header
            host_match = re.search(r"Host:\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", text, re.IGNORECASE)
            if host_match:
                self.txt_original_domain.setText(host_match.group(1))
            else:
                # Try URL
                url_match = re.search(r"https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", text)
                if url_match:
                    self.txt_original_domain.setText(url_match.group(1))

        orig_domain = self.txt_original_domain.text().strip()
        if not orig_domain:
            QMessageBox.warning(self, "Missing Domain", "Could not auto-detect Original Domain. Please enter it manually.")
            self.txt_original_domain.setFocus()
            return

        port = self.txt_local_port.text().strip()
        port_suffix = f":{port}" if port else ""
        localhost = f"localhost{port_suffix}"
        
        # 2. Global Domain Replacement (Smart & Wildcard)
        # Regex: (?:[a-zA-Z0-9-]+\.)*ESCAPED_DOMAIN\b
        # Matches subdomains + domain
        
        escaped_domain = re.escape(orig_domain)
        pattern = rf"(?:[a-zA-Z0-9-]+\.)*{escaped_domain}\b"
        
        # Replace all instances with localhost:PORT, PRESERVING protocol
        # Case insensitive
        converted = re.sub(pattern, localhost, text, flags=re.IGNORECASE)
        
        # Note: We do NOT force http/https downgrade anymore, respecting original protocol.
        
        self.txt_output.setPlainText(converted)
        QMessageBox.information(self, "Converted", "Domains (and subdomains) converted to Localhost!")

    def revert_to_original(self):
        text = self.txt_input.toPlainText()
        orig_domain = self.txt_original_domain.text().strip()
        port = self.txt_local_port.text().strip()
        
        if not text: return
        if not orig_domain: 
            QMessageBox.warning(self, "Flag", "Please enter the Original Domain to revert to!")
            self.txt_original_domain.setFocus()
            return

        # 1. Revert localhost:PORT to ORIG_DOMAIN
        # Matches localhost:PORT or just localhost
        
        port_suffix = f":{port}" if port else ""
        # Escape for regex
        escaped_suffix = re.escape(port_suffix)
        
        # Pattern: localhost(:PORT)?
        # We want to match 'localhost:8080' specifically if port is set, or just 'localhost'
        pattern = rf"localhost{escaped_suffix}"
        
        converted = re.sub(pattern, orig_domain, text, flags=re.IGNORECASE)
        self.txt_output.setPlainText(converted)
        QMessageBox.information(self, "Reverted", f"Localhost reverted to {orig_domain}!")

    def create_downloader_page(self):
        self.downloader_widget = DownloaderWidget()
        return self.downloader_widget

    def create_dork_page(self):
        self.dorks_widget = DorkWidget()
        return self.dorks_widget

    def create_ddos_page(self):
        # Placeholder Widget for Lazy Loading
        self.ddos_container = QWidget()
        layout = QVBoxLayout(self.ddos_container)
        layout.setAlignment(Qt.AlignCenter)
        
        lbl_info = QLabel("🔥 ATTACK PANEL (MHDDoS)")
        lbl_info.setStyleSheet("font-size: 20pt; font-weight: bold; color: #ff0055;")
        lbl_info.setAlignment(Qt.AlignCenter)
        
        btn_load = GlowButton("⚠️ ACTIVATE ATTACK PANEL ⚠️", "#ff0055")
        btn_load.setFixedSize(300, 60)
        btn_load.clicked.connect(self.load_mhddos_panel)
        
        layout.addWidget(lbl_info)
        layout.addSpacing(20)
        layout.addWidget(btn_load)
        
        return self.ddos_container

    def load_mhddos_panel(self):
        try:
            # Lazy Import
            try:
                from gui.ddos_widget import MHDDoSWidget
            except ImportError as e:
                try:
                    from .ddos_widget import MHDDoSWidget
                except ImportError:
                    raise e
            
            # Clear container
            layout = self.ddos_container.layout()
            while layout.count():
                child = layout.takeAt(0)
                if child.widget():
                    child.widget().deleteLater()
            
            # Initialize Widget
            self.ddos_widget = MHDDoSWidget()
            layout.addWidget(self.ddos_widget)
            
        except Exception as e:
            QMessageBox.critical(self, "Lazy Load Error", f"Failed to load Attack Panel: {e}")

    def create_network_page(self):
        self.network_widget = NetworkAnalyzerWidget()
        return self.network_widget

    def create_supabase_page(self):
        self.supabase_widget = SupabaseWidget()
        return self.supabase_widget

    def create_mirror_page(self):
        self.mirror_widget = MirrorWidget()
        return self.mirror_widget

    def create_sqlmap_page(self):
        self.sqlmap_widget = SqlMapWidget()
        return self.sqlmap_widget

    def create_portscan_page(self):
        self.portscan_widget = PortScanWidget()
        return self.portscan_widget

    def create_xssscan_page(self):
        self.xssscan_widget = XssScanWidget()
        return self.xssscan_widget

    def create_settings_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)

        title = QLabel("⚙ SYSTEM SETTINGS")
        title.setStyleSheet("color: #FFFFFF; font-weight: 800; font-size: 24pt; letter-spacing: -1px;")
        layout.addWidget(title)
        
        desc = QLabel("Configure global application parameters, AI engine credentials, and system localization.")
        desc.setStyleSheet("color: rgba(255, 255, 255, 0.6); font-size: 11pt;")
        layout.addWidget(desc)

        # AI Configuration
        ai_panel = QFrame()
        ai_panel.setObjectName("ContentPanel")
        ai_layout = QVBoxLayout(ai_panel)
        
        lbl_ai = QLabel("⚡ AI ENGINE CONFIGURATION")
        lbl_ai.setStyleSheet("color: #00F3FF; font-weight: bold; font-size: 10pt; letter-spacing: 1px;")
        ai_layout.addWidget(lbl_ai)

        self.txt_ai_key = QLineEdit()
        self.txt_ai_key.setPlaceholderText("Enter Groq API Key (gsk_...)")
        self.txt_ai_key.setEchoMode(QLineEdit.Password)
        self.txt_ai_key.setStyleSheet("padding: 12px; font-size: 10pt;")
        ai_layout.addWidget(self.txt_ai_key)

        self.combo_ai_model = QComboBox()
        self.combo_ai_model.addItems([
            "llama-3.3-70b-versatile",
            "openai/gpt-oss-120b",
            "moonshotai/kimi-k2-instruct-0905",
            "meta-llama/llama-4-maverick-17b-128k",
            "meta-llama/llama-4-scout-17b-16e-instruct",
            "mixtral-8x7b-32768",
        ])
        ai_layout.addWidget(self.combo_ai_model)
        
        lbl_firebase = QLabel("🔥 FIREBASE CREDENTIALS (JSON PATH)")
        lbl_firebase.setStyleSheet("color: #00F3FF; font-weight: bold; font-size: 10pt; letter-spacing: 1px; margin-top: 15px;")
        ai_layout.addWidget(lbl_firebase)

        self.txt_firebase_path = QLineEdit()
        self.txt_firebase_path.setPlaceholderText("C:/path/to/firebase-sdk.json")
        self.txt_firebase_path.setStyleSheet("padding: 12px; font-size: 10pt;")
        # Keep old bionicdragon path as default to preserve backwards compat if it is valid locally
        self.txt_firebase_path.setText(r"c:\Users\bionicdragon\Downloads\sunshinecursos-5f92a-firebase-adminsdk-fbsvc-f534ab6d5c.json")
        ai_layout.addWidget(self.txt_firebase_path)

        layout.addWidget(ai_panel)

        # Localization
        lang_panel = QFrame()
        lang_panel.setObjectName("ContentPanel")
        lang_layout = QVBoxLayout(lang_panel)
        
        lbl_lang = QLabel("🌐 SYSTEM LANGUAGE")
        lbl_lang.setStyleSheet("color: #00F3FF; font-weight: bold; font-size: 10pt; letter-spacing: 1px;")
        lang_layout.addWidget(lbl_lang)

        self.combo_lang = QComboBox()
        self.combo_lang.addItems([
            "English (US)", "Português (Brasil)", "Español", "Français", 
            "Deutsch", "Русский (Russian)", "中文 (Chinese)", "日本語 (Japanese)"
        ])
        self.combo_lang.currentTextChanged.connect(self.change_language)
        lang_layout.addWidget(self.combo_lang)
        layout.addWidget(lang_panel)

        # Governor Backend Control
        gov_panel = QFrame()
        gov_panel.setObjectName("ContentPanel")
        gov_layout = QVBoxLayout(gov_panel)
        
        lbl_gov = QLabel("🛡️ GOVERNOR EXECUTION BACKEND")
        lbl_gov.setStyleSheet("color: #FF0055; font-weight: bold; font-size: 10pt; letter-spacing: 1px;")
        gov_layout.addWidget(lbl_gov)

        gov_desc = QLabel("O backend permite que botes no relatório executem comandos no seu terminal Windows instantaneamente.")
        gov_desc.setStyleSheet("color: #aaa; font-size: 9pt;")
        gov_layout.addWidget(gov_desc)

        gov_btn_layout = QHBoxLayout()
        self.btn_start_gov = QPushButton("▶ INICIAR BACKEND")
        self.btn_start_gov.setStyleSheet("background-color: #1a1a2e; color: #00ff9d; border: 1px solid #00ff9d; padding: 10px;")
        self.btn_start_gov.clicked.connect(self.toggle_governor_backend)
        
        self.lbl_gov_status = QLabel("STATUS: OFFLINE")
        self.lbl_gov_status.setStyleSheet("color: #ff0055; font-weight: bold; margin-left: 10px;")
        
        gov_btn_layout.addWidget(self.btn_start_gov)
        gov_btn_layout.addWidget(self.lbl_gov_status)
        gov_btn_layout.addStretch()
        gov_layout.addLayout(gov_btn_layout)
        
        layout.addWidget(gov_panel)

        layout.addStretch()
        return page

    def toggle_governor_backend(self):
        import subprocess
        import os
        
        if self.governor_backend_process is None:
            # Start backend
            try:
                # Use sys.executable to ensure we use the same python environment
                self.governor_backend_process = subprocess.Popen([sys.executable, "core/governor_backend.py"])
                self.lbl_gov_status.setText("STATUS: ONLINE (Port 5000)")
                self.lbl_gov_status.setStyleSheet("color: #00ff9d; font-weight: bold; margin-left: 10px;")
                self.btn_start_gov.setText("⏹ PARAR BACKEND")
                self.btn_start_gov.setStyleSheet("background-color: #1a1a2e; color: #ff0055; border: 1px solid #ff0055; padding: 10px;")
                QMessageBox.information(self, "Governor Backend", "Backend iniciado com sucesso na porta 5000.")
            except Exception as e:
                QMessageBox.critical(self, "Erro", f"Falha ao iniciar backend: {str(e)}")
        else:
            # Stop backend
            self.governor_backend_process.terminate()
            self.governor_backend_process = None
            self.lbl_gov_status.setText("STATUS: OFFLINE")
            self.lbl_gov_status.setStyleSheet("color: #ff0055; font-weight: bold; margin-left: 10px;")
            self.btn_start_gov.setText("▶ INICIAR BACKEND")
            self.btn_start_gov.setStyleSheet("background-color: #1a1a2e; color: #00ff9d; border: 1px solid #00ff9d; padding: 10px;")
            QMessageBox.information(self, "Governor Backend", "Backend encerrado.")

    def closeEvent(self, event):
        # Cleanup backend process on exit
        if self.governor_backend_process:
            self.governor_backend_process.terminate()
        super().closeEvent(event)
