import sys
import asyncio
import re
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QPushButton, 
    QTextEdit, QProgressBar, QLabel, QHBoxLayout, QMessageBox, QFileDialog, QCheckBox,
    QStackedWidget, QFrame, QSizePolicy, QLineEdit, QApplication, QGraphicsDropShadowEffect
)
from PySide6.QtCore import Slot, Qt, QSize
from PySide6.QtGui import QIcon, QAction, QColor

try:
    from .styles import MAIN_STYLE, LOG_STYLE
    from .widgets import (
        ResultsTable, DashboardStats, GlowButton, 
        FundsWidget, SensitiveDataWidget, ProxyWidget, PayloadsWidget, ScriptLabWidget
    )
    from core.scanner import NexusScanner
    from core.reporter import ReportGenerator
    from core.integrations import SupabaseHandler
    from .downloader import DownloaderWidget
    from .dork_widget import DorkWidget
    from .network_widget import NetworkAnalyzerWidget
    # from .ddos_widget import MHDDoSWidget # Lazy loaded
except ImportError:
    from gui.styles import MAIN_STYLE, LOG_STYLE
    from gui.widgets import (
        ResultsTable, DashboardStats, GlowButton, 
        FundsWidget, SensitiveDataWidget, ProxyWidget, PayloadsWidget, ScriptLabWidget
    )
    from core.scanner import NexusScanner
    from core.reporter import ReportGenerator
    from core.integrations import SupabaseHandler
    from gui.downloader import DownloaderWidget # Import Downloader
    from gui.dork_widget import DorkWidget
    from gui.network_widget import NetworkAnalyzerWidget
    # from gui.ddos_widget import MHDDoSWidget # Lazy loaded

class MainWindow(QMainWindow):
    def __init__(self, targets):
        super().__init__()
        self.targets = targets 
        self.scanner = None
        self.all_findings = []
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("NEXUS CYBER-OFFENSIVE SUITE v21.0 - ULTIMATE")
        self.resize(1400, 900)
        self.setStyleSheet(MAIN_STYLE)

        # Main Layout (Sidebar + Content)
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QHBoxLayout(main_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # --- SIDEBAR ---
        self.sidebar = QWidget()
        self.sidebar.setObjectName("Sidebar")
        self.sidebar.setFixedWidth(250)
        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(0, 20, 0, 20)
        sidebar_layout.setSpacing(10)

        # Header in Sidebar
        header = QLabel("⬡ NEXUS")
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("font-family: 'Consolas'; font-size: 24pt; font-weight: bold; color: #00f3ff; letter-spacing: 4px;")
        sidebar_layout.addWidget(header)

        subtitle = QLabel("CYBER-OFFENSIVE SUITE")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("font-family: 'Consolas'; font-size: 7pt; color: #445; letter-spacing: 3px;")
        sidebar_layout.addWidget(subtitle)
        sidebar_layout.addSpacing(35)

        # Navigation Buttons
        self.btn_nav_dashboard = self.create_nav_button("DASHBOARD", 0)
        self.btn_nav_scan = self.create_nav_button("SCANNER", 1)
        self.btn_nav_payloads = self.create_nav_button("PAYLOADS", 2)
        self.btn_nav_scriptlab = self.create_nav_button("SCRIPT LAB", 3)
        self.btn_nav_tools = self.create_nav_button("TOOLS / PROXY", 4)
        self.btn_nav_converter = self.create_nav_button("CONVERTER", 5)
        self.btn_nav_downloader = self.create_nav_button("DOWNLOADER", 6)
        self.btn_nav_dorks = self.create_nav_button("DORK ANALYSIS", 7)
        self.btn_nav_ddos = self.create_nav_button("ATTACK PANEL", 8)
        self.btn_nav_network = self.create_nav_button("NETWORK & DB ANALYZER", 9)
        
        sidebar_layout.addWidget(self.btn_nav_dashboard)
        sidebar_layout.addWidget(self.btn_nav_scan)
        sidebar_layout.addWidget(self.btn_nav_payloads)
        sidebar_layout.addWidget(self.btn_nav_scriptlab)
        sidebar_layout.addWidget(self.btn_nav_tools)
        sidebar_layout.addWidget(self.btn_nav_converter)
        sidebar_layout.addWidget(self.btn_nav_downloader)
        sidebar_layout.addWidget(self.btn_nav_dorks)
        sidebar_layout.addWidget(self.btn_nav_ddos)
        sidebar_layout.addWidget(self.btn_nav_network)
        sidebar_layout.addStretch()
        
        # Version Info
        version = QLabel("v20.1.0  │  ULTIMA")
        version.setAlignment(Qt.AlignCenter)
        version.setStyleSheet("color: #334; font-size: 7pt; letter-spacing: 2px;")
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
        
        # Default Page
        self.btn_nav_dashboard.setChecked(True)

    def create_nav_button(self, text, index):
        btn = QPushButton(text)
        btn.setObjectName("SidebarButton")
        btn.setCheckable(True)
        btn.setAutoExclusive(True)
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
                    self.dorks_widget.set_target(self.txt_target.text().strip())

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
        
        widgets_layout.addWidget(self.stats, 6)
        widgets_layout.addWidget(self.funds, 4)
        layout.addLayout(widgets_layout) # Add the new widgets_layout to the main layout
        
        # Target Input
        input_layout = QHBoxLayout()
        lbl = QLabel("TARGET:")
        lbl.setStyleSheet("color: #00f3ff; font-weight: bold;")
        self.txt_target = QLineEdit()
        self.txt_target.setPlaceholderText("https://example.com")
        self.txt_target.setStyleSheet("font-size: 11pt; padding: 8px;")
        
        input_layout.addWidget(lbl)
        input_layout.addWidget(self.txt_target)
        layout.addLayout(input_layout)

        # --- AI CONFIGURATION ---
        ai_frame = QFrame()
        ai_frame.setStyleSheet("background-color: rgba(0, 50, 80, 0.3); border-radius: 5px; padding: 5px;")
        ai_layout = QHBoxLayout(ai_frame)
        
        lbl_ai = QLabel("⚡ AI ENGINE:")
        lbl_ai.setStyleSheet("color: #ffcc00; font-weight: bold; font-size: 10pt; letter-spacing: 1px;")
        
        self.txt_ai_key = QLineEdit()
        self.txt_ai_key.setPlaceholderText("gsk_... (Groq API Key)")
        self.txt_ai_key.setEchoMode(QLineEdit.Password)
        
        from PySide6.QtWidgets import QComboBox
        self.combo_ai_model = QComboBox()
        self.combo_ai_model.addItems([
            # --- Top Tier (Best for Pentesting) ---
            "llama-3.3-70b-versatile",
            "openai/gpt-oss-120b",
            "moonshotai/kimi-k2-instruct-0905",
            "meta-llama/llama-4-maverick-17b-128k",
            "meta-llama/llama-4-scout-17b-16e-instruct",
            # --- Fast / Lightweight ---
            "openai/gpt-oss-20b",
            "llama-3.1-8b-instant",
            "qwen/qwen3-32b",
            # --- Specialized ---
            "mixtral-8x7b-32768",
            "meta-llama/llama-prompt-guard-2-86m",
        ])
        # self.combo_ai_model.setEditable(True) # Disabled per user request (wants list only)
        self.combo_ai_model.setFixedWidth(260)
        
        ai_layout.addWidget(lbl_ai)
        ai_layout.addWidget(self.txt_ai_key)
        ai_layout.addWidget(self.combo_ai_model)
        
        layout.addWidget(ai_frame)
        
        # --- LANGUAGE CONFIGURATION ---
        lang_frame = QFrame()
        lang_frame.setStyleSheet("background-color: rgba(60, 0, 80, 0.3); border-radius: 5px; padding: 5px; margin-top: 10px;")
        lang_layout = QHBoxLayout(lang_frame)
        
        lbl_lang = QLabel("🌐 SYSTEM LANGUAGE:")
        lbl_lang.setStyleSheet("color: #ff00ff; font-weight: bold; font-size: 10pt; letter-spacing: 1px;")
        
        self.combo_lang = QComboBox()
        self.combo_lang.addItems([
            "English (US)", "Português (Brasil)", "Español", "Français", 
            "Deutsch", "Русский (Russian)", "中文 (Chinese)", "日本語 (Japanese)",
            "العربية (Arabic)", "हिन्दी (Hindi)"
        ])
        self.combo_lang.setFixedWidth(260)
        self.combo_lang.currentTextChanged.connect(self.change_language)
        
        lang_layout.addWidget(lbl_lang)
        lang_layout.addStretch()
        lang_layout.addWidget(self.combo_lang)
        layout.addWidget(lang_frame)
        
        # Quick Actions Layout
        actions_layout = QHBoxLayout()
        self.chk_deep = QCheckBox("DEEP_SCAN_PROTOCOL")
        self.chk_deep.setStyleSheet("font-size: 11pt; color: #00ff9d; font-weight: bold;")
        
        self.chk_headless = QCheckBox("HEADLESS_MODE")
        self.chk_headless.setChecked(True)
        self.chk_headless.setStyleSheet("font-size: 11pt; color: #00ff9d; font-weight: bold;")
        
        self.chk_proxychains = QCheckBox("PROXYCHAINS (SOCKS5 127.0.0.1:9050)")
        self.chk_proxychains.setStyleSheet("font-size: 11pt; color: #ff9d00; font-weight: bold;")
        
        self.btn_start = GlowButton("INITIALIZE SCAN", "#00ff9d")
        self.btn_start.setObjectName("ActionGreen")
        self.btn_start.clicked.connect(self.start_scan)
        
        self.btn_stop = GlowButton("ABORT OPERATION", "#ff0055")
        self.btn_stop.setObjectName("ActionRed")
        self.btn_stop.clicked.connect(self.stop_scan)
        self.btn_stop.setEnabled(False)
        
        self.btn_copy = GlowButton("COPY FINDINGS", "#00f3ff")
        self.btn_copy.setObjectName("ActionBlue")
        self.btn_copy.clicked.connect(self.copy_all_findings)

        actions_layout.addWidget(self.chk_deep)
        actions_layout.addSpacing(15)
        actions_layout.addWidget(self.chk_headless)
        actions_layout.addSpacing(15)
        actions_layout.addWidget(self.chk_proxychains)
        actions_layout.addStretch()
        actions_layout.addWidget(self.btn_copy)
        actions_layout.addWidget(self.btn_start)
        actions_layout.addWidget(self.btn_stop)
        
        layout.addLayout(actions_layout)
        
        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("SYSTEM IDLE")
        layout.addWidget(self.progress_bar)

        # Recent Findings (Small Table)        # 4. Results Table
        self.results_table = ResultsTable()
        self.apply_glow_effect(self.results_table, QColor(0, 243, 255, 30))
        layout.addWidget(self.results_table)

        return page

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
        # We target the first target passed or default
        target_url = self.txt_target.text().strip()
        if not target_url and not self.targets:
             QMessageBox.warning(self, "Error", "Target URL is required for initialization.")
             return
             
        if not target_url and self.targets:
            target_url = self.targets[0]['url']
            
        if not target_url.startswith("http"): target_url = "https://" + target_url

        # Build scan targets
        scan_targets = [{"name": "Global Target", "url": target_url}]
        
        self.btn_start.setEnabled(False)
        self.txt_target.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.progress_bar.setFormat("SCANNING IN PROGRESS... %p%")
        
        self.progress_bar.setValue(0)
        self.results_table.setRowCount(0)
        self.log_console.clear()
        self.sensitive_widget.list_widget.clear()
        self.all_findings = []
        self.stats.update_stats(0, 0, 0)
        
        is_deep = self.chk_deep.isChecked()
        is_bypass = self.proxy_widget.chk_bypass.isChecked()
        is_headless = self.chk_headless.isChecked()
        is_proxychains = self.chk_proxychains.isChecked()
        is_strict = self.proxy_widget.chk_strict.isChecked()
        is_dynamic_timeout = self.proxy_widget.chk_timeout.isChecked()
        is_heuristic = self.proxy_widget.chk_heuristic.isChecked()
        
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
            ai_key=ai_key,
            ai_model=ai_model
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
                self.dorks_widget.set_target(self.txt_target.text().strip())
        
        asyncio.ensure_future(self.scanner.run_scan())

    @Slot()
    def stop_scan(self):
        if self.scanner: self.scanner.stop_scan()
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
        
        clipboard.setText(report)
        QMessageBox.information(self, "Copied", "All findings copied to clipboard!")

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
            
            if file_path.endswith(".html"):
                # TODO: Trigger AI PoC generation async if needed
                content = generator.generate_html()
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
        self.reset_controls()
        self.progress_bar.setFormat("TASK COMPLETE")
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
            QMessageBox.critical(self, "Error", f"Failed to load Attack Panel:\n{str(e)}")

    def create_network_page(self):
        self.network_widget = NetworkAnalyzerWidget()
        return self.network_widget
