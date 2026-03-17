from PySide6.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout, QLabel, QFrame, QPushButton, 
    QGraphicsDropShadowEffect, QTableWidget, QTableWidgetItem, QHeaderView,
    QLineEdit, QInputDialog, QMessageBox, QListWidget, QListWidgetItem,
    QCheckBox, QTextEdit
)
from PySide6.QtCore import Qt, QTimer, Property, QPropertyAnimation, QEasingCurve, Signal
from PySide6.QtGui import QColor, QFont, QBrush
import time

class GlowButton(QPushButton):
    def __init__(self, text, color="#00f3ff", parent=None):
        super().__init__(text, parent)
        self.color = color
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: rgba({self._hex_to_rgb(self.color)}, 0.07);
                border: 1px solid {self.color};
                border-radius: 8px;
                color: {self.color};
                padding: 10px 22px;
                font-weight: bold;
                letter-spacing: 1px;
                min-height: 18px;
            }}
            QPushButton:hover {{
                background-color: rgba({self._hex_to_rgb(self.color)}, 0.25);
                border: 1px solid #ffffff;
                color: #ffffff;
            }}
            QPushButton:pressed {{
                background-color: rgba({self._hex_to_rgb(self.color)}, 0.4);
            }}
            QPushButton:disabled {{
                background-color: rgba(30, 30, 40, 0.4);
                border: 1px solid #333;
                color: #555;
            }}
        """)
        
        # Add Glow Effect
        self.shadow = QGraphicsDropShadowEffect(self)
        self.shadow.setBlurRadius(0)
        self.shadow.setColor(QColor(self.color))
        self.shadow.setOffset(0, 0)
        self.setGraphicsEffect(self.shadow)
        
        # Animation for hover
        self.anim = QPropertyAnimation(self.shadow, b"blurRadius")
        self.anim.setDuration(200)
        
    @staticmethod
    def _hex_to_rgb(hex_color):
        """Convert #RRGGBB or #RGB to 'R, G, B' string."""
        hex_color = hex_color.lstrip('#')
        if len(hex_color) == 3:
            hex_color = hex_color[0]*2 + hex_color[1]*2 + hex_color[2]*2
        r, g, b = int(hex_color[0:2], 16), int(hex_color[2:4], 16), int(hex_color[4:6], 16)
        return f"{r}, {g}, {b}"

    def enterEvent(self, event):
        self.anim.stop()
        self.anim.setEndValue(25)  # Stronger glow
        self.anim.start()
        super().enterEvent(event)
        
    def leaveEvent(self, event):
        self.anim.stop()
        self.anim.setEndValue(0)
        self.anim.start()
        super().leaveEvent(event)


class AnimatedLabel(QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._value = 0
        self.target_value = 0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_value)
        
    def set_value(self, value):
        self.target_value = value
        if not self.timer.isActive():
            self.timer.start(30) # 30ms update interval

    def update_value(self):
        if self._value < self.target_value:
            step = max(1, int((self.target_value - self._value) / 10))
            self._value += step
            self.setText(str(self._value))
        elif self._value > self.target_value: 
            self._value = self.target_value
            self.setText(str(self._value))
            self.timer.stop()
        else:
            self.timer.stop()

class StatCard(QFrame):
    def __init__(self, title, value_color="#00f3ff"):
        super().__init__()
        self.layout = QVBoxLayout(self)
        self.layout.setSpacing(6)
        self.layout.setContentsMargins(12, 16, 12, 16)
        self.setStyleSheet(f"""
            QFrame {{
                border: 1px solid rgba(255, 255, 255, 0.1);
                background-color: rgba(30, 30, 45, 0.4);
                border-radius: 28px;
            }}
        """)
        self.setMinimumHeight(100)
        
        self.lbl_title = QLabel(title)
        self.lbl_title.setStyleSheet("color: #556; font-size: 8pt; border: none; background: transparent; font-weight: 700; letter-spacing: 2px;")
        self.lbl_title.setAlignment(Qt.AlignCenter)
        
        self.lbl_value = AnimatedLabel("0")
        self.lbl_value.setStyleSheet(f"color: {value_color}; font-size: 26pt; font-weight: bold; border: none; background: transparent;")
        self.lbl_value.setAlignment(Qt.AlignCenter)
        
        self.layout.addWidget(self.lbl_title)
        self.layout.addWidget(self.lbl_value)

    def set_value(self, value):
        self.lbl_value.set_value(value)

class DashboardStats(QWidget):
    def __init__(self):
        super().__init__()
        layout = QHBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(10, 10, 10, 10)
        
        self.card_targets = StatCard("TARGETS", "#00f3ff")
        self.card_findings = StatCard("VULNS", "#00ff9d")
        self.card_critical = StatCard("CRITICAL", "#ff0055")
        self.card_scanned = StatCard("REQUESTS", "#ffcc00")
        self.card_rps = StatCard("REQ/SEC (RPS)", "#00b4ff")

        layout.addWidget(self.card_targets)
        layout.addWidget(self.card_findings)
        layout.addWidget(self.card_critical)
        layout.addWidget(self.card_scanned)
        layout.addWidget(self.card_rps)
        
        self.total_requests_last = 0
        self.last_time = time.time()

    def set_target_count(self, count):
        self.card_targets.set_value(count)

    def update_stats(self, findings, critical, requests=0):
        self.card_findings.set_value(findings)
        self.card_critical.set_value(critical)
        self.card_scanned.set_value(requests)
        
        # Calculate RPS
        current_time = time.time()
        time_diff = current_time - self.last_time
        if time_diff >= 1.0:
            req_diff = requests - self.total_requests_last
            rps = int(max(0, req_diff / time_diff))
            self.card_rps.set_value(rps)
            self.total_requests_last = requests
            self.last_time = current_time

class FundsWidget(QFrame):
    add_funds_clicked = Signal(float)

    def __init__(self):
        super().__init__()
        self.setObjectName("RainbowCard")
        layout = QVBoxLayout(self)
        
        title = QLabel("SUPABASE WALLET (SECURE)")
        title.setStyleSheet("color: #00f3ff; font-weight: bold; font-size: 14pt; border: none; background: transparent;")
        title.setAlignment(Qt.AlignCenter)
        
        self.lbl_balance = QLabel("$ 0.00")
        self.lbl_balance.setStyleSheet("color: #00ff9d; font-weight: bold; font-size: 32pt; border: none; background: transparent;")
        self.lbl_balance.setAlignment(Qt.AlignCenter)
        
        btn_add = GlowButton("ADD BALANCE", "#00ff9d")
        btn_add.clicked.connect(self._prompt_add_funds)
        
        layout.addWidget(title)
        layout.addStretch()
        layout.addWidget(self.lbl_balance)
        layout.addStretch()
        layout.addWidget(btn_add)
        
    def update_balance(self, amount):
        self.lbl_balance.setText(f"$ {amount:.2f}")
        
    def _prompt_add_funds(self):
        amount, ok = QInputDialog.getDouble(self, "Add Funds", "Amount to add ($):", 50.00, 0, 10000, 2)
        if ok:
            self.add_funds_clicked.emit(amount)

class SensitiveDataWidget(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("ContentPanel")
        layout = QVBoxLayout(self)
        
        title = QLabel("EXTRACTED SECRETS")
        title.setStyleSheet("color: #ff0055; font-weight: bold; font-size: 12pt; border: none; background: transparent;")
        
        self.list_widget = QListWidget()
        self.list_widget.setStyleSheet("""
            QListWidget { background: rgba(0,0,0,0.3); border: none; }
            QListWidgetItem { padding: 5px; border-bottom: 1px solid #333; color: #ddd; }
        """)
        
        layout.addWidget(title)
        layout.addWidget(self.list_widget)

    def add_data(self, title, content):
        item_text = f"[{title}] {content}"
        # Dedup
        existing = self.list_widget.findItems(item_text, Qt.MatchExactly)
        if not existing:
            item = QListWidgetItem(item_text)
            item.setForeground(QBrush(QColor("#ff0055")))
            self.list_widget.addItem(item)

class ProxyWidget(QFrame):
    toggled = Signal(bool)

    def __init__(self):
        super().__init__()
        self.setObjectName("ContentPanel")
        layout = QVBoxLayout(self)
        
        title = QLabel("BYPASS TOOLS")
        title.setStyleSheet("color: #ffcc00; font-weight: bold; font-size: 12pt; border: none; background: transparent;")
        
        self.chk_bypass = QCheckBox("ACTIVATE HEADER BYPASS (403/WAF)")
        self.chk_bypass.setStyleSheet("font-size: 10pt; color: #ffcc00; font-weight: bold;")
        self.chk_bypass.toggled.connect(self.toggled.emit)
        
        info = QLabel("Spoofs X-Forwarded-For, Referer, and User-Agent to bypass IP-based restrictions.")
        info.setWordWrap(True)
        info.setStyleSheet("color: #888; border: none; background: transparent; font-size: 9pt;")
        
        self.chk_jitter = QCheckBox("SMART JITTER (RANDOM DELAYS)")
        self.chk_jitter.setStyleSheet("font-size: 10pt; color: #00f3ff; font-weight: bold;")
        
        info_jitter = QLabel("Introduces random delays (0.5s - 2.5s) between requests to prevent rate-limit bans and reduce false positives.")
        info_jitter.setWordWrap(True)
        info_jitter.setStyleSheet("color: #888; border: none; background: transparent; font-size: 9pt;")

        self.chk_ua = QCheckBox("DYNAMIC USER-AGENT ROTATION")
        self.chk_ua.setStyleSheet("font-size: 10pt; color: #00f3ff; font-weight: bold;")
        
        info_ua = QLabel("Rotates through 50+ modern browser profiles per request to avoid static fingerprinting.")
        info_ua.setWordWrap(True)
        info_ua.setStyleSheet("color: #888; border: none; background: transparent; font-size: 9pt;")

        self.chk_strict = QCheckBox("STRICT VALIDATION (ANTI-FALSE POSITIVE)")
        self.chk_strict.setStyleSheet("font-size: 10pt; color: #ff0055; font-weight: bold;")
        
        info_strict = QLabel("Performs baseline matching against 404 behavior to destroy Soft-404 false positive hits on directories/files.")
        info_strict.setWordWrap(True)
        info_strict.setStyleSheet("color: #888; border: none; background: transparent; font-size: 9pt;")

        self.chk_timeout = QCheckBox("DYNAMIC TIMEOUT SCALING")
        self.chk_timeout.setStyleSheet("font-size: 10pt; color: #ff0055; font-weight: bold;")
        
        info_timeout = QLabel("Dynamically increases connection timeouts per-request on throttled WAFs to prevent false timeout negatives.")
        info_timeout.setWordWrap(True)
        info_timeout.setStyleSheet("color: #888; border: none; background: transparent; font-size: 9pt;")

        self.chk_heuristic = QCheckBox("HEURISTIC PARAMETER MINING (DEEP SQLI/XSS)")
        self.chk_heuristic.setStyleSheet("font-size: 10pt; color: #00ff9d; font-weight: bold;")
        
        info_heur = QLabel("Forces deep Fuzzing into every parsed URL parameter found during the crawl. Extremely loud and slow, but yields 10x deeper results.")
        info_heur.setWordWrap(True)
        info_heur.setStyleSheet("color: #888; border: none; background: transparent; font-size: 9pt;")

        self.chk_ip_rot = QCheckBox("SMART IP ROTATION (TOR/PROXY)")
        self.chk_ip_rot.setStyleSheet("font-size: 10pt; color: #b825ff; font-weight: bold;")

        info_ip = QLabel("Automatically routes traffic through a rotating proxy pool, changing IP addresses every 5 requests to melt IP-based rate limiting walls.")
        info_ip.setWordWrap(True)
        info_ip.setStyleSheet("color: #888; border: none; background: transparent; font-size: 9pt;")

        self.chk_dom_poll = QCheckBox("ASYNC DOM POLLING (HEADLESS XSS)")
        self.chk_dom_poll.setStyleSheet("font-size: 10pt; color: #00f3ff; font-weight: bold;")

        info_dom = QLabel("Spawns headless browser workers to evaluate injected payloads in real-time. Crucial for catching delayed Blind/DOM-based XSS attacks.")
        info_dom.setWordWrap(True)
        info_dom.setStyleSheet("color: #888; border: none; background: transparent; font-size: 9pt;")

        self.chk_ssl_strip = QCheckBox("SSL STRIPPING ABUSE")
        self.chk_ssl_strip.setStyleSheet("font-size: 10pt; color: #ff9d00; font-weight: bold;")

        info_ssl = QLabel("Forces HTTP downgrade attacks on internal links and API calls missing HSTS flags, exposing plain-text session tokens.")
        info_ssl.setWordWrap(True)
        info_ssl.setStyleSheet("color: #888; border: none; background: transparent; font-size: 9pt;")
        
        self.chk_waf_evasion = QCheckBox("ADVANCED WAF EVASION (PAYLOAD OBFUSCATION)")
        self.chk_waf_evasion.setStyleSheet("font-size: 10pt; color: #ff2a2a; font-weight: bold;")

        info_waf = QLabel("Mutates SQLi/XSS payloads using Hex encoding, Unicode escapes, and unexpected null bytes (%00) to bypass strict Firewalls like Cloudflare and AWS WAF.")
        info_waf.setWordWrap(True)
        info_waf.setStyleSheet("color: #888; border: none; background: transparent; font-size: 9pt;")

        self.chk_req_smuggle = QCheckBox("HTTP REQUEST SMUGGLING (CL.TE / TE.CL)")
        self.chk_req_smuggle.setStyleSheet("font-size: 10pt; color: #8a2be2; font-weight: bold;")

        info_smuggle = QLabel("Injects desynchronized Content-Length and Transfer-Encoding headers to poison load balancers and access unauthenticated backend admin panels.")
        info_smuggle.setWordWrap(True)
        info_smuggle.setStyleSheet("color: #888; border: none; background: transparent; font-size: 9pt;")
        
        self.chk_error_bypass = QCheckBox("SMART ERROR BYPASS (401/403/500)")
        self.chk_error_bypass.setStyleSheet("font-size: 10pt; color: #ff0055; font-weight: bold;")

        info_error = QLabel("Automatically attempts to force access to forbidden or crashing endpoints by manipulating HTTP methods, path normalization (/%2e/), and spoofed internal headers upon receiving error codes.")
        info_error.setWordWrap(True)
        info_error.setStyleSheet("color: #888; border: none; background: transparent; font-size: 9pt;")

        self.chk_payload_encode = QCheckBox("CONTEXT-AWARE PAYLOAD ENCODING")
        self.chk_payload_encode.setStyleSheet("font-size: 10pt; color: #00ffcc; font-weight: bold;")

        info_encode = QLabel("Sanitizes and dynamically encodes payloads (URL, Double URL, Base64, CharCode) to avoid breaking server parsers, ensuring only valid tokenized strings reach the final execution context.")
        info_encode.setWordWrap(True)
        info_encode.setStyleSheet("color: #888; border: none; background: transparent; font-size: 9pt;")


        layout.addWidget(title)
        layout.addWidget(self.chk_bypass)
        layout.addWidget(info)
        layout.addSpacing(10)
        layout.addWidget(self.chk_jitter)
        layout.addWidget(info_jitter)
        layout.addSpacing(10)
        layout.addWidget(self.chk_ua)
        layout.addWidget(info_ua)
        layout.addSpacing(10)
        layout.addWidget(self.chk_strict)
        layout.addWidget(info_strict)
        layout.addSpacing(10)
        layout.addWidget(self.chk_timeout)
        layout.addWidget(info_timeout)
        layout.addSpacing(10)
        layout.addWidget(self.chk_heuristic)
        layout.addWidget(info_heur)
        layout.addSpacing(10)
        layout.addWidget(self.chk_ip_rot)
        layout.addWidget(info_ip)
        layout.addSpacing(10)
        layout.addWidget(self.chk_dom_poll)
        layout.addWidget(info_dom)
        layout.addSpacing(10)
        layout.addWidget(self.chk_ssl_strip)
        layout.addWidget(info_ssl)
        layout.addSpacing(10)
        layout.addWidget(self.chk_waf_evasion)
        layout.addWidget(info_waf)
        layout.addSpacing(10)
        layout.addWidget(self.chk_req_smuggle)
        layout.addWidget(info_smuggle)
        layout.addSpacing(10)
        layout.addWidget(self.chk_error_bypass)
        layout.addWidget(info_error)
        layout.addSpacing(10)
        layout.addWidget(self.chk_payload_encode)
        layout.addWidget(info_encode)
        
        # --- NEW EFFICIENCY & EVASION OPTIONS ---
        self.chk_403_bypass = QCheckBox("ACTIVE 403/FORBIDDEN OBFUSCATION")
        self.chk_403_bypass.setStyleSheet("font-size: 10pt; color: #ff00ff; font-weight: bold;")
        info_403 = QLabel("Dynamically alters paths (/%2e/, //) and spoof headers (X-Original-URL) upon hitting WAF blocks.")
        info_403.setWordWrap(True)
        info_403.setStyleSheet("color: #888; border: none; background: transparent; font-size: 9pt;")
        
        self.chk_header_rot = QCheckBox("DYNAMIC HEADER & USER-AGENT ROTATION")
        self.chk_header_rot.setStyleSheet("font-size: 10pt; color: #00ff33; font-weight: bold;")
        info_header = QLabel("Aggressively cycles User-Agents and Accept headers per-request to disrupt behavioral fingerprinting.")
        info_header.setWordWrap(True)
        info_header.setStyleSheet("color: #888; border: none; background: transparent; font-size: 9pt;")
        
        self.chk_auto_tune = QCheckBox("AUTO-TUNE CONCURRENCY (SEMAPHORE OPTIMIZATION)")
        self.chk_auto_tune.setStyleSheet("font-size: 10pt; color: #ffff00; font-weight: bold;")
        info_tune = QLabel("Reduces scanning lag by replacing static fuzz workers with scalable async Semaphores tied to local CPU/Network.")
        info_tune.setWordWrap(True)
        info_tune.setStyleSheet("color: #888; border: none; background: transparent; font-size: 9pt;")

        layout.addSpacing(10)
        layout.addWidget(self.chk_403_bypass)
        layout.addWidget(info_403)
        layout.addSpacing(10)
        layout.addWidget(self.chk_header_rot)
        layout.addWidget(info_header)
        layout.addSpacing(10)
        layout.addWidget(self.chk_auto_tune)
        layout.addWidget(info_tune)
        layout.addStretch()

class ResultsTable(QTableWidget):
    def __init__(self):
        super().__init__()
        self.setColumnCount(5)
        self.setHorizontalHeaderLabels(["SEV", "VULNERABILITY TYPE", "TARGET", "IMPACT / DETAILS", "AÇÃO"])
        self.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.verticalHeader().setVisible(False)
        self.setAlternatingRowColors(True)
        self.setEditTriggers(QTableWidget.NoEditTriggers)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setShowGrid(False)

        # Badge Column size
        self.horizontalHeader().resizeSection(0, 80)

    def add_finding(self, finding):
        row = self.rowCount()
        self.insertRow(row)
        
        # Severity Badge
        sev_item = QTableWidgetItem(finding.severity)
        sev_item.setTextAlignment(Qt.AlignCenter)
        font = QFont()
        font.setBold(True)
        sev_item.setFont(font)

        if finding.severity == "CRITICAL":
            sev_item.setForeground(QColor("#ff0055"))
            sev_item.setBackground(QColor(50, 0, 20, 150))
        elif finding.severity == "HIGH":
            sev_item.setForeground(QColor("#ffcc00"))
            sev_item.setBackground(QColor(50, 40, 0, 150))
        else:
            sev_item.setForeground(QColor("#00f3ff"))
        
        self.setItem(row, 0, sev_item)
        self.setItem(row, 1, QTableWidgetItem(finding.vuln_type))
        self.setItem(row, 2, QTableWidgetItem(finding.target))
        self.setItem(row, 3, QTableWidgetItem(finding.impact))

        if hasattr(finding, 'comando_direto') and finding.comando_direto:
            btn = QPushButton("▶ ACESSAR FALHA")
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #ff0055;
                    color: white;
                    font-weight: bold;
                    border-radius: 4px;
                    padding: 4px 12px;
                }
                QPushButton:hover {
                    background-color: #ff3377;
                }
            """)
            btn.setCursor(Qt.PointingHandCursor)
            cmd = finding.comando_direto
            btn.clicked.connect(lambda checked=False, command=cmd: self._execute_direct_command(command))
            self.setCellWidget(row, 4, btn)
        else:
            # Placeholder se não houver comando
            no_cmd_item = QTableWidgetItem("-")
            no_cmd_item.setTextAlignment(Qt.AlignCenter)
            self.setItem(row, 4, no_cmd_item)

    def _execute_direct_command(self, cmd):
        import subprocess
        try:
            subprocess.Popen(['cmd.exe', '/c', 'start', 'cmd.exe', '/k', cmd])
        except Exception as e:
            print(f"Error executing command: {e}")

class PayloadsWidget(QWidget):
    """Panel that collects and displays AI-generated payloads for easy copying."""

    def __init__(self):
        super().__init__()
        self.payloads = []  # list of (url, script, timestamp)
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        # Header
        header_row = QHBoxLayout()
        title = QLabel("⚡ AI-GENERATED PAYLOADS")
        title.setStyleSheet(
            "color: #ffcc00; font-weight: bold; font-size: 12pt; letter-spacing: 2px;"
        )
        self.lbl_count = QLabel("0 payloads")
        self.lbl_count.setStyleSheet("color: #445; font-size: 8pt;")

        header_row.addWidget(title)
        header_row.addStretch()
        header_row.addWidget(self.lbl_count)
        layout.addLayout(header_row)

        # Payload list (scrollable)
        from PySide6.QtWidgets import QScrollArea
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(
            "QScrollArea { border: none; background: transparent; }"
        )

        self.payload_container = QWidget()
        self.payload_layout = QVBoxLayout(self.payload_container)
        self.payload_layout.setSpacing(10)
        self.payload_layout.setContentsMargins(0, 0, 0, 0)
        self.payload_layout.addStretch()

        scroll.setWidget(self.payload_container)
        layout.addWidget(scroll)

        # Bottom actions
        actions = QHBoxLayout()
        btn_copy_all = GlowButton("COPY ALL PAYLOADS", "#ffcc00")
        btn_copy_all.clicked.connect(self.copy_all)
        btn_clear = GlowButton("CLEAR", "#666")
        btn_clear.clicked.connect(self.clear_all)

        actions.addWidget(btn_clear)
        actions.addStretch()
        actions.addWidget(btn_copy_all)
        layout.addLayout(actions)

    def add_payload(self, url, script):
        """Add a new payload card to the list (with dedup)."""
        # Deduplicate: skip if same URL + script already exists
        for existing_url, existing_script, _ in self.payloads:
            if existing_url == url and existing_script == script:
                return

        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.payloads.append((url, script, timestamp))
        self.lbl_count.setText(f"{len(self.payloads)} payloads")

        # Create card
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background-color: rgba(12, 12, 28, 0.8);
                border: 1px solid rgba(255, 204, 0, 0.2);
                border-radius: 8px;
                padding: 8px;
            }
        """)
        card_layout = QVBoxLayout(card)
        card_layout.setSpacing(6)

        # Card header: URL + timestamp + copy button
        card_header = QHBoxLayout()
        lbl_url = QLabel(f"🎯 {url[:60]}...")
        lbl_url.setStyleSheet("color: #00f3ff; font-size: 9pt; font-weight: bold; border: none; background: transparent;")
        lbl_time = QLabel(timestamp)
        lbl_time.setStyleSheet("color: #556; font-size: 8pt; border: none; background: transparent;")
        btn_copy = QPushButton("📋 COPY")
        btn_copy.setStyleSheet("""
            QPushButton {
                background-color: rgba(255, 204, 0, 0.1);
                border: 1px solid #ffcc00;
                border-radius: 4px;
                color: #ffcc00;
                padding: 4px 12px;
                font-weight: bold;
                font-size: 8pt;
            }
            QPushButton:hover {
                background-color: rgba(255, 204, 0, 0.3);
                color: #fff;
            }
        """)
        btn_copy.setFixedHeight(26)
        # Capture script in closure
        _script = script
        btn_copy.clicked.connect(lambda _, s=_script: self._copy_single(s))

        card_header.addWidget(lbl_url, 1)
        card_header.addWidget(lbl_time)
        card_header.addWidget(btn_copy)
        card_layout.addLayout(card_header)

        # Script preview (truncated, read-only)
        from PySide6.QtWidgets import QTextEdit
        preview = QTextEdit()
        preview.setReadOnly(True)
        preview.setPlainText(script)
        preview.setMaximumHeight(120)
        preview.setStyleSheet("""
            QTextEdit {
                background-color: rgba(5, 5, 12, 0.9);
                color: #c8ffd4;
                border: 1px solid rgba(0, 255, 157, 0.1);
                border-radius: 6px;
                font-family: 'Consolas', monospace;
                font-size: 8pt;
                padding: 6px;
            }
        """)
        card_layout.addWidget(preview)

        # Insert before the stretch
        self.payload_layout.insertWidget(self.payload_layout.count() - 1, card)

    def _copy_single(self, script):
        from PySide6.QtWidgets import QApplication
        clipboard = QApplication.clipboard()
        try:
            clipboard.setText(script)
        except Exception as e:
            print(f"Clipboard error: {e}")

    def copy_all(self):
        if not self.payloads:
            return
        from PySide6.QtWidgets import QApplication
        clipboard = QApplication.clipboard()
        all_text = ""
        for url, script, ts in self.payloads:
            all_text += f"// === [{ts}] {url} ===\n{script}\n\n"
        try:
            clipboard.setText(all_text)
        except Exception as e:
            print(f"Clipboard error: {e}")

    def clear_all(self):
        self.payloads.clear()
        # Remove all cards
        while self.payload_layout.count() > 1:
            item = self.payload_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self.lbl_count.setText("0 payloads")


class ScriptLabWidget(QWidget):
    """Script Lab: Paste audit data, select attack type, generate custom scripts with AI."""

    def __init__(self):
        super().__init__()
        self.ai_assistant = None
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # === HEADER ===
        header = QLabel("🧪 SCRIPT LAB  —  AI EXPLOIT GENERATOR")
        header.setStyleSheet(
            "color: #ff0055; font-weight: bold; font-size: 13pt; letter-spacing: 2px;"
        )
        layout.addWidget(header)

        # === API KEY ROW ===
        from PySide6.QtWidgets import QComboBox
        api_row = QHBoxLayout()
        
        lbl_key = QLabel("AI API KEY (Optional for Ollama):")
        lbl_key.setStyleSheet("color: #ffcc00; font-weight: bold; font-size: 9pt;")
        
        self.txt_api_key = QLineEdit()
        self.txt_api_key.setPlaceholderText("API Key (e.g. gsk_...) - Not needed for llama3:8b")
        self.txt_api_key.setEchoMode(QLineEdit.Password)
        
        self.combo_model = QComboBox()
        self.combo_model.addItems([
            "llama3:8b",
            "llama-3.3-70b-versatile",
            "llama-3.1-8b-instant",
            "mixtral-8x7b-32768",
            "qwen/qwen3-32b",
        ])
        self.combo_model.setFixedWidth(260)
        
        api_row.addWidget(lbl_key)
        api_row.addWidget(self.txt_api_key, 1)
        api_row.addWidget(self.combo_model)
        layout.addLayout(api_row)

        self.target_url = ""

        # === TOP: Input Area (Audit Paste) ===
        lbl_input = QLabel("PASTE AUDIT / RECON DATA:")
        lbl_input.setStyleSheet("color: #00f3ff; font-weight: bold; font-size: 9pt; letter-spacing: 1px;")
        layout.addWidget(lbl_input)

        from PySide6.QtWidgets import QTextEdit
        self.txt_audit_input = QTextEdit()
        self.txt_audit_input.setPlaceholderText(
            "Paste your audit output here...\n\n"
            "Example:\n"
            "[COOKIES] session_id=abc123; auth_token=eyJhbG...\n"
            "[LOCAL_STORAGE] {\"userId\": \"...\", \"apiKey\": \"...\"}\n"
            "[FORM_0] POST /api/login name=text, password=password\n"
            "[INTERESTING_LINK] https://example.com/admin/panel"
        )
        self.txt_audit_input.setMaximumHeight(180)
        self.txt_audit_input.setStyleSheet("""
            QTextEdit {
                background-color: rgba(5, 5, 12, 0.9);
                color: #c8ffd4;
                border: 1px solid rgba(0, 255, 157, 0.2);
                border-radius: 8px;
                font-family: 'Consolas', monospace;
                font-size: 9pt;
                padding: 8px;
            }
        """)
        layout.addWidget(self.txt_audit_input)

        # === CONTROLS ROW ===
        controls = QHBoxLayout()

        # Script Type Selector
        from PySide6.QtWidgets import QComboBox
        lbl_type = QLabel("SCRIPT TYPE:")
        lbl_type.setStyleSheet("color: #ffcc00; font-weight: bold; font-size: 9pt;")

        self.combo_type = QComboBox()
        self.combo_type.addItems([
            "💰 Balance Manipulation",
            "👑 Admin Escalation",
            "💀 Full Takeover",
            "🔍 Full Recon",
            "🔑 Session Hijack",
            "🍪 Cookie Theft",
            "💾 Storage Dump",
            "📋 Form Exploit",
            "🌐 API Recon",
            "💉 DOM XSS",
            "🔐 Credential Harvest",
            "⚙️ Custom"
        ])
        self.combo_type.setFixedWidth(250)

        # Map display names to API keys
        self._type_map = {
            "💰 Balance Manipulation": "balance_manipulation",
            "👑 Admin Escalation": "admin_escalation",
            "💀 Full Takeover": "full_takeover",
            "🔍 Full Recon": "full_recon",
            "🔑 Session Hijack": "session_hijack",
            "🍪 Cookie Theft": "cookie_theft",
            "💾 Storage Dump": "storage_dump",
            "📋 Form Exploit": "form_exploit",
            "🌐 API Recon": "api_recon",
            "💉 DOM XSS": "dom_xss",
            "🔐 Credential Harvest": "credential_harvest",
            "⚙️ Custom": "custom"
        }

        controls.addWidget(lbl_type)
        controls.addWidget(self.combo_type)

        # Extra instructions
        self.txt_extra = QLineEdit()
        self.txt_extra.setPlaceholderText("Extra instructions (optional)...")
        self.txt_extra.setStyleSheet("""
            QLineEdit {
                background-color: rgba(8, 8, 18, 0.9);
                color: #00ff9d;
                border: 1px solid rgba(0, 243, 255, 0.2);
                border-radius: 6px;
                padding: 8px;
            }
        """)
        controls.addWidget(self.txt_extra, 1)

        # Generate button
        self.btn_generate = GlowButton("⚡ GENERATE SCRIPT", "#ff0055")
        self.btn_generate.clicked.connect(self._on_generate)
        controls.addWidget(self.btn_generate)

        layout.addLayout(controls)

        # === STATUS ===
        self.lbl_status = QLabel("")
        self.lbl_status.setStyleSheet("color: #556; font-size: 8pt;")
        layout.addWidget(self.lbl_status)

        # === OUTPUT: Generated Script ===
        lbl_output = QLabel("GENERATED SCRIPT (ready to paste in console):")
        lbl_output.setStyleSheet("color: #00ff9d; font-weight: bold; font-size: 9pt; letter-spacing: 1px;")
        layout.addWidget(lbl_output)

        self.txt_output = QTextEdit()
        self.txt_output.setReadOnly(True)
        self.txt_output.setPlaceholderText("Generated script will appear here...")
        self.txt_output.setStyleSheet("""
            QTextEdit {
                background-color: rgba(5, 5, 12, 0.95);
                color: #c8ffd4;
                border: 1px solid rgba(0, 255, 157, 0.15);
                border-radius: 8px;
                font-family: 'Consolas', monospace;
                font-size: 9pt;
                padding: 10px;
            }
        """)
        layout.addWidget(self.txt_output)

        # === RESULTS FEEDBACK AREA ===
        lbl_results = QLabel("📊 PASTE CONSOLE RESULTS (to refine the script):")
        lbl_results.setStyleSheet("color: #ff9d00; font-weight: bold; font-size: 9pt; letter-spacing: 1px;")
        layout.addWidget(lbl_results)

        self.txt_results = QTextEdit()
        self.txt_results.setPlaceholderText(
            "Run the generated script in the browser console, then paste the output here...\n\n"
            "The AI will analyze the results and generate an improved, fixed version."
        )
        self.txt_results.setMaximumHeight(140)
        self.txt_results.setStyleSheet("""
            QTextEdit {
                background-color: rgba(20, 10, 5, 0.9);
                color: #ffd4a8;
                border: 1px solid rgba(255, 157, 0, 0.25);
                border-radius: 8px;
                font-family: 'Consolas', monospace;
                font-size: 9pt;
                padding: 8px;
            }
        """)
        layout.addWidget(self.txt_results)

        # Refinement Instructions
        self.txt_refine_instr = QLineEdit()
        self.txt_refine_instr.setPlaceholderText("Tell the AI what to fix/improve (e.g. 'Fix the syntax error', 'Add logging')...")
        self.txt_refine_instr.setStyleSheet("""
            QLineEdit {
                background-color: rgba(20, 10, 5, 0.9);
                color: #ffcc00;
                border: 1px solid rgba(255, 157, 0, 0.4);
                border-radius: 4px;
                padding: 6px;
                font-size: 9pt;
            }
        """)
        layout.addWidget(self.txt_refine_instr)

        # === BOTTOM ACTIONS ===
        bottom = QHBoxLayout()
        btn_clear = GlowButton("CLEAR ALL", "#666")
        btn_clear.clicked.connect(self._clear_all)

        self.btn_refine = GlowButton("🔄 REFINE SCRIPT", "#ff9d00")
        self.btn_refine.clicked.connect(self._on_refine)

        self.btn_copy = GlowButton("📋 COPY TO CLIPBOARD", "#00ff9d")
        self.btn_copy.clicked.connect(self._copy_output)

        bottom.addWidget(btn_clear)
        bottom.addStretch()
        bottom.addWidget(self.btn_refine)
        bottom.addWidget(self.btn_copy)
        layout.addLayout(bottom)

    def set_ai_assistant(self, ai_assistant):
        """Set the AI assistant for script generation."""
        self.ai_assistant = ai_assistant

    def set_target(self, url):
        """Set the current target URL for masking."""
        self.target_url = url
        if self.ai_assistant:
            self.ai_assistant.current_real_url = url
            self.ai_assistant.current_masked_url = self.ai_assistant._mask_target(url)

    def _ensure_ai(self):
        """Create AI assistant from local key field if not set."""
        if not self.ai_assistant:
            api_key = self.txt_api_key.text().strip()
            model = self.combo_model.currentText()
            if api_key:
                from core.ai_assistant import AIAssistant
                self.ai_assistant = AIAssistant(api_key, model)
                return True
            return False
        return True

    def _on_generate(self):
        """Start async script generation."""
        audit_data = self.txt_audit_input.toPlainText().strip()
        if not audit_data:
            self.lbl_status.setText("⚠️ Paste audit data first!")
            self.lbl_status.setStyleSheet("color: #ff5555; font-size: 8pt;")
            return

        if not self._ensure_ai():
            self.lbl_status.setText("⚠️ Enter your Groq API key above! Get one at groq.com/keys")
            self.lbl_status.setStyleSheet("color: #ff5555; font-size: 8pt;")
            return

        script_type = self._type_map.get(self.combo_type.currentText(), "full_recon")
        extra = self.txt_extra.text().strip()

        # Update UI state
        self.btn_generate.setEnabled(False)
        self.btn_generate.setText("⏳ GENERATING...")
        self.lbl_status.setText("AI is generating your script...")
        self.lbl_status.setStyleSheet("color: #ffcc00; font-size: 8pt;")
        self.txt_output.setPlainText("")

        # Run async
        import asyncio

        async def _run():
            try:
                result = await self.ai_assistant.generate_custom_script(
                    audit_data, script_type, extra
                )
                return result
            except Exception as e:
                return f"// Error: {str(e)}"

        def _done(future):
            try:
                result = future.result()
                self.txt_output.setPlainText(result)
                lines = result.count('\n') + 1
                if "AI Refusal" in result:
                    self.lbl_status.setText("❌ AI Refused (Safety Filter). Try 'Refine' or use a different model.")
                    self.lbl_status.setStyleSheet("color: #ff5555; font-size: 8pt;")
                else:
                    self.lbl_status.setText(f"✅ Script generated! ({len(result)} chars, {lines} lines)")
                    self.lbl_status.setStyleSheet("color: #00ff9d; font-size: 8pt;")
            except Exception as e:
                self.txt_output.setPlainText(f"// Error: {str(e)}")
                self.lbl_status.setText(f"❌ Generation failed: {str(e)}")
                self.lbl_status.setStyleSheet("color: #ff5555; font-size: 8pt;")
            finally:
                self.btn_generate.setEnabled(True)
                self.btn_generate.setText("⚡ GENERATE SCRIPT")

        loop = asyncio.get_event_loop()
        future = asyncio.ensure_future(_run())
        future.add_done_callback(_done)

    def _on_refine(self):
        """Refine the generated script using console results."""
        current_script = self.txt_output.toPlainText().strip()
        results = self.txt_results.toPlainText().strip()

        if not current_script:
            self.lbl_status.setText("⚠️ Generate a script first!")
            self.lbl_status.setStyleSheet("color: #ff5555; font-size: 8pt;")
            return

        if not results:
            self.lbl_status.setText("⚠️ Paste the console output results above!")
            self.lbl_status.setStyleSheet("color: #ff5555; font-size: 8pt;")
            return

        if not self._ensure_ai():
            self.lbl_status.setText("⚠️ Enter your Groq API key above!")
            self.lbl_status.setStyleSheet("color: #ff5555; font-size: 8pt;")
            return

        script_type = self._type_map.get(self.combo_type.currentText(), "full_recon")
        refine_instr = self.txt_refine_instr.text().strip()

        # Update UI
        self.btn_refine.setEnabled(False)
        self.btn_refine.setText("⏳ REFINING...")
        self.lbl_status.setText("AI is analyzing results and improving the script...")
        self.lbl_status.setStyleSheet("color: #ff9d00; font-size: 8pt;")

        import asyncio

        async def _run():
            try:
                result = await self.ai_assistant.refine_script(
                    current_script, results, script_type, refine_instr
                )
                return result
            except Exception as e:
                return f"// Refine Error: {str(e)}"

        def _done(future):
            try:
                result = future.result()
                self.txt_output.setPlainText(result)
                lines = result.count('\n') + 1
                self.lbl_status.setText(f"🔄 Script refined! ({len(result)} chars, {lines} lines)")
                self.lbl_status.setStyleSheet("color: #ff9d00; font-size: 8pt;")
            except Exception as e:
                self.lbl_status.setText(f"❌ Refinement failed: {str(e)}")
                self.lbl_status.setStyleSheet("color: #ff5555; font-size: 8pt;")
            finally:
                self.btn_refine.setEnabled(True)
                self.btn_refine.setText("🔄 REFINE SCRIPT")

        future = asyncio.ensure_future(_run())
        future.add_done_callback(_done)

    def _copy_output(self):
        text = self.txt_output.toPlainText()
        if text:
            from PySide6.QtWidgets import QApplication
            try:
                QApplication.clipboard().setText(text)
                self.lbl_status.setText("✅ Copied to clipboard!")
                self.lbl_status.setStyleSheet("color: #00ff9d; font-size: 8pt;")
            except Exception as e:
                self.lbl_status.setText("⚠️ Clipboard locked by OS.")
                self.lbl_status.setStyleSheet("color: #ffaa00; font-size: 8pt;")

    def _clear_all(self):
        self.txt_audit_input.clear()
        self.txt_output.clear()
        self.txt_results.clear()
        self.txt_extra.clear()
        self.lbl_status.setText("")

class AMSIWidget(QWidget):
    """AMSI & WAF Analyzer Tool: Safely probes for integrated endpoint defenses."""

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # Header
        header = QLabel("🛡️ AMSI & WAF ANALYZER  —  DEFENSE PROBING ENGINE")
        header.setStyleSheet("color: #00f3ff; font-weight: bold; font-size: 13pt; letter-spacing: 2px;")
        layout.addWidget(header)

        info = QLabel(
            "Safely injects industry-standard test signatures (e.g., EICAR, AMSI triggers) into HTTP headers and payloads "
            "to behaviorally map the presence of Antimalware Scan Interface (AMSI) and Web Application Firewalls. "
            "Does not execute exploits."
        )
        info.setWordWrap(True)
        info.setStyleSheet("color: #aaa; font-size: 9pt; margin-bottom: 5px;")
        layout.addWidget(info)

        # Input Row
        input_row = QHBoxLayout()
        
        lbl_target = QLabel("TARGET URL:")
        lbl_target.setStyleSheet("color: #00ff9d; font-weight: bold; font-size: 9pt;")
        
        self.txt_target = QLineEdit()
        self.txt_target.setPlaceholderText("https://target.gov/api")
        self.txt_target.setStyleSheet("""
            QLineEdit {
                background-color: rgba(0, 0, 0, 0.4);
                color: #fff;
                border: 1px solid rgba(0, 243, 255, 0.4);
                border-radius: 4px;
                padding: 8px;
                font-size: 10pt;
            }
            QLineEdit:focus { border: 1px solid #00f3ff; }
        """)

        input_row.addWidget(lbl_target)
        input_row.addWidget(self.txt_target, 1)
        layout.addLayout(input_row)

        # Action Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setContentsMargins(0, 10, 0, 10) # Add vertical breathing room
        
        self.btn_analyze = GlowButton("🔍 RUN DEFENSE AUDIT", "#00f3ff")
        self.btn_analyze.setMinimumHeight(40)  # Ensure button isn't squashed
        self.btn_analyze.clicked.connect(self._run_audit)
        
        self.lbl_status = QLabel("")
        
        btn_layout.addWidget(self.btn_analyze)
        btn_layout.addWidget(self.lbl_status, 1)
        layout.addLayout(btn_layout)

        # Output Terminal
        lbl_out = QLabel("🕵️ DETECTED PROFILES:")
        lbl_out.setStyleSheet("color: #00f3ff; font-weight: bold; font-size: 10pt;")
        layout.addWidget(lbl_out)

        self.txt_output = QTextEdit()
        self.txt_output.setReadOnly(True)
        self.txt_output.setStyleSheet("""
            QTextEdit {
                background-color: rgba(10, 15, 20, 0.9);
                color: #00f3ff;
                border: 1px solid rgba(0, 243, 255, 0.3);
                border-radius: 8px;
                font-family: 'Consolas', monospace;
                font-size: 9pt;
                padding: 10px;
            }
        """)
        layout.addWidget(self.txt_output, 1)

    def _run_audit(self):
        target = self.txt_target.text().strip()
        if not target:
            self.lbl_status.setText("⚠️ Enter a valid target URL!")
            self.lbl_status.setStyleSheet("color: #ff5555; font-size: 9pt;")
            return
            
        if not target.startswith("http"):
            target = "https://" + target
            self.txt_target.setText(target)

        self.btn_analyze.setEnabled(False)
        self.btn_analyze.setText("⏳ AUDITING...")
        self.lbl_status.setText("Injecting harmless signatures and waiting for endpoint response...")
        self.lbl_status.setStyleSheet("color: #ffcc00; font-size: 9pt;")
        
        # We must run the aiohttp probe in the background asyncio loop
        import asyncio
        import aiohttp
        from core.amsi_analyzer import AMSIAnalyzer
        
        async def _probe():
            try:
                # Use a short-lived session for the tool
                async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                    analyzer = AMSIAnalyzer(session)
                    results = await analyzer.run_detection(target)
                    report = analyzer.format_report(results)
                    return True, report
            except Exception as e:
                return False, str(e)

        def _done(future):
            try:
                success, data = future.result()
                if success:
                    self.txt_output.append(f"====== AUDIT: {target} ======\n{data}\n")
                    self.lbl_status.setText("✅ Reconnaissance complete.")
                    self.lbl_status.setStyleSheet("color: #00ff9d; font-size: 9pt;")
                else:
                    self.txt_output.append(f"[!] Engine Error -> {data}\n")
                    self.lbl_status.setText("❌ Connection failed.")
                    self.lbl_status.setStyleSheet("color: #ff5555; font-size: 9pt;")
            except Exception as e:
                self.lbl_status.setText(f"❌ Error: {str(e)}")
            finally:
                self.btn_analyze.setEnabled(True)
                self.btn_analyze.setText("🔍 RUN DEFENSE AUDIT")
                
        future = asyncio.ensure_future(_probe())
        future.add_done_callback(_done)


class MarauderWidget(QFrame):
    """
    Dedicated widget for Nexus Marauder (Automated Purchase & CVV Handling).
    Provides a separate interface for inventory depletion and secure checkout.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("QFrame { background-color: rgba(15, 20, 25, 0.7); border-radius: 12px; }")
        self.scanner = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        title = QLabel("☠ NEXUS MARAUDER: INVENTORY DEPLETION SUITE")
        title.setStyleSheet("color: #ff0055; font-size: 16pt; font-weight: 800; letter-spacing: 2px;")
        layout.addWidget(title)
        
        desc = QLabel("Escalate access from login to automated checkout. Optimized for high-value asset depletion.")
        desc.setStyleSheet("color: #888; font-size: 10pt; margin-bottom: 10px;")
        layout.addWidget(desc)

        # Inputs Grid
        input_grid = QVBoxLayout()
        input_grid.setSpacing(10)

        self.txt_url = self._create_input("TARGET URL:", "https://target-store.com/login")
        self.txt_product = self._create_input("TARGET PRODUCT (HUNT):", "iPhone 17 Pro Max")
        self.txt_user = self._create_input("USERNAME / EMAIL:", "admin@target.com")
        self.txt_pass = self._create_input("PASSWORD:", "********", is_password=True)
        self.txt_bypass_email = self._create_input("BYPASS REDIRECT EMAIL:", "your-hacker-mail@mail.com")
        
        # Payment Row
        payment_title = QLabel("💳 PAYMENT INSTRUMENT (SECURE INJECTION)")
        payment_title.setStyleSheet("color: #00ff9d; font-weight: bold; margin-top: 10px;")
        layout.addWidget(payment_title)

        self.txt_card = self._create_input("CARD NUMBER:", "4111 1111 1111 1111")
        
        expiry_cvv = QHBoxLayout()
        self.txt_expiry = self._create_input("EXPIRY (MM/YY):", "12/26")
        self.txt_cvv = self._create_input("CVV / CVC:", "XXX")
        expiry_cvv.addWidget(self.txt_expiry)
        expiry_cvv.addWidget(self.txt_cvv)

        layout.addLayout(input_grid)
        layout.addWidget(self.txt_url)
        layout.addWidget(self.txt_product)
        layout.addWidget(self.txt_user)
        layout.addWidget(self.txt_pass)
        layout.addWidget(self.txt_bypass_email)
        layout.addWidget(self.txt_card)
        layout.addLayout(expiry_cvv)

        # Automation Status
        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setPlaceholderText("AUTOMATION LOG: Waiting for engagement...")
        self.txt_log.setStyleSheet("""
            QTextEdit {
                background-color: #050505;
                color: #ff0055;
                font-family: 'Consolas', monospace;
                border: 1px solid #333;
                border-radius: 4px;
                padding: 10px;
            }
        """)
        layout.addWidget(self.txt_log, 1)

        # Engagement Buttons
        btn_layout = QHBoxLayout()
        self.btn_engage = GlowButton("☠ ENGAGE MARAUDER", "#ff0055")
        self.btn_engage.setMinimumHeight(50)
        self.btn_engage.clicked.connect(self._start_sequence)
        
        self.btn_abort = GlowButton("ABORT", "#aaaaaa")
        self.btn_abort.setMinimumHeight(50)
        self.btn_abort.setEnabled(False)
        self.btn_abort.clicked.connect(self._abort_sequence)
        
        btn_layout.addWidget(self.btn_engage, 2)
        btn_layout.addWidget(self.btn_abort, 1)
        layout.addLayout(btn_layout)

    def _create_input(self, label_text, placeholder, is_password=False):
        container = QWidget()
        lay = QVBoxLayout(container)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(5)
        
        lbl = QLabel(label_text)
        lbl.setStyleSheet("color: #00f3ff; font-weight: bold; font-size: 8pt;")
        
        edit = QLineEdit()
        edit.setPlaceholderText(placeholder)
        if is_password: edit.setEchoMode(QLineEdit.Password)
        edit.setStyleSheet("""
            QLineEdit {
                background-color: rgba(255, 255, 255, 0.05);
                color: white;
                border: 1px solid #333;
                border-radius: 4px;
                padding: 10px;
            }
            QLineEdit:focus { border: 1px solid #ff0055; }
        """)
        lay.addWidget(lbl)
        lay.addWidget(edit)
        return container

    def _start_sequence(self):
        url = self.txt_url.findChildren(QLineEdit)[0].text().strip()
        product = self.txt_product.findChildren(QLineEdit)[0].text().strip() or "iPhone 17 Pro Max"
        user = self.txt_user.findChildren(QLineEdit)[0].text().strip()
        pwd = self.txt_pass.findChildren(QLineEdit)[0].text().strip()
        bypass_email = self.txt_bypass_email.findChildren(QLineEdit)[0].text().strip()
        card = self.txt_card.findChildren(QLineEdit)[0].text().strip()
        expiry = self.txt_expiry.findChildren(QLineEdit)[0].text().strip()
        cvv = self.txt_cvv.findChildren(QLineEdit)[0].text().strip()

        if not url:
            self.txt_log.append("<span style='color:#ff5555'>[!] Target URL is required.</span>")
            return

        self.btn_engage.setEnabled(False)
        self.btn_abort.setEnabled(True)
        self.txt_log.append(f"<span style='color:#00f3ff'>[!] ENGAGING NEXUS MARAUDER: {url}</span>")

        # Persistent Scanner Management
        if not self.scanner:
            from core.browser_scanner import BrowserScanner
            self.scanner = BrowserScanner(url, headless=False)
            self.scanner.log_message.connect(self._append_to_log)
        
        self.txt_log.append("<span style='color:#ff0055'>[*] Pre-flight configuration finalized. Initializing Engine...</span>")

        async def _run():
            try:
                # Lazy Init: only start if closed or new url
                if not self.scanner.page or self.scanner.target_url != url:
                    if self.scanner.page: await self.scanner.close()
                    self.scanner.target_url = url
                    await self.scanner.initialize()
                
                await self.scanner.run_marauder_sequence(url, user, pwd, target_product=product, bypass_email=bypass_email)
                await self.scanner._marauder_checkout(card, expiry, cvv)
                self.txt_log.append("<span style='color:#00ff9d'>[Marauder] Depletion sequence finalized.</span>")
            except Exception as e:
                self.txt_log.append(f"<span style='color:#ff5555'>[!] Marauder Crash: {str(e)}</span>")
            finally:
                self.btn_engage.setEnabled(True)
                self.btn_abort.setEnabled(False)

        asyncio.ensure_future(_run())

    def _abort_sequence(self):
        """Forcefully kills the browser and stops the sequence."""
        if self.scanner:
            self.txt_log.append("<span style='color:#ffaa00'>[!] ABORTING: Closing browser instances...</span>")
            asyncio.ensure_future(self.scanner.close())
        self.btn_engage.setEnabled(True)
        self.btn_abort.setEnabled(False)

    def _append_to_log(self, msg):
        # Handle HTML logs
        self.txt_log.append(msg)
        # Scroll to bottom
        self.txt_log.verticalScrollBar().setValue(self.txt_log.verticalScrollBar().maximum())

