from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
    QTextEdit, QProgressBar, QFrame, QTableWidget, QTableWidgetItem, QHeaderView
)
from PySide6.QtCore import Qt, QThread, Signal, Slot
from gui.widgets import GlowButton
import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from collections import Counter

class XssScanWorker(QThread):
    log_signal = Signal(str)
    result_signal = Signal(dict)
    progress_signal = Signal(int)
    finished_signal = Signal()

    def __init__(self, url):
        super().__init__()
        self.url = url
        self.is_running = True
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "\"'><script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
        ]

    def run(self):
        try:
            self.log_signal.emit(f"<span style='color:#00F3FF'>[*] Analyzing {self.url}...</span>")
            response = requests.get(self.url, timeout=10)
            soup = bs(response.content, "html.parser")
            forms = soup.find_all("form")
            
            if not forms:
                self.log_signal.emit("<span style='color:#ffcc00'>[!] No forms found on the page.</span>")
                self.finished_signal.emit()
                return

            self.log_signal.emit(f"<span style='color:#00ff9d'>[+] Found {len(forms)} form(s). Testing payloads...</span>")
            
            total_tests = len(forms) * len(self.xss_payloads)
            current_test = 0

            for i, form in enumerate(forms):
                if not self.is_running: break
                
                details = self.get_form_details(form)
                action = details.get("action")
                target_url = urljoin(self.url, action) if action else self.url
                
                self.log_signal.emit(f"[*] Testing form #{i+1} at {action or 'root'}")

                for payload in self.xss_payloads:
                    if not self.is_running: break
                    
                    current_test += 1
                    self.progress_signal.emit(int((current_test / total_tests) * 100))
                    
                    res = self.test_xss(target_url, details, payload)
                    if res and res["reflected"]:
                        self.result_signal.emit(res)
                        self.log_signal.emit(f"<span style='color:#ff0055'>[!] VULNERABLE: {payload[:30]}...</span>")

            self.finished_signal.emit()
        except Exception as e:
            self.log_signal.emit(f"<span style='color:#ff0055'>[!] Critical Error: {str(e)}</span>")
            self.finished_signal.emit()

    def get_form_details(self, form):
        details = {}
        action = form.attrs.get("action", "")
        method = form.attrs.get("method", "get").lower()
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            inputs.append({"type": input_type, "name": input_name})
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details

    def test_xss(self, target_url, details, payload):
        data = {}
        for inp in details["inputs"]:
            if inp["type"] in ["text", "search", "email"]:
                data[inp["name"]] = payload
            else:
                data[inp["name"]] = "test"
        
        try:
            if details["method"] == "post":
                res = requests.post(target_url, data=data, timeout=5)
            else:
                res = requests.get(target_url, params=data, timeout=5)
            
            return {
                "url": target_url,
                "payload": payload,
                "reflected": payload in res.text,
                "status": res.status_code
            }
        except:
            return None

    def stop(self):
        self.is_running = False

class XssScanWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        
        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)

        # Header
        title = QLabel("💉 XSS VULNERABILITY SCANNER")
        title.setStyleSheet("color: #FFFFFF; font-weight: 800; font-size: 24pt; letter-spacing: -1px;")
        layout.addWidget(title)
        
        desc = QLabel("Scan web forms for Cross-Site Scripting (XSS) vulnerabilities. Includes automated payload injection and reflection detection.")
        desc.setWordWrap(True)
        desc.setStyleSheet("color: rgba(255, 255, 255, 0.6); font-size: 11pt; line-height: 1.5;")
        layout.addWidget(desc)

        # Input Frame
        self.input_frame = QFrame()
        self.input_frame.setObjectName("ContentPanel")
        input_layout = QHBoxLayout(self.input_frame)
        input_layout.setContentsMargins(20, 20, 20, 20)
        input_layout.setSpacing(15)
        
        self.txt_url = QLineEdit()
        self.txt_url.setPlaceholderText("https://example.com/login")
        self.txt_url.setFixedHeight(50)
        
        self.btn_toggle = GlowButton("START XSS SCAN", "#00F3FF")
        self.btn_toggle.setFixedWidth(200)
        self.btn_toggle.setFixedHeight(50)
        self.btn_toggle.clicked.connect(self.toggle_scan)
        
        input_layout.addWidget(self.txt_url, 1)
        input_layout.addWidget(self.btn_toggle)
        layout.addWidget(self.input_frame)

        # Progress
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        # Split: Table + Console
        content_split = QHBoxLayout()
        
        # Results Table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(3)
        self.results_table.setHorizontalHeaderLabels(["TARGET URL", "PAYLOAD", "STATUS"])
        self.results_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.results_table.setShowGrid(False)
        self.results_table.setStyleSheet("background: transparent; border: none;")
        content_split.addWidget(self.results_table, 2)

        # Console
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        from gui.styles import LOG_STYLE
        self.console.setStyleSheet(LOG_STYLE)
        content_split.addWidget(self.console, 1)
        
        layout.addLayout(content_split)

    def log(self, text):
        self.console.append(text)
        sb = self.console.verticalScrollBar()
        sb.setValue(sb.maximum())

    def add_result(self, result):
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        url_item = QTableWidgetItem(result["url"])
        payload_item = QTableWidgetItem(result["payload"])
        status_item = QTableWidgetItem(f"Reflected ({result['status']})")
        status_item.setForeground(Qt.red)
        
        self.results_table.setItem(row, 0, url_item)
        self.results_table.setItem(row, 1, payload_item)
        self.results_table.setItem(row, 2, status_item)

    def toggle_scan(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.btn_toggle.setText("START XSS SCAN")
        else:
            url = self.txt_url.text().strip()
            if not url: return
            if not url.startswith("http"): url = "http://" + url
            
            self.console.clear()
            self.results_table.setRowCount(0)
            self.progress.setValue(0)
            self.progress.setVisible(True)
            
            self.worker = XssScanWorker(url)
            self.worker.log_signal.connect(self.log)
            self.worker.result_signal.connect(self.add_result)
            self.worker.progress_signal.connect(self.progress.setValue)
            self.worker.finished_signal.connect(self._on_finished)
            
            self.btn_toggle.setText("ABORT SCAN")
            self.worker.start()

    def _on_finished(self):
        self.btn_toggle.setText("START XSS SCAN")
        self.progress.setVisible(False)
        self.log(f"<span style='color:rgba(255,255,255,0.4)'>\n[#] XSS scan finalized.</span>")
