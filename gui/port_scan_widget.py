from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
    QTextEdit, QProgressBar, QFrame, QScrollArea
)
from PySide6.QtCore import Qt, QThread, Signal, Slot
from gui.widgets import GlowButton
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
import threading

class PortScanWorker(QThread):
    log_signal = Signal(str)
    progress_signal = Signal(int)
    finished_signal = Signal(dict)

    def __init__(self, target, start_port, end_port):
        super().__init__()
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.is_running = True
        self.found_services = {}
        self._lock = threading.Lock()
        self._processed_count = 0

    def scan_single_port(self, port):
        if not self.is_running:
            return

        the_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        the_socket.settimeout(1.0) # Increased timeout slightly for reliable concurrent scans
        
        try:
            result = the_socket.connect_ex((self.target, port))
            if result == 0:
                banner = "Unknown Service"
                try:
                    the_socket.send(b"Hello\r\n")
                    data = the_socket.recv(1024)
                    if data:
                        banner = data.decode(errors='ignore').strip()
                except:
                    pass
                
                with self._lock:
                    self.found_services[port] = banner
                self.log_signal.emit(f"<span style='color:#00ff9d'>[+] Port {port} OPEN: {banner}</span>")
        except Exception as e:
            # Don't spam errors for every port in high-speed mode unless it's critical
            pass
        finally:
            the_socket.close()
            with self._lock:
                self._processed_count += 1
                total = self.end_port - self.start_port + 1
                progress = int((self._processed_count / total) * 100)
                self.progress_signal.emit(progress)

    def run(self):
        self.found_services = {}
        self._processed_count = 0
        ports = list(range(self.start_port, self.end_port + 1))
        
        # Explicitly wait for all tasks using futures to avoid race conditions on completion
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(self.scan_single_port, p) for p in ports]
            for future in futures:
                try:
                    future.result() # This blocks until the specific port scan is complete
                except:
                    pass
                
        print(f"[DEBUG] Scan complete. Found: {len(self.found_services)}")
        self.finished_signal.emit(self.found_services)

    def stop(self):
        self.is_running = False

class PortScanWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        
        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)

        # Header
        title = QLabel("⚒ PORT & SERVICE SCANNER")
        title.setStyleSheet("color: #FFFFFF; font-weight: 800; font-size: 24pt; letter-spacing: -1px;")
        layout.addWidget(title)

        desc = QLabel("Identify open ports and running services on a target host. Uses asynchronous socket connections for high performance.")
        desc.setWordWrap(True)
        desc.setStyleSheet("color: rgba(255, 255, 255, 0.6); font-size: 11pt; line-height: 1.5;")
        layout.addWidget(desc)

        # Input Frame (Glass)
        self.input_frame = QFrame()
        self.input_frame.setObjectName("ContentPanel")
        input_layout = QVBoxLayout(self.input_frame)
        input_layout.setSpacing(15)
        input_layout.setContentsMargins(20, 20, 20, 20)
        
        # Target
        lbl_target = QLabel("TARGET HOST (IP/DOMAIN)")
        lbl_target.setStyleSheet("color: #00F3FF; font-weight: bold; text-transform: uppercase; font-size: 9pt; letter-spacing: 1px;")
        self.txt_target = QLineEdit()
        self.txt_target.setPlaceholderText("e.g., 127.0.0.1 or scanme.nmap.org")
        input_layout.addWidget(lbl_target)
        input_layout.addWidget(self.txt_target)

        # Ports Row
        port_row = QHBoxLayout()
        
        v_start = QVBoxLayout()
        v_start.addWidget(QLabel("START PORT"))
        self.txt_start = QLineEdit("1")
        self.txt_start.setFixedWidth(100)
        v_start.addWidget(self.txt_start)
        
        v_end = QVBoxLayout()
        v_end.addWidget(QLabel("END PORT"))
        self.txt_end = QLineEdit("1024")
        self.txt_end.setFixedWidth(100)
        v_end.addWidget(self.txt_end)
        
        port_row.addLayout(v_start)
        port_row.addLayout(v_end)
        port_row.addStretch()
        
        self.btn_toggle = GlowButton("INITIALIZE SCAN", "#00F3FF")
        self.btn_toggle.setFixedWidth(220)
        self.btn_toggle.setFixedHeight(50)
        self.btn_toggle.clicked.connect(self.toggle_scan)
        port_row.addWidget(self.btn_toggle, alignment=Qt.AlignBottom)
        
        input_layout.addLayout(port_row)
        layout.addWidget(self.input_frame)

        # Progress
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        # Console
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        from gui.styles import LOG_STYLE
        self.console.setStyleSheet(LOG_STYLE)
        layout.addWidget(self.console, 1)

    def log(self, text):
        self.console.append(text)
        sb = self.console.verticalScrollBar()
        sb.setValue(sb.maximum())

    def toggle_scan(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.btn_toggle.setText("INITIALIZE SCAN")
        else:
            target = self.txt_target.text().strip()
            if not target: return

            # Sanitize target: remove protocol and trailing path
            if "://" in target:
                target = target.split("://")[1]
            if "/" in target:
                target = target.split("/")[0]
            if ":" in target: # Remove port if present
                target = target.split(":")[0]

            try:
                start_p = int(self.txt_start.text())
                end_p = int(self.txt_end.text())
            except:
                self.log("<span style='color:#ff0055'>[!] Invalid port range.</span>")
                return

            self.console.clear()
            self.progress.setValue(0)
            self.progress.setVisible(True)
            self.log(f"<span style='color:#FFFFFF'>[*] Starting scan on {target} ({start_p}-{end_p})...</span>")
            
            self.worker = PortScanWorker(target, start_p, end_p)
            self.worker.log_signal.connect(self.log)
            self.worker.progress_signal.connect(self.progress.setValue)
            self.worker.finished_signal.connect(self._on_finished)
            
            self.btn_toggle.setText("ABORT SCAN")
            self.worker.start()

    def _on_finished(self, results):
        self.btn_toggle.setText("INITIALIZE SCAN")
        self.progress.setVisible(False)
        self.log(f"<span style='color:rgba(255,255,255,0.4)'>\n[#] Scan complete. Found {len(results)} open ports.</span>")
