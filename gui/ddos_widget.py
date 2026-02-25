from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
    QComboBox, QSpinBox, QTextEdit, QCheckBox, QGroupBox,
    QMessageBox
)
from PySide6.QtCore import Slot, Qt
import sys
import os

from gui.widgets import GlowButton
from core.mhddos import MHDDoSAttack

class MHDDoSWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.attack_thread = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # Header
        header_layout = QHBoxLayout()
        header = QLabel("🔥 ATTACK PANEL [MHDDoS NATIVE]")
        header.setStyleSheet("color: #ff0055; font-weight: bold; font-size: 16pt; font-family: 'Consolas'; letter-spacing: 2px;")
        header_layout.addWidget(header)
        header_layout.addStretch()
        layout.addLayout(header_layout)

        desc = QLabel("Initialize Layer 4 & Layer 7 Stress Tests using the integrated MHDDoS engine.")
        desc.setStyleSheet("color: #aaa; font-size: 10pt;")
        layout.addWidget(desc)

        # Main Grid Layout for Config
        config_group = QGroupBox("Configuration")
        config_group.setStyleSheet("""
            QGroupBox { border: 1px solid #444; border-radius: 5px; margin-top: 10px; color: #ccc; font-weight: bold; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }
        """)
        config_layout = QVBoxLayout(config_group)
        
        # Row 1: Target & Method
        row1 = QHBoxLayout()
        
        lbl_target = QLabel("TARGET (URL/IP:PORT):")
        lbl_target.setStyleSheet("color: #00ff9d;")
        self.txt_target = QLineEdit()
        self.txt_target.setPlaceholderText("http://example.com or 1.1.1.1:80")
        self.txt_target.setStyleSheet("background-color: #111; color: #fff; border: 1px solid #334; padding: 6px;")
        
        lbl_method = QLabel("METHOD:")
        lbl_method.setStyleSheet("color: #ffcc00;")
        self.combo_method = QComboBox()
        self.combo_method.setStyleSheet("background-color: #111; color: #fff; border: 1px solid #334; padding: 6px;")
        self.combo_method.addItems([
            # Layer 7
            "GET", "POST", "OVH", "RHEX", "STOMP", "STRESS", "DYN", "DOWNLOADER", 
            "SLOW", "HEAD", "NULL", "COOKIE", "PPS", "EVEN", "GSB", "DGB", "AVB", 
            "BOT", "APACHE", "XMLRPC", "CFB", "CFBUAM", "BYPASS", "BOMB", "KILLER", "TOR",
            # Layer 4
            "TCP", "UDP", "SYN", "OVH-UDP", "CPS", "ICMP", "CONNECTION", "VSE", 
            "TS3", "FIVEM", "FIVEM-TOKEN", "MEM", "NTP", "MCBOT", "MINECRAFT", 
            "MCPE", "DNS", "CHAR", "CLDAP", "ARD", "RDP"
        ])
        
        row1.addWidget(lbl_target)
        row1.addWidget(self.txt_target)
        row1.addSpacing(15)
        row1.addWidget(lbl_method)
        row1.addWidget(self.combo_method)
        config_layout.addLayout(row1)

        # Row 2: Threads, Duration, Proxy Type
        row2 = QHBoxLayout()
        
        lbl_threads = QLabel("THREADS:")
        self.spin_threads = QSpinBox()
        self.spin_threads.setRange(1, 10000)
        self.spin_threads.setValue(100)
        self.spin_threads.setStyleSheet(self.txt_target.styleSheet())
        
        lbl_time = QLabel("TIME (s):")
        self.spin_time = QSpinBox()
        self.spin_time.setRange(1, 3600)
        self.spin_time.setValue(60)
        self.spin_time.setStyleSheet(self.txt_target.styleSheet())
        
        lbl_proxy = QLabel("PROXY TYPE:")
        self.combo_proxy = QComboBox()
        self.combo_proxy.addItems(["5", "4", "1", "0"]) # 5=SOCKS5, 4=SOCKS4, 1=HTTP, 0=ALL
        self.combo_proxy.setStyleSheet(self.combo_method.styleSheet())
        
        row2.addWidget(lbl_threads)
        row2.addWidget(self.spin_threads)
        row2.addSpacing(15)
        row2.addWidget(lbl_time)
        row2.addWidget(self.spin_time)
        row2.addSpacing(15)
        row2.addWidget(lbl_proxy)
        row2.addWidget(self.combo_proxy)
        config_layout.addLayout(row2)

        # Row 3: Proxy File & RPC
        row3 = QHBoxLayout()
        
        lbl_rpc = QLabel("RPC/Interval:")
        self.spin_rpc = QSpinBox()
        self.spin_rpc.setRange(1, 1000)
        self.spin_rpc.setValue(100)
        self.spin_rpc.setStyleSheet(self.txt_target.styleSheet())

        lbl_pfile = QLabel("PROXY FILE:")
        self.txt_pfile = QLineEdit()
        self.txt_pfile.setText("proxies.txt") 
        self.txt_pfile.setStyleSheet(self.txt_target.styleSheet())
        
        self.chk_debug = QCheckBox("DEBUG MODE")
        self.chk_debug.setStyleSheet("color: #ccc;")
        
        row3.addWidget(lbl_rpc)
        row3.addWidget(self.spin_rpc)
        row3.addSpacing(15)
        row3.addWidget(lbl_pfile)
        row3.addWidget(self.txt_pfile)
        row3.addSpacing(15)
        row3.addWidget(self.chk_debug)
        config_layout.addLayout(row3)
        
        layout.addWidget(config_group)
        
        # Actions
        btn_layout = QHBoxLayout()
        self.btn_start = GlowButton("☠ START ATTACK", "#ff0055")
        self.btn_start.clicked.connect(self.start_attack)
        
        self.btn_stop = GlowButton("STOP", "#888")
        self.btn_stop.clicked.connect(self.stop_attack)
        self.btn_stop.setEnabled(False)
        
        btn_layout.addWidget(self.btn_start)
        btn_layout.addWidget(self.btn_stop)
        layout.addLayout(btn_layout)
        
        # Console Output
        layout.addWidget(QLabel("ATTACK CONSOLE:"))
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setStyleSheet("background-color: #000; color: #0f0; font-family: 'Consolas'; font-size: 9pt; border: 1px solid #333;")
        layout.addWidget(self.console)

    @Slot()
    def start_attack(self):
        target = self.txt_target.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Please specify a Target URL or IP.")
            return

        method = self.combo_method.currentText()
        threads = str(self.spin_threads.value())
        duration = str(self.spin_time.value())
        socks_type = self.combo_proxy.currentText()
        proxy_file = self.txt_pfile.text().strip()
        rpc = str(self.spin_rpc.value())
        debug = "true" if self.chk_debug.isChecked() else "false"
        
        self.console.clear()
        self.console.append(f"<span style='color:yellow'>[*] Initializing attack on {target}...</span>")

        # Start Attack Thread
        self.attack_thread = MHDDoSAttack(
            method=method,
            url=target,
            threads=threads,
            duration=duration,
            proxy_type=socks_type,
            proxy_file=proxy_file,
            rpc=rpc,
            debug=debug
        )
        
        self.attack_thread.log_signal.connect(self.console.append)
        self.attack_thread.stop_signal.connect(self.attack_finished)
        self.attack_thread.start()
        
        # UI State Updates
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.btn_stop.setStyleSheet("background-color: #ff0000; color: white;")
        
        self.txt_target.setEnabled(False)
        self.combo_method.setEnabled(False)
        self.spin_threads.setEnabled(False)
        self.spin_time.setEnabled(False)
        self.combo_proxy.setEnabled(False)
        self.txt_pfile.setEnabled(False)
        self.spin_rpc.setEnabled(False)
        self.chk_debug.setEnabled(False)

    @Slot()
    def stop_attack(self):
        if self.attack_thread and self.attack_thread.isRunning():
            self.console.append("<span style='color:orange'>[!] Stopping attack...</span>")
            self.attack_thread.stop()
            self.attack_thread.wait()
        
    def attack_finished(self):
        self.console.append("<span style='color:cyan'>[#] Attack Finished.</span>")
        
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.btn_stop.setStyleSheet("background-color: #888; color: white;")

        self.txt_target.setEnabled(True)
        self.combo_method.setEnabled(True)
        self.spin_threads.setEnabled(True)
        self.spin_time.setEnabled(True)
        self.combo_proxy.setEnabled(True)
        self.txt_pfile.setEnabled(True)
        self.spin_rpc.setEnabled(True)
        self.chk_debug.setEnabled(True)
