from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
    QTextEdit, QApplication, QFrame, QScrollArea
)
from PySide6.QtCore import Qt, QThread, Signal
from gui.widgets import GlowButton
import asyncio
import logging

from core.mirror_proxy import PlaywrightMirrorProxy

class MirrorWorker(QThread):
    log_signal = Signal(str)
    started_signal = Signal()
    stopped_signal = Signal()

    def __init__(self, target_url, port, fb_config):
        super().__init__()
        self.target_url = target_url
        self.port = port
        self.fb_config = fb_config # Configurações completas do Firebase
        self.proxy = None
        self.runner = None
        self.loop = None

    def run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        
        # Inicia o Proxy com as chaves de interceptação
        self.proxy = PlaywrightMirrorProxy(
            self.target_url, 
            port=self.port, 
            firebase_config=self.fb_config
        )
        
        # Redirecionamento de Logs para o Console do GUI
        class SignalHandler(logging.Handler):
            def __init__(self, signal):
                super().__init__()
                self.signal = signal
            def emit(self, record):
                msg = self.format(record)
                self.signal.emit(msg)
                
        logger = logging.getLogger("MirrorProxy")
        for h in logger.handlers[:]:
            logger.removeHandler(h)
        handler = SignalHandler(self.log_signal)
        handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
        logger.addHandler(handler)

        try:
            self.runner = self.loop.run_until_complete(self.proxy.start())
            self.started_signal.emit()
            self.log_signal.emit(f"<span style='color:#00ff9d'>[+] NEXUS CLONE ONLINE: http://localhost:{self.port}</span>")
            self.loop.run_forever()
        except Exception as e:
            self.log_signal.emit(f"<span style='color:#ff0055'>[!] Erro no Proxy: {e}</span>")
        finally:
            if self.runner:
                self.loop.run_until_complete(self.proxy.stop(self.runner))
            if self.loop.is_running():
                self.loop.stop()
            self.loop.close()
            self.stopped_signal.emit()

    def stop(self):
        if self.loop and self.loop.is_running():
            self.log_signal.emit("<span style='color:#ffcc00'>[-] Desmontando Mirror Local...</span>")
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.wait()

class MirrorWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # Título Nexus
        title = QLabel("🪞 NEXUS CLONE & INTERCEPT ENGINE")
        title.setStyleSheet("color: #b825ff; font-weight: bold; font-size: 14pt; letter-spacing: 2px;")
        layout.addWidget(title)

        # --- SEÇÃO FIREBASE CONFIG ---
        fb_frame = QFrame()
        fb_frame.setStyleSheet("background: rgba(10, 10, 20, 0.8); border: 1px solid #ff0055; border-radius: 8px; padding: 10px;")
        fb_layout = QVBoxLayout(fb_frame)
        
        fb_layout.addWidget(QLabel("🔥 FIREBASE SDK & REST CONFIG (sunshinecursos)"))
        
        # Grid para inputs do Firebase
        fb_grid = QHBoxLayout()
        self.txt_api_key = QLineEdit("AIzaSyDKL_tODwAIEnCq10-s5DRzFeHWsQLViOs")
        self.txt_db_url = QLineEdit("https://sunshinecursos-5f92a-default-rtdb.firebaseio.com")
        self.txt_db_secret = QLineEdit() # Necessário para o REST API Bypass
        self.txt_db_secret.setPlaceholderText("DATABASE_SECRET (Obrigatório)")
        self.txt_db_secret.setEchoMode(QLineEdit.Password)

        fb_grid.addWidget(self.txt_api_key)
        fb_grid.addWidget(self.txt_db_url)
        fb_grid.addWidget(self.txt_db_secret)
        fb_layout.addLayout(fb_grid)

        self.txt_project_id = QLineEdit("sunshinecursos-5f92a")
        fb_layout.addWidget(self.txt_project_id)
        layout.addWidget(fb_frame)

        # --- CONFIGURAÇÃO DO ALVO ---
        target_row = QHBoxLayout()
        self.txt_url = QLineEdit("https://exemplo.com")
        self.txt_port = QLineEdit("5000")
        self.txt_port.setFixedWidth(60)
        
        self.btn_toggle = GlowButton("START MIRROR", "#00ff9d")
        self.btn_toggle.clicked.connect(self.toggle_mirror)

        target_row.addWidget(QLabel("TARGET URL:"))
        target_row.addWidget(self.txt_url)
        target_row.addWidget(QLabel("PORT:"))
        target_row.addWidget(self.txt_port)
        target_row.addWidget(self.btn_toggle)
        layout.addLayout(target_row)

        # Console de Logs
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setStyleSheet("background: #000; color: #ccc; font-family: 'Consolas'; border: 1px solid #333;")
        layout.addWidget(self.console)

    def log(self, text):
        self.console.append(text)
        self.console.verticalScrollBar().setValue(self.console.verticalScrollBar().maximum())

    def toggle_mirror(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker = None
            self.btn_toggle.setText("START MIRROR")
            self.set_inputs_enabled(True)
        else:
            fb_config = {
                "apiKey": self.txt_api_key.text().strip(),
                "databaseURL": self.txt_db_url.text().strip(),
                "projectId": self.txt_project_id.text().strip(),
                "db_secret": self.txt_db_secret.text().strip()
            }
            
            if not fb_config["db_secret"]:
                self.log("<span style='color:#ffcc00'>[!] Erro: Database Secret é obrigatório para gravação.</span>")
                return

            self.console.clear()
            self.set_inputs_enabled(False)
            self.worker = MirrorWorker(self.txt_url.text(), int(self.txt_port.text()), fb_config)
            self.worker.log_signal.connect(self.log)
            self.worker.started_signal.connect(lambda: self.btn_toggle.setText("STOP MIRROR"))
            self.worker.start()

    def set_inputs_enabled(self, status):
        self.txt_url.setEnabled(status)
        self.txt_port.setEnabled(status)
        self.txt_api_key.setEnabled(status)
        self.txt_db_url.setEnabled(status)
        self.txt_db_secret.setEnabled(status)