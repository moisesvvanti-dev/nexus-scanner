from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
    QProgressBar, QTextEdit, QFileDialog, QSpinBox, QMessageBox
)
from PySide6.QtCore import Slot, Qt
import asyncio
import os

from gui.widgets import GlowButton
from core.downloader import AsyncDownloader

class DownloaderWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.downloader = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # Header
        header = QLabel("🌐 COMPLETE SITE DOWNLOADER (MIRROR)")
        header.setStyleSheet("color: #00f3ff; font-weight: bold; font-size: 16pt; font-family: 'Consolas'; letter-spacing: 2px;")
        layout.addWidget(header)
        
        desc = QLabel("Recursively download an entire website, including assets (CSS, JS, Images), and rewrite links for offline viewing.")
        desc.setStyleSheet("color: #aaa; font-size: 10pt;")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        # Form Layout
        form_layout = QVBoxLayout()
        form_layout.setSpacing(10)
        
        # 1. Target URL
        url_layout = QHBoxLayout()
        lbl_url = QLabel("TARGET URL:")
        lbl_url.setFixedWidth(100)
        lbl_url.setStyleSheet("color: #00ff9d; font-weight: bold;")
        self.txt_url = QLineEdit()
        self.txt_url.setPlaceholderText("https://example.com")
        self.txt_url.setStyleSheet("background-color: #111; color: #fff; border: 1px solid #334; padding: 8px;")
        url_layout.addWidget(lbl_url)
        url_layout.addWidget(self.txt_url)
        form_layout.addLayout(url_layout)

        # 2. Output Directory
        path_layout = QHBoxLayout()
        lbl_path = QLabel("SAVE TO:")
        lbl_path.setFixedWidth(100)
        lbl_path.setStyleSheet("color: #00ff9d; font-weight: bold;")
        self.txt_path = QLineEdit()
        self.txt_path.setText(os.path.join(os.getcwd(), "downloads_site"))
        self.txt_path.setStyleSheet(self.txt_url.styleSheet())
        btn_browse = GlowButton("📂", "#00f3ff")
        btn_browse.setFixedWidth(40)
        btn_browse.clicked.connect(self._browse_folder)
        path_layout.addWidget(lbl_path)
        path_layout.addWidget(self.txt_path)
        path_layout.addWidget(btn_browse)
        form_layout.addLayout(path_layout)
        
        # 3. Settings (Depth & Concurrency)
        settings_layout = QHBoxLayout()
        
        lbl_depth = QLabel("DEPTH:")
        lbl_depth.setStyleSheet("color: #ffcc00; font-weight: bold;")
        self.spin_depth = QSpinBox()
        self.spin_depth.setRange(1, 10)
        self.spin_depth.setValue(2)
        self.spin_depth.setStyleSheet("background-color: #111; color: #fff; border: 1px solid #334; padding: 5px;")
        
        lbl_conc = QLabel("THREADS:")
        lbl_conc.setStyleSheet("color: #ffcc00; font-weight: bold;")
        self.spin_conc = QSpinBox()
        self.spin_conc.setRange(1, 50)
        self.spin_conc.setValue(10)
        self.spin_conc.setStyleSheet(self.spin_depth.styleSheet())

        settings_layout.addWidget(lbl_depth)
        settings_layout.addWidget(self.spin_depth)
        settings_layout.addSpacing(20)
        settings_layout.addWidget(lbl_conc)
        settings_layout.addWidget(self.spin_conc)
        settings_layout.addStretch()
        form_layout.addLayout(settings_layout)

        layout.addLayout(form_layout)
        
        # Actions
        btn_layout = QHBoxLayout()
        self.btn_start = GlowButton("START DOWNLOAD", "#00ff9d")
        self.btn_start.clicked.connect(self.start_download)
        
        self.btn_stop = GlowButton("STOP", "#ff0055")
        self.btn_stop.clicked.connect(self.stop_download)
        self.btn_stop.setEnabled(False)
        
        btn_layout.addWidget(self.btn_start)
        btn_layout.addWidget(self.btn_stop)
        layout.addLayout(btn_layout)

        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Ready")
        self.progress_bar.setStyleSheet("QProgressBar { border: 1px solid #334; border-radius: 5px; text-align: center; } QProgressBar::chunk { background-color: #00ff9d; }")
        layout.addWidget(self.progress_bar)

        # Logs
        layout.addWidget(QLabel("DOWNLOAD LOGS:"))
        self.log_console = QTextEdit()
        self.log_console.setReadOnly(True)
        self.log_console.setStyleSheet("background-color: #0a0a12; color: #ccc; border: 1px solid #334; font-family: 'Consolas'; font-size: 9pt;")
        layout.addWidget(self.log_console)

    def _browse_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if folder:
            self.txt_path.setText(folder)

    @Slot()
    def start_download(self):
        url = self.txt_url.text().strip()
        path = self.txt_path.text().strip()
        depth = self.spin_depth.value()
        conc = self.spin_conc.value()

        if not url:
            QMessageBox.warning(self, "Error", "Please enter a Target URL.")
            return

        # UI Updates
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.txt_url.setEnabled(False)
        self.log_console.clear()
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Downloading... %v files")
        
        # Init Downloader
        self.downloader = AsyncDownloader(url, path, depth, conc)
        self.downloader.log_message.connect(self.log_message)
        self.downloader.progress_updated.connect(self.update_progress)
        self.downloader.finished.connect(self.on_finished)
        
        # Start Async
        asyncio.ensure_future(self.downloader.start_download())

    @Slot()
    def stop_download(self):
        if self.downloader:
            asyncio.ensure_future(self.downloader.stop())
        self.btn_stop.setEnabled(False)
        self.log_console.append("<span style='color:#ff5555'>[!] Stopping... please wait for active tasks to cancel.</span>")

    @Slot(str)
    def log_message(self, msg):
        self.log_console.append(msg)
        sb = self.log_console.verticalScrollBar()
        sb.setValue(sb.maximum())

    @Slot(int)
    def update_progress(self, count):
        self.progress_bar.setValue(count)

    @Slot()
    def on_finished(self):
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.txt_url.setEnabled(True)
        self.progress_bar.setFormat(f"Completed! ({self.progress_bar.value()} files)")
        QMessageBox.information(self, "Done", f"Download finished.\nFiles saved to: {self.txt_path.text()}")
