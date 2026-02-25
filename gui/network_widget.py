import json
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QLineEdit, 
    QPushButton, QProgressBar, QSplitter, QTreeWidget, QTreeWidgetItem, 
    QHeaderView, QTabWidget, QTableWidget, QTextEdit, QStatusBar, QMessageBox,
    QFileDialog, QApplication, QLabel, QTableWidgetItem
)
from PySide6.QtCore import Qt, QTimer, Slot
from PySide6.QtGui import QColor

# Local imports
from core.network_analyzer import NetworkAnalyzerCore
from core.database_dumper import DatabaseWorker
from gui.widgets import GlowButton

class NetworkAnalyzerWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

        # Worker threads
        self.analyzer = None
        self.db_worker = None
        self.running = False
        self.analysis_results = {}
        
        # Timer for progress simulation (if needed)
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_status)
        self.timer.start(1000)

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        # Header
        header = QLabel("NETWORK & DATABASE ANALYZER")
        header.setStyleSheet("font-size: 16pt; font-weight: bold; color: #00f3ff; font-family: 'Consolas';")
        layout.addWidget(header)

        # Target Configuration
        url_group = QGroupBox("Target Configuration")
        url_group.setStyleSheet("QGroupBox { border: 1px solid #445; border-radius: 5px; margin-top: 10px; font-weight: bold; color: #fff; } QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 3px 0 3px; }")
        url_layout = QHBoxLayout()
        url_label = QLabel("Target URL:")
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com")
        self.url_input.setStyleSheet("background-color: #1a1a2e; color: #fff; padding: 5px; border: 1px solid #334; border-radius: 3px;")
        
        url_layout.addWidget(url_label)
        url_layout.addWidget(self.url_input)
        url_group.setLayout(url_layout)
        layout.addWidget(url_group)

        # Controls
        control_group = QGroupBox("Controls")
        control_group.setStyleSheet(url_group.styleSheet())
        control_layout = QHBoxLayout()
        
        self.start_button = GlowButton("Start Full Analysis", "#00ff9d")
        self.stop_button = GlowButton("Stop Analysis", "#ff0055")
        self.stop_button.setEnabled(False)
        self.copy_button = GlowButton("Copy Results", "#00f3ff")
        self.save_button = GlowButton("Save Results", "#ff9d00")
        
        self.start_button.clicked.connect(self.start_analysis)
        self.stop_button.clicked.connect(self.stop_analysis)
        self.copy_button.clicked.connect(self.copy_results)
        self.save_button.clicked.connect(self.save_results)
        
        control_layout.addWidget(self.start_button)
        control_layout.addWidget(self.stop_button)
        control_layout.addWidget(self.copy_button)
        control_layout.addWidget(self.save_button)
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("QProgressBar { border: 1px solid #445; border-radius: 5px; text-align: center; color: white; } QProgressBar::chunk { background-color: #00ff9d; }")
        layout.addWidget(self.progress_bar)

        # Main content area (Splitter)
        splitter = QSplitter(Qt.Horizontal)
        splitter.setStyleSheet("QSplitter::handle { background-color: #445; margin: 2px; }")
        
        # Left panel - Routes Tree
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0,0,0,0)
        
        self.routes_tree = QTreeWidget()
        self.routes_tree.setHeaderLabels(["Route / Endpoint", "Method", "Status"])
        self.routes_tree.header().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.routes_tree.setStyleSheet("QTreeWidget { background-color: #111; color: #eee; border: 1px solid #334; } QHeaderView::section { background-color: #223; color: #00f3ff; border: 1px solid #334; font-weight: bold; }")
        left_layout.addWidget(self.routes_tree)
        splitter.addWidget(left_panel)
        
        # Right panel - Details
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0,0,0,0)
        
        self.detail_tabs = QTabWidget()
        self.detail_tabs.setStyleSheet("QTabWidget::pane { border: 1px solid #445; } QTabBar::tab { background: #223; color: #889; padding: 8px 15px; border-top-left-radius: 4px; border-top-right-radius: 4px; } QTabBar::tab:selected { background: #1a1a2e; color: #00f3ff; font-weight: bold; border: 1px solid #445; border-bottom: none; }")
        
        # URLs tab
        self.urls_tab = QWidget()
        urls_layout = QVBoxLayout(self.urls_tab)
        self.urls_table = QTableWidget()
        self.urls_table.setColumnCount(2)
        self.urls_table.setHorizontalHeaderLabels(["URL Resource", "Status"])
        self.urls_table.horizontalHeader().setStretchLastSection(True)
        self.urls_table.setStyleSheet(self.routes_tree.styleSheet())
        urls_layout.addWidget(self.urls_table)
        self.detail_tabs.addTab(self.urls_tab, "URLs / Subdomains")
        
        # Databses tab
        self.db_tab = QWidget()
        db_layout = QVBoxLayout(self.db_tab)
        self.db_tree = QTreeWidget()
        self.db_tree.setHeaderLabels(["Database Info", "Details"])
        self.db_tree.header().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.db_tree.setStyleSheet(self.routes_tree.styleSheet())
        db_layout.addWidget(self.db_tree)
        self.detail_tabs.addTab(self.db_tab, "DB / Credentials")

        # Vulnerabilities tab
        self.vulns_tab = QWidget()
        vulns_layout = QVBoxLayout(self.vulns_tab)
        self.vulns_table = QTableWidget()
        self.vulns_table.setColumnCount(1)
        self.vulns_table.setHorizontalHeaderLabels(["Vulnerability Check Issue"])
        self.vulns_table.horizontalHeader().setStretchLastSection(True)
        self.vulns_table.setStyleSheet(self.routes_tree.styleSheet())
        vulns_layout.addWidget(self.vulns_table)
        self.detail_tabs.addTab(self.vulns_tab, "Vulnerabilities")
        
        # Logs tab
        self.logs_tab = QWidget()
        logs_layout = QVBoxLayout(self.logs_tab)
        self.logs_text = QTextEdit()
        self.logs_text.setReadOnly(True)
        self.logs_text.setStyleSheet("background-color: #0b0b14; color: #a9b7c6; font-family: 'Consolas'; border: 1px solid #445;")
        logs_layout.addWidget(self.logs_text)
        self.detail_tabs.addTab(self.logs_tab, "Live Logs")
        
        right_layout.addWidget(self.detail_tabs)
        splitter.addWidget(right_panel)
        
        splitter.setSizes([400, 600])
        layout.addWidget(splitter)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.status_bar.setStyleSheet("color: #00ff9d; font-family: 'Consolas';")
        layout.addWidget(self.status_bar)

    @Slot()
    def start_analysis(self):
        target = self.url_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target URL.")
            return

        if self.running: return
        self.running = True
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setValue(0)
        self.status_bar.showMessage(f"Analysis started on {target}...")
        
        # Clear previous results
        self.routes_tree.clear()
        self.urls_table.setRowCount(0)
        self.vulns_table.setRowCount(0)
        self.db_tree.clear()
        self.logs_text.clear()
        self.analysis_results = {}
        
        # Start Network thread
        self.analyzer = NetworkAnalyzerCore(target)
        self.analyzer.status_update.connect(self.update_logs)
        self.analyzer.route_found.connect(self.add_route)
        self.analyzer.url_found.connect(self.add_url)
        self.analyzer.vulnerability_found.connect(self.add_vulnerability)
        self.analyzer.finished.connect(self.check_finished)
        self.analyzer.start()

        # Start Database thread
        self.db_worker = DatabaseWorker(target)
        self.db_worker.status_update.connect(self.update_logs)
        self.db_worker.data_dumped.connect(self.add_db_dump)
        self.db_worker.finished.connect(self.check_finished)
        self.db_worker.start()

    @Slot()
    def stop_analysis(self):
        if self.analyzer:
            self.analyzer.running = False
            self.analyzer.wait()
        if self.db_worker:
            self.db_worker.running = False
            self.db_worker.wait()
            
        self.running = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setValue(100)
        self.status_bar.showMessage("Analysis explicitly stopped.")
        self.update_logs("[SYSTEM] Analysis Aborted.")

    @Slot(str)
    def add_route(self, route):
        item = QTreeWidgetItem([route, "GET/POST", "Discovered"])
        self.routes_tree.addTopLevelItem(item)
        self.analysis_results[f"route_{hash(route)}"] = {"route": route, "method": "GET", "status": "Found"}

    @Slot(str)
    def add_url(self, url):
        row = self.urls_table.rowCount()
        self.urls_table.insertRow(row)
        self.urls_table.setItem(row, 0, QTableWidgetItem(url))
        self.urls_table.setItem(row, 1, QTableWidgetItem("Found"))
        self.analysis_results[f"url_{hash(url)}"] = {"url": url, "status": "Found"}

    @Slot(str)
    def add_vulnerability(self, vuln):
        row = self.vulns_table.rowCount()
        self.vulns_table.insertRow(row)
        self.vulns_table.setItem(row, 0, QTableWidgetItem(vuln))
        self.analysis_results[f"vuln_{hash(vuln)}"] = {"vulnerability": vuln}
        # Switch to tab to emphasize
        self.detail_tabs.setCurrentIndex(2)

    @Slot(dict)
    def add_db_dump(self, data):
        db_type = data.get('type', 'Unknown')
        host = data.get('host', 'Unknown')
        
        parent = QTreeWidgetItem([f"[{db_type.upper()}] {host}", "Database Dump"])
        self.db_tree.addTopLevelItem(parent)
        
        # Tables
        tables = data.get('tables', [])
        if tables:
            tables_item = QTreeWidgetItem(["Tables Included", f"{len(tables)} tables"])
            parent.addChild(tables_item)
            for t in tables:
                if isinstance(t, dict): # Supabase bypassed
                    tbl = QTreeWidgetItem([t.get('table', 'Unknown'), f"{len(t.get('data',[]))} rows extracted"])
                    tables_item.addChild(tbl)
                else:
                    tables_item.addChild(QTreeWidgetItem([str(t), ""]))
                    
        # Credentials
        creds = data.get('credentials', [])
        if creds:
            creds_item = QTreeWidgetItem(["Credentials Found", f"{len(creds)} pairs"])
            creds_item.setForeground(0, QColor("#ff0055"))
            parent.addChild(creds_item)
            for c in creds:
                ci = QTreeWidgetItem([str(c), ""])
                ci.setForeground(0, QColor("#ff0055"))
                creds_item.addChild(ci)

        self.analysis_results[f"db_{host}"] = data
        parent.setExpanded(True)
        self.update_logs(f"[DB] successfully dumped data from {db_type} at {host}")

    @Slot(str)
    def update_logs(self, message):
        self.logs_text.append(message)
        self.logs_text.verticalScrollBar().setValue(self.logs_text.verticalScrollBar().maximum())

    @Slot()
    def update_status(self):
        if self.running:
            # Fake progress loop if true progress isn't discrete
            curr = self.progress_bar.value()
            if curr < 95:
                self.progress_bar.setValue(curr + 1)

    @Slot()
    def check_finished(self):
        # Only true finish if both are done
        net_running = self.analyzer and self.analyzer.running
        db_running = self.db_worker and self.db_worker.running
        
        if not net_running and not db_running and self.running:
            self.running = False
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.progress_bar.setValue(100)
            self.status_bar.showMessage("All analyses completed.")
            self.update_logs("[SYSTEM] Network and Database Analysis Comprehensive Finish.")

    @Slot()
    def copy_results(self):
        if not self.analysis_results:
            QMessageBox.information(self, "No Data", "No data to copy")
            return
            
        try:
            text = json.dumps(self.analysis_results, indent=2)
            clipboard = QApplication.clipboard()
            clipboard.setText(text)
            QMessageBox.information(self, "Copied", "JSON Results copied to clipboard")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to copy: {str(e)}")

    @Slot()
    def save_results(self):
        if not self.analysis_results:
            QMessageBox.information(self, "No Data", "No data to save")
            return
            
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Analysis Results", "Network_DB_Dump.json", "JSON Files (*.json);;Text Files (*.txt)"
        )
        if not filename:
            return
            
        try:
            if filename.endswith(".json"):
                with open(filename, "w") as f:
                    json.dump(self.analysis_results, f, indent=2)
            else:
                text = "Type\tData\n"
                for key, data in self.analysis_results.items():
                    if "route" in data:
                        text += f"Route\t{data['route']}\n"
                    elif "url" in data:
                        text += f"URL\t{data['url']}\n"
                    elif "vulnerability" in data:
                        text += f"Vulnerability\t{data['vulnerability']}\n"
                    elif "tables" in data:
                        text += f"Database Dump\t{data.get('type')} at {data.get('host')} WITH {len(data.get('tables', []))} tables\n"
                with open(filename, "w") as f:
                    f.write(text)
                    
            QMessageBox.information(self, "Saved", f"Results saved to {filename}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save: {str(e)}")
