import webbrowser
import urllib.parse
import threading
import requests
import random
import time
import re
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QAbstractItemView, QMessageBox, QApplication, QFrame, QProgressBar,
    QComboBox, QFileDialog
)
from PySide6.QtCore import Qt, Slot, Signal, QTimer
import json
import os
from PySide6.QtGui import QColor, QBrush

try:
    from .widgets import GlowButton
except ImportError:
    from gui.widgets import GlowButton

# User-Agent pool for Google scraping
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
]

DORK_TABLE_STYLE = """
QTableWidget {
    background-color: rgba(8, 8, 20, 0.9);
    border: 1px solid rgba(0, 243, 255, 0.15);
    border-radius: 8px;
    gridline-color: rgba(0, 243, 255, 0.08);
    color: #ddd;
    font-size: 9pt;
}
QTableWidget::item {
    padding: 6px 10px;
    border-bottom: 1px solid rgba(0, 243, 255, 0.06);
}
QTableWidget::item:selected {
    background-color: rgba(0, 243, 255, 0.15);
    color: #fff;
}
QHeaderView::section {
    background-color: rgba(0, 20, 40, 0.9);
    color: #00f3ff;
    font-weight: bold;
    font-size: 8pt;
    letter-spacing: 2px;
    padding: 8px;
    border: none;
    border-bottom: 2px solid #00f3ff;
}
"""


class DorkWidget(QWidget):
    # Signal emitted from worker thread to update UI
    _analysis_result = Signal(int, str, str)  # row, status, color
    _analysis_progress = Signal(int, int)  # current, total
    _analysis_done = Signal()
    _log_message = Signal(str)  # log text for live console

    def __init__(self, parent=None):
        super().__init__(parent)
        self.ai_assistant = None
        self._analyzing = False
        self._stop_analysis = False
        self.init_ui()

        # Connect internal signals
        self._analysis_result.connect(self._on_analysis_result)
        self._analysis_progress.connect(self._on_analysis_progress)
        self._analysis_done.connect(self._on_analysis_done)
        self._log_message.connect(self._on_log_message)

    def init_ui(self):
        self.setObjectName("ContentPanel")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        # Header
        header = QLabel("🔍 GOOGLE DORK ANALYSIS ENGINE")
        header.setStyleSheet("font-size: 18pt; font-weight: bold; color: #00f3ff; font-family: 'Consolas'; letter-spacing: 3px;")
        layout.addWidget(header)

        desc = QLabel("Enter a target domain, auto-analyze dorks via Google, or use AI to generate custom dorks for deep recon.")
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #888; font-size: 9pt; border: none; background: transparent;")
        layout.addWidget(desc)

        # ═══════ TARGET INPUT ROW ═══════
        target_layout = QHBoxLayout()
        lbl_target = QLabel("🎯 TARGET:")
        lbl_target.setStyleSheet("color: #00ff9d; font-weight: bold; font-size: 10pt;")
        self.txt_target = QLineEdit()
        self.txt_target.setPlaceholderText("alvo.com.br")
        self.txt_target.setStyleSheet("font-size: 11pt; padding: 8px;")
        
        self.btn_load = GlowButton("⚡ LOAD DORKS", "#00ff9d")
        self.btn_load.clicked.connect(self.load_default_dorks)

        target_layout.addWidget(lbl_target)
        target_layout.addWidget(self.txt_target, 1)
        target_layout.addWidget(self.btn_load)
        layout.addLayout(target_layout)

        # ═══════ GROQ AI KEY ROW (built-in) ═══════
        ai_frame = QFrame()
        ai_frame.setStyleSheet("background-color: rgba(60, 40, 0, 0.3); border-radius: 5px; padding: 5px;")
        ai_layout = QHBoxLayout(ai_frame)

        lbl_ai = QLabel("🔑 GROQ KEY:")
        lbl_ai.setStyleSheet("color: #ffcc00; font-weight: bold; font-size: 9pt;")

        self.txt_groq_key = QLineEdit()
        self.txt_groq_key.setPlaceholderText("gsk_... (groq.com/keys — needed for AI dork generation)")
        self.txt_groq_key.setEchoMode(QLineEdit.Password)

        self.combo_model = QComboBox()
        self.combo_model.addItems([
            "llama-3.3-70b-versatile",
            "moonshotai/kimi-k2-instruct-0905",
            "meta-llama/llama-4-maverick-17b-128k",
            "llama-3.1-8b-instant",
            "qwen/qwen3-32b",
            "mixtral-8x7b-32768",
        ])
        self.combo_model.setFixedWidth(260)

        ai_layout.addWidget(lbl_ai)
        ai_layout.addWidget(self.txt_groq_key, 1)
        ai_layout.addWidget(self.combo_model)
        layout.addWidget(ai_frame)

        # ═══════ TABLE (5 columns now: Category, Description, Dork, Status, Action) ═══════
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["CATEGORY", "DESCRIPTION", "DORK QUERY", "STATUS", "ACTION"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table.setStyleSheet(DORK_TABLE_STYLE)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table, 3)

        # ═══════ PROGRESS BAR ═══════
        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setFormat("IDLE")
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        # ═══════ ACTION BUTTONS ═══════
        btn_layout = QHBoxLayout()
        
        self.btn_auto_analyze = GlowButton("🚀 AUTO-ANALYZE ALL", "#ff0055")
        self.btn_auto_analyze.clicked.connect(self.auto_analyze_all)

        self.btn_ai_gen = GlowButton("🤖 AI GENERATE DORKS", "#ffcc00")
        self.btn_ai_gen.clicked.connect(self.generate_ai_dorks)

        self.btn_copy_all = GlowButton("📋 COPY ALL", "#00f3ff")
        self.btn_copy_all.clicked.connect(self.copy_all_dorks)

        self.btn_copy_hits = GlowButton("📋 COPY HITS ONLY", "#00ff9d")
        self.btn_copy_hits.clicked.connect(self.copy_hits_only)
        
        self.btn_clear = GlowButton("🗑️ CLEAR", "#666")
        self.btn_clear.clicked.connect(self.clear_table)

        self.btn_import = GlowButton("📥 IMPORT", "#9b59b6")
        self.btn_import.clicked.connect(self.import_dorks_dialog)

        btn_layout.addWidget(self.btn_auto_analyze)
        btn_layout.addWidget(self.btn_ai_gen)
        btn_layout.addWidget(self.btn_import)
        btn_layout.addWidget(self.btn_copy_all)
        btn_layout.addWidget(self.btn_copy_hits)
        btn_layout.addStretch()
        btn_layout.addWidget(self.btn_clear)
        layout.addLayout(btn_layout)

        # ═══════ LIVE LOG CONSOLE ═══════
        from PySide6.QtWidgets import QTextEdit
        log_header = QLabel("◉ ANALYSIS LOG")
        log_header.setStyleSheet("color: #00f3ff; font-weight: bold; font-size: 9pt; letter-spacing: 2px;")
        layout.addWidget(log_header)

        self.log_console = QTextEdit()
        self.log_console.setReadOnly(True)
        self.log_console.setMaximumHeight(180)
        self.log_console.setStyleSheet("""
            QTextEdit {
                background-color: rgba(5, 5, 12, 0.95);
                color: #00ff9d;
                border: 1px solid rgba(0, 243, 255, 0.15);
                border-radius: 10px;
                font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace;
                font-size: 9pt;
                padding: 8px;
            }
        """)
        layout.addWidget(self.log_console, 1)

        # Status label
        self.lbl_status = QLabel("")
        self.lbl_status.setStyleSheet("color: #556; font-size: 8pt;")
        layout.addWidget(self.lbl_status)

        # Load initial dorks
        self.load_default_dorks()

    # ═══════════════════════════════════════════════════
    # DEFAULT DORK LIST (120+)
    # ═══════════════════════════════════════════════════
    def load_default_dorks(self):
        self.table.setRowCount(0)
        target = self.txt_target.text().strip()
        if not target:
            target = "{target}"
        else:
            target = target.replace("https://", "").replace("http://", "").split('/')[0]

        default_dorks = [
            # ═══════ INFO DISCLOSURE ═══════
            ("Info Disclosure", "Open Directory Listings", f'site:{target} intitle:"index of"'),
            ("Info Disclosure", "Parent Directory", f'site:{target} intitle:"index of" "parent directory"'),
            ("Info Disclosure", "Apache Server Status", f'site:{target} intitle:"Apache Status"'),
            ("Info Disclosure", "PHP Info Page", f'site:{target} ext:php intitle:phpinfo'),
            ("Info Disclosure", "Robots.txt Exposed", f'site:{target} inurl:robots.txt'),
            ("Info Disclosure", "Sitemap.xml", f'site:{target} inurl:sitemap.xml'),
            ("Info Disclosure", "Crossdomain.xml", f'site:{target} inurl:crossdomain.xml'),
            ("Info Disclosure", "Security.txt", f'site:{target} inurl:.well-known/security.txt'),
            ("Info Disclosure", "Server Version Headers", f'site:{target} intitle:"Apache" OR intitle:"nginx" "server at"'),
            ("Info Disclosure", "WSDL/Web Services", f'site:{target} ext:wsdl OR inurl:?wsdl'),
            ("Info Disclosure", "License Files", f'site:{target} inurl:license.txt OR inurl:LICENSE'),

            # ═══════ BACKUP FILES ═══════
            ("Backups", "Backup Extensions", f'site:{target} ext:bkf OR ext:bkp OR ext:bak OR ext:old OR ext:backup'),
            ("Backups", "Index of Backups", f'site:{target} intitle:"index of" "backup"'),
            ("Backups", "Database Dumps", f'site:{target} ext:sql OR ext:db OR ext:sqlite OR ext:mdb OR ext:dump'),
            ("Backups", "Compressed Archives", f'site:{target} ext:zip OR ext:tar OR ext:gz OR ext:tgz OR ext:rar OR ext:7z'),
            ("Backups", "WordPress Backup", f'site:{target} inurl:wp-content/backups'),
            ("Backups", "CMS Backups", f'site:{target} intitle:"index of" "wp-" OR "joomla" OR "drupal" ext:zip'),
            ("Backups", "Config Backups (.bak)", f'site:{target} inurl:config ext:bak OR ext:old'),

            # ═══════ ADMIN & LOGIN PANELS ═══════
            ("Admin Panels", "Admin/Login Pages", f'site:{target} inurl:admin OR inurl:login OR inurl:wp-admin'),
            ("Admin Panels", "Dashboard/Painel", f'site:{target} inurl:dashboard OR inurl:painel OR inurl:controlpanel'),
            ("Admin Panels", "Jenkins", f'site:{target} intitle:"Dashboard [Jenkins]"'),
            ("Admin Panels", "phpMyAdmin", f'site:{target} inurl:phpmyadmin'),
            ("Admin Panels", "Adminer", f'site:{target} inurl:adminer.php'),
            ("Admin Panels", "CMS Login", f'site:{target} inurl:wp-login.php OR inurl:administrator OR inurl:user/login'),
            ("Admin Panels", "cPanel / WHM", f'site:{target} inurl:2082 OR inurl:2083 OR inurl:2086'),
            ("Admin Panels", "Webmin", f'site:{target} intitle:"Webmin" inurl:10000'),
            ("Admin Panels", "Tomcat Manager", f'site:{target} intitle:"Tomcat" inurl:manager'),
            ("Admin Panels", "Django Admin", f'site:{target} inurl:/admin/ intitle:"Django"'),
            ("Admin Panels", "Magento Admin", f'site:{target} inurl:admin OR inurl:backend intitle:"Magento"'),

            # ═══════ PARAMETERS & INJECTION POINTS ═══════
            ("Parameters", "ID Parameter (SQLi)", f'site:{target} inurl:id='),
            ("Parameters", "User Parameter", f'site:{target} inurl:user= OR inurl:username='),
            ("Parameters", "Search/Query (XSS)", f'site:{target} inurl:q= OR inurl:search= OR inurl:query='),
            ("Parameters", "Page/File (LFI)", f'site:{target} inurl:page= OR inurl:file= OR inurl:path='),
            ("Parameters", "Category/Product IDs", f'site:{target} inurl:cat= OR inurl:product= OR inurl:item='),
            ("Parameters", "Redirect (Open Redirect)", f'site:{target} inurl:redirect= OR inurl:url= OR inurl:next= OR inurl:return='),
            ("Parameters", "Action/CMD", f'site:{target} inurl:action= OR inurl:cmd= OR inurl:do='),
            ("Parameters", "Download/Read (Traversal)", f'site:{target} inurl:download= OR inurl:read= OR inurl:fetch='),
            ("Parameters", "Sort/Order By (SQLi)", f'site:{target} inurl:sort= OR inurl:order= OR inurl:column='),
            ("Parameters", "Language/Locale", f'site:{target} inurl:lang= OR inurl:locale= OR inurl:language='),
            ("Parameters", "Template (SSTI)", f'site:{target} inurl:template= OR inurl:view= OR inurl:render='),
            ("Parameters", "Email Parameter", f'site:{target} inurl:email= OR inurl:mail= OR inurl:to='),
            ("Parameters", "Debug/Test", f'site:{target} inurl:debug= OR inurl:test= OR inurl:verbose='),

            # ═══════ E-COMMERCE ═══════
            ("E-Commerce", "Order/Pedido IDs", f'site:{target} inurl:pedido= OR inurl:order='),
            ("E-Commerce", "Cart/Checkout", f'site:{target} inurl:cart OR inurl:checkout OR inurl:carrinho'),
            ("E-Commerce", "Payment Pages", f'site:{target} inurl:payment OR inurl:pagamento OR inurl:pay'),
            ("E-Commerce", "Invoice/Receipt", f'site:{target} inurl:invoice OR inurl:receipt OR inurl:nota'),
            ("E-Commerce", "Coupon/Discount", f'site:{target} inurl:coupon= OR inurl:discount= OR inurl:promo='),

            # ═══════ SENSITIVE FILES ═══════
            ("Sensitive Files", "Documents (PDF/XLS/DOC)", f'site:{target} ext:pdf OR ext:xls OR ext:xlsx OR ext:csv OR ext:doc OR ext:docx'),
            ("Sensitive Files", "Spreadsheet + Passwords", f'site:{target} ext:xls OR ext:csv "password" OR "users" OR "email"'),
            ("Sensitive Files", "Financial/Budget", f'site:{target} ext:pdf OR ext:xls "financial" OR "budget" OR "salary"'),
            ("Sensitive Files", "Private Keys & Certs", f'site:{target} ext:pem OR ext:key OR ext:crt OR ext:cer OR ext:p12 OR ext:pfx'),
            ("Sensitive Files", "Passwd / Shadow", f'site:{target} inurl:passwd OR inurl:shadow OR inurl:htpasswd'),
            ("Sensitive Files", "SSH Config", f'site:{target} ext:conf "ssh" OR inurl:ssh_config'),

            # ═══════ LOG FILES ═══════
            ("Logs", "General Log Files", f'site:{target} ext:log'),
            ("Logs", "Error / Debug Logs", f'site:{target} ext:log "error" OR "exception" OR "stack trace"'),
            ("Logs", "Access Logs", f'site:{target} ext:log "GET /" OR "POST /" OR "200" OR "404"'),
            ("Logs", "Logs Directory", f'site:{target} inurl:log OR inurl:logs intitle:"index of"'),
            ("Logs", "Mail/SMTP Logs", f'site:{target} ext:log "smtp" OR "mail" OR "postfix"'),

            # ═══════ CONFIGURATION & SECRETS ═══════
            ("Configuration", "Config (INI/YAML/ENV)", f'site:{target} ext:env OR ext:conf OR ext:ini OR ext:yml OR ext:yaml'),
            ("Configuration", ".env Files (Secrets!)", f'site:{target} inurl:".env" "DB_PASSWORD" OR "APP_KEY" OR "SECRET"'),
            ("Configuration", "wp-config.php", f'site:{target} inurl:wp-config.php'),
            ("Configuration", "AWS Credentials", f'site:{target} "aws_access_key_id" OR "aws_secret_access_key"'),
            ("Configuration", "SSH Keys", f'site:{target} intitle:"index of" "id_rsa" OR "id_dsa"'),
            ("Configuration", "Docker/K8s YAML", f'site:{target} ext:yml "docker-compose" OR inurl:Dockerfile'),
            ("Configuration", "Firebase Config", f'site:{target} "apiKey" "authDomain" "databaseURL"'),
            ("Configuration", "Git Config", f'site:{target} inurl:".git/config"'),
            ("Configuration", "Terraform State", f'site:{target} ext:tfstate OR inurl:terraform'),
            ("Configuration", "NPM .npmrc / .npmignore", f'site:{target} inurl:.npmrc OR inurl:.npmignore'),
            ("Configuration", "Ansible Vault", f'site:{target} "$ANSIBLE_VAULT" OR ext:vault'),

            # ═══════ SOURCE CODE & METADATA ═══════
            ("Source Code", ".git Directory", f'site:{target} inurl:".git" intitle:"index of"'),
            ("Source Code", ".svn Directory", f'site:{target} inurl:".svn" intitle:"index of"'),
            ("Source Code", ".DS_Store", f'site:{target} inurl:".DS_Store"'),
            ("Source Code", "Source Archives", f'site:{target} ext:zip OR ext:tar intitle:"index of" "src"'),
            ("Source Code", ".htaccess Exposed", f'site:{target} inurl:.htaccess'),
            ("Source Code", "package.json / composer.json", f'site:{target} inurl:composer.json OR inurl:package.json'),
            ("Source Code", "Gemfile / requirements.txt", f'site:{target} inurl:Gemfile OR inurl:requirements.txt'),
            ("Source Code", "README.md", f'site:{target} inurl:README.md'),

            # ═══════ API KEYS & TOKENS ═══════
            ("API Keys", "Exposed API Keys", f'site:{target} "api_key" OR "apikey" OR "api_secret"'),
            ("API Keys", "OAuth Tokens", f'site:{target} "access_token" OR "client_secret" OR "client_id"'),
            ("API Keys", "JWT Tokens", f'site:{target} "eyJhbG"'),
            ("API Keys", "Stripe/Payment Keys", f'site:{target} "sk_live_" OR "pk_live_" OR "rk_live_"'),
            ("API Keys", "Google Maps Key", f'site:{target} "AIza" ext:js OR ext:json'),
            ("API Keys", "Slack Token", f'site:{target} "xoxb-" OR "xoxp-" OR "xoxs-"'),
            ("API Keys", "GitHub Token", f'site:{target} "ghp_" OR "github_pat_"'),
            ("API Keys", "Mailgun/Sendgrid Key", f'site:{target} "key-" "api.mailgun.net" OR "SG."'),

            # ═══════ ERROR MESSAGES ═══════
            ("Errors", "SQL Errors (MySQL)", f'site:{target} "You have an error in your SQL syntax"'),
            ("Errors", "SQL Errors (PostgreSQL)", f'site:{target} "ERROR: syntax error at or near"'),
            ("Errors", "PHP Errors", f'site:{target} "Fatal error:" "on line" ext:php'),
            ("Errors", "ASP.NET Errors", f'site:{target} "Server Error in" "Application"'),
            ("Errors", "Stack Traces", f'site:{target} "Stack trace:" OR "Traceback (most recent call"'),
            ("Errors", "Debug Mode Enabled", f'site:{target} "DEBUG = True" OR "DJANGO_DEBUG"'),
            ("Errors", "Laravel Debug", f'site:{target} "Whoops!" "Laravel"'),
            ("Errors", "Spring Boot Error", f'site:{target} "Whitelabel Error Page" "Spring"'),

            # ═══════ IoT / CAMERAS ═══════
            ("IoT/Cameras", "IP Cameras", f'site:{target} inurl:"/view/view.shtml" OR intitle:"Live View"'),
            ("IoT/Cameras", "MikroTik/RouterOS", f'site:{target} intitle:"RouterOS" OR intitle:"MikroTik"'),
            ("IoT/Cameras", "Printer Panels", f'site:{target} intitle:"HP" "Web Jetadmin"'),

            # ═══════ EXPOSED SERVICES ═══════
            ("Services", "Elasticsearch", f'site:{target} intitle:"Elasticsearch"'),
            ("Services", "Kibana", f'site:{target} inurl:app/kibana'),
            ("Services", "Grafana", f'site:{target} intitle:"Grafana"'),
            ("Services", "Swagger/API Docs", f'site:{target} inurl:swagger OR inurl:api-docs'),
            ("Services", "GraphQL Playground", f'site:{target} inurl:graphql OR inurl:graphiql'),
            ("Services", "MongoDB Web", f'site:{target} intitle:"mongod" OR inurl:28017'),
            ("Services", "Redis Commander", f'site:{target} intitle:"Redis Commander"'),
            ("Services", "RabbitMQ Management", f'site:{target} intitle:"RabbitMQ Management"'),
            ("Services", "MinIO Console", f'site:{target} intitle:"MinIO" inurl:login'),
            ("Services", "GitLab/Gitea", f'site:{target} intitle:"GitLab" OR intitle:"Gitea"'),
            ("Services", "Portainer", f'site:{target} intitle:"Portainer"'),
            ("Services", "SonarQube", f'site:{target} intitle:"SonarQube"'),

            # ═══════ BACKDOORS & SHELLS ═══════
            ("Backdoors", "Web Shells", f'site:{target} inurl:shell OR inurl:cmd OR inurl:exec'),
            ("Backdoors", "Known Shells (b374k/c99)", f'site:{target} intitle:"b374k" OR intitle:"c99" OR intitle:"r57"'),
            ("Backdoors", "File Upload Pages", f'site:{target} inurl:upload OR inurl:fileupload'),
            ("Backdoors", "Reverse Shell Scripts", f'site:{target} "reverse shell" OR "bind shell" ext:py OR ext:php'),

            # ═══════ CLOUD MISCONFIG ═══════
            ("Cloud", "S3 Bucket Exposed", f'site:{target} "s3.amazonaws.com" OR "s3-" ".amazonaws.com"'),
            ("Cloud", "Azure Blob Storage", f'site:{target} ".blob.core.windows.net"'),
            ("Cloud", "Google Cloud Storage", f'site:{target} "storage.googleapis.com"'),
            ("Cloud", "DigitalOcean Spaces", f'site:{target} ".digitaloceanspaces.com"'),

            # ═══════ SUBDOMAIN RECON ═══════
            ("Subdomains", "All Indexed Subdomains", f'site:*.{target}'),
            ("Subdomains", "Dev/Staging", f'site:*.{target} inurl:dev OR inurl:staging OR inurl:test'),
            ("Subdomains", "API Subdomains", f'site:*.{target} inurl:api'),
            ("Subdomains", "Mail Subdomains", f'site:*.{target} inurl:mail OR inurl:webmail OR inurl:smtp'),

            # ═══════ CACHED / INDEXED ═══════
            ("Recon", "Google Cached Pages", f'cache:{target}'),
            ("Recon", "Related Sites", f'related:{target}'),

            # ═══════ SOCIAL ENGINEERING ═══════
            ("Social Eng", "Email Addresses", f'site:{target} intext:"@{target}"'),
            ("Social Eng", "Phone/Contact Info", f'site:{target} "phone" OR "tel" OR "contact" OR "whatsapp"'),
            ("Social Eng", "LinkedIn Employees", f'site:linkedin.com "{target}"'),
            ("Social Eng", "GitHub Mentions", f'site:github.com "{target}"'),
            ("Social Eng", "Pastebin Leaks", f'site:pastebin.com "{target}"'),

            # ═══════ WORDPRESS SPECIFIC ═══════
            ("WordPress", "WP Plugins Dir", f'site:{target} inurl:wp-content/plugins'),
            ("WordPress", "WP Uploads Dir", f'site:{target} inurl:wp-content/uploads intitle:"index of"'),
            ("WordPress", "WP User Enumeration", f'site:{target} inurl:?author=1'),
            ("WordPress", "WP XMLRPC", f'site:{target} inurl:xmlrpc.php'),
            ("WordPress", "WP Debug Log", f'site:{target} inurl:wp-content/debug.log'),
            # ═══════ ENTERPRISE & HIGH-VALUE TARGETS ═══════
            ("Enterprise", "Employee Portals", f'site:{target} inurl:portal OR inurl:employee OR inurl:intranet'),
            ("Enterprise", "Outlook Web Access", f'site:{target} inurl:owa OR inurl:exchange'),
            ("Enterprise", "Citrix / VPN Login", f'site:{target} inurl:vpn OR inurl:citrix OR inurl:anyconnect'),
            ("Enterprise", "Enterprise FTP", f'site:{target} inurl:ftp OR inurl:fileshare intitle:"index of"'),
            ("Enterprise", "SAP NetWeaver", f'site:{target} inurl:irj/portal'),
            ("Enterprise", "Oracle PeopleSoft", f'site:{target} inurl:psp/ps/EMPLOYEE'),
            ("Enterprise", "Salesforce Exposed", f'site:{target} inurl:salesforce'),
            ("Enterprise", "Atlassian Confluence", f'site:{target} inurl:confluence'),
            ("Enterprise", "Atlassian Jira", f'site:{target} inurl:jira'),
            ("Enterprise", "Office 365 Setup", f'site:{target} inurl:autodiscover'),
            ("Enterprise", "Confidential Salary Info", f'site:{target} ext:pdf OR ext:xls "confidential" "salary" OR "payroll"'),
            ("Enterprise", "Internal Strategic Plans", f'site:{target} ext:pdf OR ext:doc "strategic plan" OR "confidential"'),
            ("Enterprise", "SharePoint Exposed", f'site:{target} inurl:_layouts/15/start.aspx'),
            ("Enterprise", "PowerBI Reports", f'site:{target} inurl:apps.powerbi.com'),
            ("Enterprise", "Global Protect Portal", f'site:{target} inurl:global-protect'),
        ]

        # Merge with persistent custom dorks
        custom_dorks = self.load_saved_custom_dorks()
        for cat, desc, dork in default_dorks:
            self.add_dork_row(cat, desc, dork)
            
        for d in custom_dorks:
            self.add_dork_row(d.get("category", "Custom"), d.get("description", "Imported"), d.get("dork", ""))
        
        count = self.table.rowCount()
        self.lbl_status.setText(f"✅ {count} dorks loaded for target: {target}")
        self.lbl_status.setStyleSheet("color: #00ff9d; font-size: 8pt;")

    # ═══════════════════════════════════════════════════
    # PERSISTENCE & IMPORT
    # ═══════════════════════════════════════════════════
    def get_data_file(self):
        # Determine data path relative to main script or package
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        data_dir = os.path.join(base_dir, "data")
        if not os.path.exists(data_dir):
            os.makedirs(data_dir, exist_ok=True)
        return os.path.join(data_dir, "custom_dorks.json")

    def load_saved_custom_dorks(self):
        path = self.get_data_file()
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return []
        return []

    def save_custom_dorks(self, new_dorks):
        """new_dorks: list of dicts with cat, desc, dork"""
        existing = self.load_saved_custom_dorks()
        # Prevent duplicates
        existing_queries = {d["dork"] for d in existing}
        for d in new_dorks:
            if d["dork"] not in existing_queries:
                existing.append(d)
                existing_queries.add(d["dork"])
        
        path = self.get_data_file()
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(existing, f, indent=4)
            return True
        except Exception as e:
            print(f"Error saving dorks: {e}")
            return False

    def import_dorks_dialog(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import Dorks List", "", "Text Files (*.txt);;JSON Files (*.json);;All Files (*)"
        )
        if not file_path:
            return

        imported_count = 0
        new_dorks_data = []

        try:
            if file_path.endswith(".json"):
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict) and "dork" in item:
                                cat = item.get("category", "Imported")
                                desc = item.get("description", "From JSON")
                                q = item["dork"]
                                new_dorks_data.append({"category": cat, "description": desc, "dork": q})
                                self.add_dork_row(cat, desc, q)
                                imported_count += 1
            else:
                # Assume .txt, one dork per line
                with open(file_path, "r", encoding="utf-8") as f:
                    for line in f:
                        q = line.strip()
                        if q and not q.startswith("#"):
                            cat = "Imported"
                            desc = "From Text File"
                            new_dorks_data.append({"category": cat, "description": desc, "dork": q})
                            self.add_dork_row(cat, desc, q)
                            imported_count += 1
            
            if imported_count > 0:
                self.save_custom_dorks(new_dorks_data)
                QMessageBox.information(self, "Success", f"Successfully imported and saved {imported_count} dorks!")
                self.lbl_status.setText(f"📥 Imported {imported_count} dorks and saved to memory.")
                self.lbl_status.setStyleSheet("color: #00ff9d; font-size: 8pt;")
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to import dorks: {e}")

    def clear_table(self):
        reply = QMessageBox.question(
            self, "Clear Dorks",
            "Clear current table view?\n\nNote: This won't delete saved dorks from memory unless you restart or reload default list.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.table.setRowCount(0)
            self.lbl_status.setText("🗑️ Table cleared.")

    # ═══════════════════════════════════════════════════
    # TABLE ROW MANAGEMENT
    # ═══════════════════════════════════════════════════
    def add_dork_row(self, category, description, dork_query):
        row = self.table.rowCount()
        self.table.insertRow(row)
        
        cat_item = QTableWidgetItem(category)
        cat_item.setForeground(QColor("#ffcc00"))
        self.table.setItem(row, 0, cat_item)

        desc_item = QTableWidgetItem(description)
        desc_item.setForeground(QColor("#aaa"))
        self.table.setItem(row, 1, desc_item)

        dork_item = QTableWidgetItem(dork_query)
        dork_item.setForeground(QColor("#00f3ff"))
        self.table.setItem(row, 2, dork_item)

        # Status column (blank initially)
        status_item = QTableWidgetItem("—")
        status_item.setForeground(QColor("#556"))
        status_item.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(row, 3, status_item)
        
        # Action buttons
        action_widget = QWidget()
        action_layout = QHBoxLayout(action_widget)
        action_layout.setContentsMargins(2, 2, 2, 2)
        action_layout.setSpacing(4)

        btn_exec = QPushButton("🌐")
        btn_exec.setToolTip("Open in Google")
        btn_exec.setFixedSize(30, 26)
        btn_exec.setStyleSheet("""
            QPushButton { background: rgba(0,243,255,0.15); color: #00f3ff; border-radius: 4px; border: 1px solid rgba(0,243,255,0.3); font-size: 10pt; }
            QPushButton:hover { background: rgba(0,243,255,0.4); }
        """)
        btn_exec.clicked.connect(lambda _, q=dork_query: self.execute_dork(q))

        btn_copy = QPushButton("📋")
        btn_copy.setToolTip("Copy dork to clipboard")
        btn_copy.setFixedSize(30, 26)
        btn_copy.setStyleSheet("""
            QPushButton { background: rgba(0,255,157,0.1); color: #00ff9d; border-radius: 4px; border: 1px solid rgba(0,255,157,0.3); font-size: 10pt; }
            QPushButton:hover { background: rgba(0,255,157,0.35); }
        """)
        btn_copy.clicked.connect(lambda _, q=dork_query: self._copy_single(q))

        action_layout.addWidget(btn_exec)
        action_layout.addWidget(btn_copy)
        self.table.setCellWidget(row, 4, action_widget)

    # ═══════════════════════════════════════════════════
    # AUTO-ANALYSIS ENGINE (Google Scraping)
    # ═══════════════════════════════════════════════════
    def auto_analyze_all(self):
        target = self.txt_target.text().strip()
        if not target:
            QMessageBox.warning(self, "Missing Target", "Enter a target domain before analyzing.")
            return
        
        if self._analyzing:
            self._stop_analysis = True
            self.btn_auto_analyze.setText("🚀 AUTO-ANALYZE ALL")
            self.lbl_status.setText("⏹ Analysis stopped by user.")
            self.lbl_status.setStyleSheet("color: #ffcc00; font-size: 8pt;")
            return
        
        total = self.table.rowCount()
        if total == 0:
            return

        self._analyzing = True
        self._stop_analysis = False
        self.btn_auto_analyze.setText("⏹ STOP ANALYSIS")
        self.progress.setVisible(True)
        self.progress.setMaximum(total)
        self.progress.setValue(0)
        self.progress.setFormat("ANALYZING... %p%")
        self.lbl_status.setText(f"🔍 Auto-analyzing {total} dorks against Google...")
        self.lbl_status.setStyleSheet("color: #ffcc00; font-size: 8pt;")

        # Collect all dorks
        dorks = []
        for row in range(total):
            dork_item = self.table.item(row, 2)
            if dork_item:
                query = dork_item.text()
                query = query.replace("{target}", target.replace("https://", "").replace("http://", "").split('/')[0])
                dorks.append((row, query))

        # Run in background thread
        thread = threading.Thread(target=self._analyze_worker, args=(dorks,), daemon=True)
        thread.start()

    def _analyze_worker(self, dorks):
        """Background thread: queries Google for each dork and deeply parses the results page."""
        hits = 0
        for i, (row, query) in enumerate(dorks):
            if self._stop_analysis:
                break

            try:
                url = f"https://www.google.com/search?q={urllib.parse.quote(query)}&num=10&hl=en"
                headers = {
                    "User-Agent": random.choice(_USER_AGENTS),
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Referer": "https://www.google.com/",
                    "DNT": "1",
                    "Connection": "keep-alive",
                    "Upgrade-Insecure-Requests": "1",
                }
                resp = requests.get(url, headers=headers, timeout=12, allow_redirects=True, verify=False)
                body = resp.text
                body_lower = body.lower()

                # ─── 1. Check for CAPTCHA / block ───
                captcha_indicators = [
                    "unusual traffic",
                    "captcha",
                    "our systems have detected",
                    "/sorry/index",
                    "recaptcha",
                    "are not a robot",
                ]
                if any(ind in body_lower for ind in captcha_indicators):
                    self._analysis_result.emit(row, "⚠️ CAPTCHA", "#ff9d00")
                    self._log_message.emit(f'<span style="color:#ff9d00">[⚠️ CAPTCHA] Google blocked request for: {query[:60]}... — waiting 15-30s</span>')
                    time.sleep(random.uniform(15, 30))
                    continue

                # ─── 2. Check for explicit NO RESULTS ───
                no_results_indicators = [
                    "did not match any documents",
                    "nenhum documento foi encontrado",
                    "no results found",
                    "nenhum resultado encontrado",
                    "did not match any document",
                    "your search did not match",
                    "não corresponde a nenhum",
                ]
                is_no_result = any(ind in body_lower for ind in no_results_indicators)

                if is_no_result:
                    self._analysis_result.emit(row, "❌ 0 results", "#555")
                    self._log_message.emit(f'<span style="color:#555">[❌ NO RESULTS] {query[:80]}</span>')
                    self._analysis_progress.emit(i + 1, len(dorks))
                    time.sleep(random.uniform(2.0, 4.5))
                    continue

                # ─── 3. Extract "About X results" count from Google ───
                result_count = 0
                count_match = re.search(
                    r'(?:about|approximately|cerca de)?\s*([\d,.\s]+)\s*(?:results|resultados|résultats)',
                    body_lower
                )
                if count_match:
                    count_str = count_match.group(1).replace(",", "").replace(".", "").replace(" ", "").strip()
                    try:
                        result_count = int(count_str)
                    except ValueError:
                        result_count = 0

                # ─── 4. Count REAL result links in the page ───
                # Google wraps results in <a href="/url?q=..." or <a href="https://..."
                # We look for links that point to external sites (not google.com itself)
                real_links = re.findall(
                    r'<a\s+href="(?:/url\?q=)?(https?://[^"]+)"',
                    body
                )
                # Filter out Google internal links
                external_links = [
                    link for link in real_links
                    if not any(g in link for g in [
                        'google.com', 'google.com.br', 'gstatic.com',
                        'googleapis.com', 'youtube.com', 'accounts.google',
                        'support.google', 'policies.google', 'maps.google',
                        'webcache.googleusercontent'
                    ])
                ]
                num_real_links = len(external_links)

                # ─── 5. Also check for result snippet divs ───
                # Google wraps result descriptions in specific class patterns
                snippet_count = len(re.findall(r'class="[^"]*(?:VwiC3b|IsZvec|BNeawe|s3v9rd)[^"]*"', body))

                # ─── 6. Final verdict ───
                if num_real_links >= 1 or snippet_count >= 1:
                    # Real results found
                    if result_count > 0:
                        count_display = f"{result_count:,}" if result_count < 1000000 else f"{result_count/1000000:.1f}M"
                        self._analysis_result.emit(row, f"✅ {count_display} hits", "#00ff9d")
                    else:
                        self._analysis_result.emit(row, f"✅ {num_real_links} links", "#00ff9d")
                    hits += 1
                    self._log_message.emit(
                        f'<span style="color:#00ff9d">[✅ HIT] {query[:70]}  →  '
                        f'{num_real_links} links, {snippet_count} snippets, ~{result_count} results</span>'
                    )
                elif result_count > 0:
                    # Google says results exist but we couldn't parse links
                    count_display = f"{result_count:,}" if result_count < 1000000 else f"{result_count/1000000:.1f}M"
                    self._analysis_result.emit(row, f"🔶 ~{count_display}", "#ff9d00")
                    hits += 1
                    self._log_message.emit(
                        f'<span style="color:#ff9d00">[🔶 POSSIBLE] {query[:70]}  →  ~{result_count} results (links not parsed)</span>'
                    )
                else:
                    # Nothing found at all
                    self._analysis_result.emit(row, "❌ 0 results", "#555")
                    self._log_message.emit(f'<span style="color:#555">[❌ EMPTY] {query[:80]}</span>')

            except requests.exceptions.Timeout:
                self._analysis_result.emit(row, "⏳ TIMEOUT", "#ff9d00")
                self._log_message.emit(f'<span style="color:#ff9d00">[⏳ TIMEOUT] {query[:70]}</span>')
            except requests.exceptions.ConnectionError:
                self._analysis_result.emit(row, "🔌 CONN ERR", "#ff5555")
                self._log_message.emit(f'<span style="color:#ff5555">[🔌 CONNECTION ERROR] {query[:70]}</span>')
            except Exception as e:
                self._analysis_result.emit(row, "⚠️ ERR", "#ff5555")
                self._log_message.emit(f'<span style="color:#ff5555">[⚠️ ERROR] {query[:60]} — {str(e)[:40]}</span>')

            self._analysis_progress.emit(i + 1, len(dorks))
            # Random delay to avoid Google ban
            time.sleep(random.uniform(3.0, 6.0))

        self._analysis_done.emit()

    # ═══════ SIGNAL HANDLERS (thread-safe UI updates) ═══════
    def _count_hits(self):
        """Count rows with ✅ status."""
        hits = 0
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 3)
            if item and "✅" in item.text():
                hits += 1
        return hits

    @Slot(int, str, str)
    def _on_analysis_result(self, row, status, color):
        item = QTableWidgetItem(status)
        item.setForeground(QColor(color))
        item.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(row, 3, item)

    @Slot(str)
    def _on_log_message(self, html):
        self.log_console.append(html)
        sb = self.log_console.verticalScrollBar()
        sb.setValue(sb.maximum())

    @Slot(int, int)
    def _on_analysis_progress(self, current, total):
        self.progress.setValue(current)
        hits = self._count_hits()
        self.lbl_status.setText(f"🔍 Analyzed {current}/{total} — {hits} HITS found so far")
        self.lbl_status.setStyleSheet("color: #ffcc00; font-size: 8pt;")

    @Slot()
    def _on_analysis_done(self):
        self._analyzing = False
        self.btn_auto_analyze.setText("🚀 AUTO-ANALYZE ALL")
        self.progress.setFormat("COMPLETE")
        
        hits = self._count_hits()
        
        self.lbl_status.setText(f"✅ Analysis complete! {hits} dorks returned results.")
        self.lbl_status.setStyleSheet("color: #00ff9d; font-size: 8pt;")
        self._log_message.emit(f'<br><span style="color:#00ff9d;font-weight:bold">══════ ANALYSIS COMPLETE ══════  {hits} HITS out of {self.table.rowCount()} dorks</span>')

    # ═══════════════════════════════════════════════════
    # DORK ACTIONS
    # ═══════════════════════════════════════════════════
    def execute_dork(self, query):
        target = self.txt_target.text().strip()
        if not target:
            QMessageBox.warning(self, "Missing Target", "Please enter a target domain first.")
            return
        target = target.replace("https://", "").replace("http://", "").split('/')[0]
        final_query = query.replace("{target}", target)
        url = f"https://www.google.com/search?q={urllib.parse.quote(final_query)}"
        webbrowser.open(url)

    def _copy_single(self, query):
        target = self.txt_target.text().strip()
        if target:
            target = target.replace("https://", "").replace("http://", "").split('/')[0]
            query = query.replace("{target}", target)
        clipboard = QApplication.clipboard()
        clipboard.setText(query)
        self.lbl_status.setText(f"📋 Copied: {query[:80]}...")
        self.lbl_status.setStyleSheet("color: #00ff9d; font-size: 8pt;")

    def copy_all_dorks(self):
        target = self.txt_target.text().strip()
        if target:
            target = target.replace("https://", "").replace("http://", "").split('/')[0]

        all_dorks = []
        for row in range(self.table.rowCount()):
            dork_item = self.table.item(row, 2)
            if dork_item:
                dork = dork_item.text()
                if target:
                    dork = dork.replace("{target}", target)
                all_dorks.append(dork)
        
        if all_dorks:
            clipboard = QApplication.clipboard()
            clipboard.setText("\n".join(all_dorks))
            self.lbl_status.setText(f"📋 Copied {len(all_dorks)} dorks to clipboard!")
            self.lbl_status.setStyleSheet("color: #00ff9d; font-size: 8pt;")

    def copy_hits_only(self):
        """Copy only dorks that had ✅ HIT FOUND."""
        target = self.txt_target.text().strip()
        if target:
            target = target.replace("https://", "").replace("http://", "").split('/')[0]

        hits = []
        for row in range(self.table.rowCount()):
            status_item = self.table.item(row, 3)
            dork_item = self.table.item(row, 2)
            if status_item and dork_item and "✅" in status_item.text():
                dork = dork_item.text()
                if target:
                    dork = dork.replace("{target}", target)
                hits.append(dork)
        
        if hits:
            clipboard = QApplication.clipboard()
            clipboard.setText("\n".join(hits))
            self.lbl_status.setText(f"📋 Copied {len(hits)} HIT dorks to clipboard!")
            self.lbl_status.setStyleSheet("color: #00ff9d; font-size: 8pt;")
        else:
            self.lbl_status.setText("⚠️ No hits found yet. Run Auto-Analyze first.")
            self.lbl_status.setStyleSheet("color: #ff5555; font-size: 8pt;")

    # ═══════════════════════════════════════════════════
    # AI DORK GENERATION (with built-in Groq key)
    # ═══════════════════════════════════════════════════
    def set_ai_assistant(self, assistant):
        self.ai_assistant = assistant

    def _ensure_ai(self):
        """Create AI assistant from built-in key field if not set externally."""
        if not self.ai_assistant:
            api_key = self.txt_groq_key.text().strip()
            model = self.combo_model.currentText()
            if api_key:
                try:
                    from core.ai_assistant import AIAssistant
                    self.ai_assistant = AIAssistant(api_key, model)
                    return True
                except Exception:
                    return False
            return False
        return True

    @Slot()
    def generate_ai_dorks(self):
        if not self._ensure_ai():
            QMessageBox.warning(
                self, "API Key Required",
                "Enter your Groq API Key above (🔑 GROQ KEY field).\n\n"
                "Get a free key at: https://console.groq.com/keys"
            )
            return

        target = self.txt_target.text().strip()
        if not target:
            QMessageBox.warning(self, "Missing Target", "Please enter a target domain for the AI to analyze.")
            return

        target = target.replace("https://", "").replace("http://", "").split('/')[0]

        self.btn_ai_gen.setEnabled(False)
        self.btn_ai_gen.setText("⏳ GENERATING...")
        self.lbl_status.setText("🤖 AI is generating advanced dorks...")
        self.lbl_status.setStyleSheet("color: #ffcc00; font-size: 8pt;")

        prompt = f"""Atue como um Engenheiro de Segurança Sênior especializado em Reconhecimento Externo. Sua missão é gerar uma lista de 20 Google Dorks de alta precisão para a infraestrutura {target}.

Objetivo: Identificar vazamentos de dados, superfícies expostas e falhas de configuração antes que atores maliciosos o façam.

Requisitos Técnicos:

Use operadores avançados combinados (ext:, inurl:, intitle:, intext:, -site:github.com).

Foque em padrões de nomenclatura de ambientes de desenvolvimento (dev, staging, test, old, backup).

Inclua strings específicas de erros de servidor que revelam a stack tecnológica (X-Powered-By, PHP Errors, SQL Syntax).

Explore padrões de arquivos de configuração de nuvem e ferramentas de automação (.yml, .env, .git, .aws/credentials).

FORMATO DE SAÍDA (STRICT):

Categoria | Descrição Técnica | Query Exata

Sem introduções ou explicações.

Categorias Obrigatórias: > Credentials/Keys, DB Dumps, Admin Portals, Cloud Storage, Git/SVN Leaks, Debug/Trace Logs, API Documentation, Virtual Hosts, E-commerce PII, Subdomain Takeover Indicators"
"""
        
        try:
            import asyncio

            async def _run():
                try:
                    result = await self.ai_assistant.generate_custom_script(prompt, "full_recon", "")
                    return result
                except Exception:
                    if hasattr(self.ai_assistant, 'get_response'):
                        return self.ai_assistant.get_response(prompt)
                    raise

            def _done(future):
                try:
                    response = future.result()
                    lines = [line.strip() for line in response.split('\n') if '|' in line]
                    
                    added = 0
                    for line in lines:
                        parts = line.split('|')
                        if len(parts) >= 3:
                            cat = parts[0].strip().strip('-').strip('*').strip()
                            desc = parts[1].strip()
                            dork = parts[2].strip()
                            if dork and len(dork) > 5:
                                self.add_dork_row(f"🤖 {cat}", desc, dork)
                                added += 1
                    
                    if added > 0:
                        self.lbl_status.setText(f"✅ AI generated {added} new dorks!")
                        self.lbl_status.setStyleSheet("color: #00ff9d; font-size: 8pt;")
                    else:
                        self.lbl_status.setText("⚠️ AI response did not contain valid dorks.")
                        self.lbl_status.setStyleSheet("color: #ff5555; font-size: 8pt;")
                except Exception as e:
                    self.lbl_status.setText(f"❌ AI Error: {str(e)}")
                    self.lbl_status.setStyleSheet("color: #ff5555; font-size: 8pt;")
                finally:
                    self.btn_ai_gen.setEnabled(True)
                    self.btn_ai_gen.setText("🤖 AI GENERATE DORKS")

            loop = asyncio.get_event_loop()
            future = asyncio.ensure_future(_run())
            future.add_done_callback(_done)
            
        except Exception as e:
            self.lbl_status.setText(f"❌ Error: {str(e)}")
            self.lbl_status.setStyleSheet("color: #ff5555; font-size: 8pt;")
            self.btn_ai_gen.setEnabled(True)
            self.btn_ai_gen.setText("🤖 AI GENERATE DORKS")

    def set_target(self, target):
        """Sync with main dashboard target."""
        if target:
            clean_target = target.replace("https://", "").replace("http://", "").split('/')[0]
            self.txt_target.setText(clean_target)
