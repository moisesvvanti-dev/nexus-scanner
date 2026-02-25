# ╔══════════════════════════════════════════════════════════════╗
# ║  NEXUS CYBER-OFFENSIVE SUITE  │  PREMIUM GLASSMORPHISM UI  ║
# ╠══════════════════════════════════════════════════════════════╣
# ║  Deep Void:    #050510          │  Background               ║
# ║  Cyber Neon:   #00f3ff          │  Primary Accent (Cyan)    ║
# ║  Glitch Red:   #ff0055          │  Danger / Critical        ║
# ║  Matrix Grn:   #00ff9d          │  Success / Active         ║
# ║  Pulse Gold:   #ffcc00          │  Warning / Highlight      ║
# ║  Surface:      rgba(12,12,24)   │  Glass Panels             ║
# ╚══════════════════════════════════════════════════════════════╝

MAIN_STYLE = """
/* ═══════ CORE ═══════ */
QMainWindow {
    background-color: #050510;
    color: #e0e0e0;
}

QWidget {
    font-family: 'Consolas', 'Cascadia Code', 'Courier New', monospace;
    font-size: 10pt;
}

/* ═══════ GLASSMORPHISM PANELS ═══════ */
QFrame, QWidget#DashboardStats, QWidget#ContentPanel {
    background-color: rgba(12, 12, 28, 0.75);
    border: 1px solid rgba(0, 243, 255, 0.15);
    border-radius: 12px;
}

/* ═══════ SIDEBAR ═══════ */
QWidget#Sidebar {
    background-color: qlineargradient(
        spread:pad, x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(8, 8, 18, 0.98),
        stop:0.5 rgba(5, 10, 25, 0.98),
        stop:1 rgba(8, 8, 18, 0.98)
    );
    border-right: 1px solid rgba(0, 243, 255, 0.2);
}

QPushButton#SidebarButton {
    background-color: transparent;
    border: none;
    border-left: 3px solid transparent;
    color: #667;
    text-align: left;
    padding: 16px 24px;
    font-size: 10pt;
    font-weight: bold;
    letter-spacing: 2px;
}

QPushButton#SidebarButton:hover {
    background-color: rgba(0, 243, 255, 0.08);
    color: #00f3ff;
    border-left: 3px solid rgba(0, 243, 255, 0.5);
}

QPushButton#SidebarButton:checked {
    background-color: rgba(0, 243, 255, 0.12);
    border-left: 3px solid #00f3ff;
    color: #00f3ff;
}

/* ═══════ BUTTONS ═══════ */
QPushButton {
    background-color: rgba(0, 243, 255, 0.07);
    border: 1px solid rgba(0, 243, 255, 0.5);
    border-radius: 8px;
    color: #00f3ff;
    padding: 10px 22px;
    font-weight: bold;
    letter-spacing: 1px;
    min-height: 18px;
}

QPushButton:hover {
    background-color: rgba(0, 243, 255, 0.2);
    border: 1px solid #00f3ff;
    color: #ffffff;
}

QPushButton:pressed {
    background-color: rgba(0, 243, 255, 0.35);
}

QPushButton:disabled {
    background-color: rgba(30, 30, 40, 0.4);
    border: 1px solid #333;
    color: #555;
}

QPushButton#ActionRed {
    color: #ff0055;
    border: 1px solid rgba(255, 0, 85, 0.5);
    background-color: rgba(255, 0, 85, 0.07);
}
QPushButton#ActionRed:hover {
    background-color: rgba(255, 0, 85, 0.25);
    border: 1px solid #ff0055;
    color: #fff;
}

QPushButton#ActionGreen {
    color: #00ff9d;
    border: 1px solid rgba(0, 255, 157, 0.5);
    background-color: rgba(0, 255, 157, 0.07);
}
QPushButton#ActionGreen:hover {
    background-color: rgba(0, 255, 157, 0.25);
    border: 1px solid #00ff9d;
    color: #fff;
}

QPushButton#ActionBlue {
    color: #00b4ff;
    border: 1px solid rgba(0, 180, 255, 0.5);
    background-color: rgba(0, 180, 255, 0.07);
}
QPushButton#ActionBlue:hover {
    background-color: rgba(0, 180, 255, 0.25);
    border: 1px solid #00b4ff;
    color: #fff;
}

/* ═══════ INPUT FIELDS ═══════ */
QLineEdit, QPlainTextEdit {
    background-color: rgba(8, 8, 18, 0.9);
    border: 1px solid rgba(0, 243, 255, 0.25);
    border-radius: 8px;
    color: #00ff9d;
    padding: 10px 12px;
    font-size: 10pt;
    selection-background-color: #ff0055;
    selection-color: #fff;
}

QLineEdit:focus, QPlainTextEdit:focus {
    border: 1px solid #00f3ff;
    background-color: rgba(10, 10, 25, 0.95);
}

QLineEdit::placeholder {
    color: #445;
}

/* ═══════ TABLES ═══════ */
QTableWidget {
    background-color: rgba(8, 8, 18, 0.7);
    gridline-color: rgba(0, 243, 255, 0.06);
    border: 1px solid rgba(0, 243, 255, 0.15);
    border-radius: 10px;
    color: #ccc;
    selection-background-color: rgba(0, 243, 255, 0.15);
    selection-color: #fff;
    alternate-background-color: rgba(0, 243, 255, 0.03);
}

QHeaderView::section {
    background-color: rgba(5, 5, 15, 0.95);
    color: #00f3ff;
    padding: 10px 8px;
    border: none;
    border-bottom: 2px solid rgba(0, 243, 255, 0.4);
    font-weight: bold;
    font-size: 8pt;
    letter-spacing: 1px;
}

QTableCornerButton::section {
    background-color: rgba(5, 5, 15, 0.95);
    border: none;
}

/* ═══════ SCROLLBARS ═══════ */
QScrollBar:vertical {
    border: none;
    background: rgba(5, 5, 16, 0.5);
    width: 6px;
    margin: 4px 0;
    border-radius: 3px;
}
QScrollBar::handle:vertical {
    background: rgba(0, 243, 255, 0.4);
    min-height: 30px;
    border-radius: 3px;
}
QScrollBar::handle:vertical:hover {
    background: rgba(0, 243, 255, 0.7);
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
    background: none;
}

QScrollBar:horizontal {
    border: none;
    background: rgba(5, 5, 16, 0.5);
    height: 6px;
    margin: 0 4px;
    border-radius: 3px;
}
QScrollBar::handle:horizontal {
    background: rgba(0, 243, 255, 0.4);
    min-width: 30px;
    border-radius: 3px;
}

/* ═══════ TOOLTIPS ═══════ */
QToolTip {
    background-color: rgba(10, 10, 25, 0.95);
    color: #00f3ff;
    border: 1px solid rgba(0, 243, 255, 0.4);
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 9pt;
}

/* ═══════ CHECKBOX ═══════ */
QCheckBox {
    color: #bbb;
    spacing: 10px;
}
QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border: 2px solid rgba(0, 243, 255, 0.5);
    background: rgba(0, 0, 0, 0.4);
    border-radius: 5px;
}
QCheckBox::indicator:checked {
    background-color: #00f3ff;
    border-color: #00f3ff;
}
QCheckBox::indicator:unchecked:hover {
    border: 2px solid #00f3ff;
}

/* ═══════ PROGRESS BAR ═══════ */
QProgressBar {
    border: 1px solid rgba(0, 243, 255, 0.2);
    border-radius: 8px;
    text-align: center;
    background-color: rgba(8, 8, 18, 0.7);
    color: #fff;
    font-weight: bold;
    font-size: 9pt;
    min-height: 22px;
    letter-spacing: 1px;
}
QProgressBar::chunk {
    background-color: qlineargradient(
        spread:pad, x1:0, y1:0, x2:1, y2:0,
        stop:0 #00f3ff, stop:0.4 #00ff9d, stop:0.7 #00f3ff, stop:1 #00d4ff
    );
    border-radius: 8px;
}

/* ═══════ COMBO BOX ═══════ */
QComboBox {
    color: #00ff9d;
    background: rgba(8, 8, 18, 0.9);
    border: 1px solid rgba(0, 243, 255, 0.3);
    padding: 8px 12px;
    border-radius: 8px;
    font-weight: bold;
    min-height: 18px;
}
QComboBox:hover {
    border: 1px solid #00f3ff;
}
QComboBox::drop-down {
    border: none;
    background: rgba(0, 243, 255, 0.1);
    width: 24px;
    border-top-right-radius: 8px;
    border-bottom-right-radius: 8px;
}
QComboBox QAbstractItemView {
    background: rgba(12, 12, 28, 0.97);
    color: #00ff9d;
    selection-background-color: rgba(0, 243, 255, 0.2);
    selection-color: #fff;
    border: 1px solid rgba(0, 243, 255, 0.3);
    border-radius: 6px;
    padding: 4px;
    outline: 0px;
}

/* ═══════ TABS ═══════ */
QTabWidget::pane {
    border: 1px solid rgba(0, 243, 255, 0.15);
    border-radius: 8px;
    background: rgba(10, 10, 20, 0.5);
}
QTabBar::tab {
    background: rgba(15, 15, 30, 0.8);
    color: #667;
    padding: 10px 24px;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    margin-right: 2px;
    font-weight: bold;
    letter-spacing: 1px;
}
QTabBar::tab:selected {
    background: rgba(0, 243, 255, 0.15);
    color: #00f3ff;
    border-bottom: 2px solid #00f3ff;
}
QTabBar::tab:hover:!selected {
    background: rgba(0, 243, 255, 0.08);
    color: #88c;
}

/* ═══════ LIST WIDGET ═══════ */
QListWidget {
    background: rgba(8, 8, 18, 0.6);
    border: 1px solid rgba(0, 243, 255, 0.1);
    border-radius: 8px;
    color: #ccc;
    outline: 0px;
}
QListWidget::item {
    padding: 8px 12px;
    border-bottom: 1px solid rgba(0, 243, 255, 0.05);
}
QListWidget::item:selected {
    background: rgba(0, 243, 255, 0.12);
    color: #fff;
}

/* ═══════ MESSAGE BOX ═══════ */
QMessageBox {
    background-color: #0a0a18;
}
QMessageBox QLabel {
    color: #ddd;
}
"""

LOG_STYLE = """
QTextEdit {
    background-color: rgba(5, 5, 12, 0.95);
    color: #c8ffd4;
    border: 1px solid rgba(0, 255, 157, 0.2);
    border-radius: 10px;
    font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace;
    font-size: 9pt;
    padding: 12px;
    selection-background-color: #00ff9d;
    selection-color: #000;
    line-height: 1.4;
}
"""
