# ╔══════════════════════════════════════════════════════════════╗
# ║  NEXUS CYBER-OFFENSIVE SUITE  │  ULTIMATE GLASS v5.0         ║
# ╠══════════════════════════════════════════════════════════════╣
# ║  Glassmorphism UI: High blur emulation, neon borders, and     ║
# ║  vibrant futuristic styling for a strictly premium feel.     ║
# ╚══════════════════════════════════════════════════════════════╝

MAIN_STYLE = """
/* ═══════ CORE ═══════ */
QMainWindow {
    background: qlineargradient(
        x1: 0, y1: 0, x2: 1, y2: 1,
        stop: 0 #0f0c29, stop: 0.5 #302b63, stop: 1 #24243e
    );
    color: #FFFFFF;
}

QWidget {
    font-family: 'Outfit', 'Inter', 'Segoe UI', sans-serif;
    font-size: 10pt;
}

/* ═══════ PREMIUM GLASS PANELS (MOCKUP ACCURATE) ═══════ */
QFrame, QWidget#DashboardStats, QWidget#ContentPanel {
    background-color: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.15);
    border-radius: 20px;
}

/* ═══════ SIDEBAR (FLAT MINIMALIST) ═══════ */
QWidget#Sidebar {
    background-color: rgba(0, 0, 0, 0.3);
    border-right: 1px solid rgba(255, 255, 255, 0.05);
}

QPushButton#SidebarButton {
    background-color: transparent;
    border: none;
    color: rgba(255, 255, 255, 0.5);
    text-align: left;
    padding: 8px 16px;
    margin: 2px 12px;
    font-size: 11pt;
    font-weight: 500;
    border-radius: 12px;
}

QPushButton#SidebarButton:hover {
    background-color: rgba(255, 255, 255, 0.08);
    color: #FFFFFF;
}

QPushButton#SidebarButton:checked {
    background-color: qlineargradient(
        x1: 0, y1: 0, x2: 1, y2: 0,
        stop: 0 rgba(0, 243, 255, 0.3), stop: 1 rgba(255, 255, 255, 0.1)
    );
    border-left: 4px solid #00f3ff;
    color: #FFFFFF;
    font-weight: 700;
}

/* ═══════ BUTTONS (GLASS PILLS) ═══════ */
QPushButton {
    background-color: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.2);
    border-radius: 12px;
    color: #FFFFFF;
    padding: 10px 24px;
    font-weight: 600;
}

QPushButton:hover {
    background-color: rgba(255, 255, 255, 0.15);
    border: 1px solid rgba(255, 255, 255, 0.4);
}

QPushButton:pressed {
    background-color: rgba(255, 255, 255, 0.02);
}

/* Action Variants */
QPushButton#ActionGreen {
    background-color: rgba(0, 255, 157, 0.15);
    border: 1px solid rgba(0, 255, 157, 0.4);
    color: #00ff9d;
}

QPushButton#ActionGreen:hover {
    background-color: rgba(0, 255, 157, 0.3);
    border: 1px solid rgba(0, 255, 157, 0.8);
    box-shadow: 0 0 15px rgba(0, 255, 157, 0.5);
}

QPushButton#ActionRed {
    background-color: rgba(255, 0, 85, 0.15);
    border: 1px solid rgba(255, 0, 85, 0.4);
    color: #ff0055;
}

QPushButton#ActionRed:hover {
    background-color: rgba(255, 0, 85, 0.3);
    border: 1px solid rgba(255, 0, 85, 0.8);
}

/* ═══════ INPUT FIELDS (SUBTLE GLASS) ═══════ */
QLineEdit, QTextEdit, QPlainTextEdit, QComboBox {
    background-color: rgba(0, 0, 0, 0.3);
    border: 1px solid rgba(255, 255, 255, 0.15);
    border-radius: 12px;
    color: #FFFFFF;
    padding: 12px;
}

QLineEdit:focus, QTextEdit:focus, QComboBox:focus {
    border: 1px solid #00f3ff;
    background-color: rgba(0, 243, 255, 0.05);
}

/* ═══════ PROGRESS BAR ═══════ */
QProgressBar {
    background-color: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 6px;
    text-align: center;
    color: white;
    font-weight: bold;
    height: 20px;
}

QProgressBar::chunk {
    background-color: qlineargradient(
        x1: 0, y1: 0, x2: 1, y2: 0,
        stop: 0 #00f3ff, stop: 1 #00ff9d
    );
    border-radius: 6px;
}

/* ═══════ COMBO BOX, SCROLLBAR & TABS ═══════ */
QComboBox::drop-down {
    border: none;
    width: 20px;
}
QComboBox QAbstractItemView {
    background-color: #1a1a2e;
    color: #fff;
    selection-background-color: #00f3ff;
    selection-color: #000;
}

QScrollBar:vertical {
    border: none;
    background: rgba(0,0,0,0.3);
    width: 10px;
    border-radius: 5px;
}
QScrollBar::handle:vertical {
    background: rgba(0, 243, 255, 0.5);
    border-radius: 5px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    border: none;
    background: none;
}

QTabWidget::pane {
    border: 1px solid rgba(255, 255, 255, 0.2);
    border-radius: 8px;
    background-color: rgba(0,0,0,0.2);
}
QTabBar::tab {
    background-color: rgba(0,0,0,0.4);
    color: #aaa;
    padding: 8px 16px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
}
QTabBar::tab:selected {
    background-color: rgba(0, 243, 255, 0.2);
    color: #00f3ff;
    border-bottom: 2px solid #00f3ff;
}
"""

LOG_STYLE = """
QTextEdit {
    background-color: rgba(10, 10, 15, 0.6);
    color: #E0E0E0;
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 16px;
    font-family: 'Cascadia Code', 'Consolas', monospace;
    font-size: 10pt;
    padding: 20px;
}
"""
