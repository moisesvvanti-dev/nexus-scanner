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


/* ═══════ PREMIUM GLASS PANELS ═══════ */
QFrame, QWidget#DashboardStats, QWidget#ContentPanel, QScrollArea {
    background-color: rgba(255, 255, 255, 0.03);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 24px;
}

/* ═══════ SIDEBAR (FROSTED GLASS) ═══════ */
QWidget#Sidebar {
    background-color: rgba(0, 0, 0, 0.4);
    border-right: 1px solid rgba(0, 243, 255, 0.2);
    border-top-right-radius: 30px;
    border-bottom-right-radius: 30px;
}

QPushButton#SidebarButton {
    background-color: transparent;
    border: none;
    color: rgba(255, 255, 255, 0.4);
    text-align: left;
    padding: 8px 18px;
    margin: 2px 10px;
    font-size: 10pt;
    font-weight: 600;
    border-radius: 12px;
    letter-spacing: 1px;
}

QPushButton#SidebarButton:hover {
    background-color: rgba(255, 255, 255, 0.07);
    color: #00f3ff;
}

QPushButton#SidebarButton:checked {
    background-color: rgba(0, 243, 255, 0.15);
    border: 1px solid rgba(0, 243, 255, 0.4);
    color: #00f3ff;
    font-weight: 800;
}

/* ═══════ BUTTONS (NEON GLASS) ═══════ */
QPushButton {
    background-color: rgba(0, 243, 255, 0.05);
    border: 1px solid rgba(0, 243, 255, 0.2);
    border-radius: 14px;
    color: #FFFFFF;
    padding: 12px 28px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
}

QPushButton:hover {
    background-color: rgba(0, 243, 255, 0.15);
    border: 1px solid #00f3ff;
    color: #00f3ff;
}

/* Action Variants */
QPushButton#ActionGreen {
    background-color: rgba(0, 255, 157, 0.1);
    border: 1px solid rgba(0, 255, 157, 0.3);
    color: #00ff9d;
}

QPushButton#ActionGreen:hover {
    background-color: rgba(0, 255, 157, 0.2);
    border: 1px solid #00ff9d;
}

QPushButton#ActionRed {
    background-color: rgba(255, 0, 85, 0.1);
    border: 1px solid rgba(255, 0, 85, 0.3);
    color: #ff0055;
}

QPushButton#ActionRed:hover {
    background-color: rgba(255, 0, 85, 0.2);
    border: 1px solid #ff0055;
}

/* ═══════ TABLES (ULTRA CLEAN GLASS) ═══════ */
QTableWidget {
    background-color: rgba(255, 255, 255, 0.02);
    gridline-color: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 15px;
    color: #e0e0e0;
    selection-background-color: rgba(0, 243, 255, 0.2);
    selection-color: #00f3ff;
}

QHeaderView::section {
    background-color: rgba(0, 0, 0, 0.5);
    color: #00f3ff;
    padding: 10px;
    border: none;
    font-weight: 800;
    text-transform: uppercase;
}

/* ═══════ INPUTS ═══════ */
QLineEdit, QTextEdit, QComboBox {
    background-color: rgba(0, 0, 0, 0.4);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 12px;
    color: #fff;
    padding: 10px;
}

QLineEdit:focus {
    border: 1px solid #00f3ff;
}

/* ═══════ PROGRESS BAR ═══════ */
QProgressBar {
    background-color: rgba(0, 0, 0, 0.3);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 8px;
    text-align: center;
}

QProgressBar::chunk {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00f3ff, stop:1 #ff00ff);
    border-radius: 8px;
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
