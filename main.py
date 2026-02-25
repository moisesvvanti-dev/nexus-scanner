import sys
import os
import asyncio
from PySide6.QtWidgets import QApplication
from qasync import QEventLoop

# Suppress harmless Qt font warnings
os.environ["QT_LOGGING_RULES"] = "qt.text.font.*=false"

from gui.main_window import MainWindow

def main():
    app = QApplication(sys.argv)
    
    # Create asyncio event loop integrated with Qt
    loop = QEventLoop(app)
    asyncio.set_event_loop(loop)
    
    # Initialize with empty targets list, as user will input manually
    window = MainWindow([])
    window.show()
    
    with loop:
        loop.run_forever()

if __name__ == "__main__":
    main()
