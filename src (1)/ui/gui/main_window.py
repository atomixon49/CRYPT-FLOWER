"""
Main window for the cryptographic system GUI.
"""

import os
import sys
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QToolBar, QStatusBar, QFileDialog, QMessageBox, QApplication
)
from PyQt6.QtGui import QAction, QIcon, QPixmap
from PyQt6.QtCore import Qt, QSize

from ...core.key_management import KeyManager
from ...core.encryption import EncryptionEngine
from ...core.signatures import SignatureEngine
from ...core.key_rotation import KeyRotationManager
from ...core.crypto_audit import CryptoAuditLogger, FileAuditLogDestination
from ...core.crypto_benchmark import CryptoBenchmark
from ...core.multi_recipient_encryption import MultiRecipientEncryption
from ...core.cosign import CoSignatureManager
from ...core.timestamp import TimestampManager
from ...core.cert_revocation import CertificateRevocationChecker
from ...file_handlers.text_handler import TextFileHandler
from ...file_handlers.pdf_handler import PDFHandler
from ...file_handlers.pdf_section_handler import PDFSectionHandler

from .tabs.encryption_tab import EncryptionTab
from .tabs.pdf_section_tab import PDFSectionTab
from .tabs.signatures_tab import SignaturesTab
from .tabs.key_management_tab import KeyManagementTab
from .tabs.directory_tab import DirectoryTab
from .tabs.key_rotation_tab import KeyRotationTab
from .tabs.audit_tab import AuditTab
from .tabs.benchmark_tab import BenchmarkTab
from .tabs.jwt_tab import JWTTab
from .tabs.multi_recipient_tab import MultiRecipientTab
from .tabs.cosign_tab import CoSignTab

class MainWindow(QMainWindow):
    """Main window for the cryptographic system GUI."""

    def __init__(self):
        """Initialize the main window."""
        super().__init__()

        # Initialize core components
        self.key_manager = KeyManager()
        self.encryption_engine = EncryptionEngine()
        self.signature_engine = SignatureEngine()
        self.rotation_manager = KeyRotationManager(self.key_manager)
        self.multi_encryption = MultiRecipientEncryption(self.key_manager)
        self.cosign_manager = CoSignatureManager(self.key_manager)
        self.timestamp_manager = TimestampManager()
        self.cert_revocation_checker = CertificateRevocationChecker()

        # Initialize audit and benchmark components
        self.audit_logger = CryptoAuditLogger()
        self.benchmark = CryptoBenchmark(
            encryption_engine=self.encryption_engine,
            signature_engine=self.signature_engine,
            key_manager=self.key_manager
        )

        # Initialize file handlers
        self.text_handler = TextFileHandler(self.key_manager, self.encryption_engine)
        self.pdf_handler = PDFHandler(self.key_manager, self.encryption_engine)
        self.pdf_section_handler = PDFSectionHandler(self.key_manager, self.encryption_engine)

        # Set up the UI
        self.setWindowTitle("Cryptographic System")
        self.setMinimumSize(800, 600)

        # Create menu bar
        self.create_menu_bar()

        # Create toolbar
        self.create_toolbar()

        # Create status bar
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("Ready")

        # Create central widget and layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)

        # Create tab widget
        self.tab_widget = QTabWidget()
        self.main_layout.addWidget(self.tab_widget)

        # Create tabs
        self.create_tabs()

    def create_menu_bar(self):
        """Create the menu bar."""
        menu_bar = self.menuBar()

        # File menu
        file_menu = menu_bar.addMenu("&File")

        # Open action
        open_action = QAction("&Open...", self)
        open_action.setShortcut("Ctrl+O")
        open_action.setStatusTip("Open a file")
        open_action.triggered.connect(self.open_file)
        file_menu.addAction(open_action)

        # Exit action
        exit_action = QAction("E&xit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.setStatusTip("Exit the application")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Tools menu
        tools_menu = menu_bar.addMenu("&Tools")

        # Generate key action
        generate_key_action = QAction("&Generate Key...", self)
        generate_key_action.setStatusTip("Generate a new cryptographic key")
        generate_key_action.triggered.connect(self.generate_key)
        tools_menu.addAction(generate_key_action)

        # Help menu
        help_menu = menu_bar.addMenu("&Help")

        # About action
        about_action = QAction("&About", self)
        about_action.setStatusTip("About the application")
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def create_toolbar(self):
        """Create the toolbar."""
        toolbar = QToolBar("Main Toolbar")
        toolbar.setIconSize(QSize(16, 16))
        self.addToolBar(toolbar)

        # Open action
        open_action = QAction("Open", self)
        open_action.setStatusTip("Open a file")
        open_action.triggered.connect(self.open_file)
        toolbar.addAction(open_action)

        # Generate key action
        generate_key_action = QAction("Generate Key", self)
        generate_key_action.setStatusTip("Generate a new cryptographic key")
        generate_key_action.triggered.connect(self.generate_key)
        toolbar.addAction(generate_key_action)

    def create_tabs(self):
        """Create the tabs."""
        # Encryption/Decryption tab
        self.encryption_tab = EncryptionTab(
            self.key_manager,
            self.encryption_engine,
            self.text_handler,
            self.pdf_handler
        )
        self.tab_widget.addTab(self.encryption_tab, "Encryption/Decryption")

        # PDF Section Encryption tab
        self.pdf_section_tab = PDFSectionTab(
            self.key_manager,
            self.encryption_engine,
            self.pdf_section_handler
        )
        self.tab_widget.addTab(self.pdf_section_tab, "PDF Section Encryption")

        # Signatures tab
        self.signatures_tab = SignaturesTab(
            self.key_manager,
            self.signature_engine
        )
        self.tab_widget.addTab(self.signatures_tab, "Digital Signatures")

        # Key Management tab
        self.key_management_tab = KeyManagementTab(
            self.key_manager
        )
        self.tab_widget.addTab(self.key_management_tab, "Key Management")

        # Directory Encryption tab
        self.directory_tab = DirectoryTab(
            self.key_manager,
            self.encryption_engine
        )
        self.tab_widget.addTab(self.directory_tab, "Directory Encryption")

        # Key Rotation tab
        self.key_rotation_tab = KeyRotationTab(
            self.key_manager,
            self.rotation_manager
        )
        self.tab_widget.addTab(self.key_rotation_tab, "Key Rotation")

        # Audit tab
        self.audit_tab = AuditTab(
            self.audit_logger
        )
        self.tab_widget.addTab(self.audit_tab, "Audit & Logging")

        # Benchmark tab
        self.benchmark_tab = BenchmarkTab(
            self.benchmark
        )
        self.tab_widget.addTab(self.benchmark_tab, "Benchmarking")

        # JWT tab
        try:
            self.jwt_tab = JWTTab(
                self.key_manager
            )
            self.tab_widget.addTab(self.jwt_tab, "JWT/JWS/JWE")
        except Exception as e:
            print(f"Failed to initialize JWT tab: {str(e)}")

        # Multi-Recipient Encryption tab
        try:
            self.multi_recipient_tab = MultiRecipientTab()
            self.tab_widget.addTab(self.multi_recipient_tab, "Multi-Recipient Encryption")
        except Exception as e:
            print(f"Failed to initialize Multi-Recipient Encryption tab: {str(e)}")

        # Co-Sign tab
        try:
            self.cosign_tab = CoSignTab()
            self.tab_widget.addTab(self.cosign_tab, "Co-Signatures")
        except Exception as e:
            print(f"Failed to initialize Co-Signatures tab: {str(e)}")

    def open_file(self):
        """Open a file or directory."""
        # Ask if the user wants to open a file or directory
        options = ["File", "Directory"]
        selected_option, ok = QMessageBox.question(
            self,
            "Open File or Directory",
            "Do you want to open a file or a directory?",
            QMessageBox.StandardButton.Open | QMessageBox.StandardButton.Save,
            QMessageBox.StandardButton.Open
        )

        if selected_option == QMessageBox.StandardButton.Open:  # File
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Open File",
                "",
                "All Files (*)"
            )

            if file_path:
                # Determine the appropriate tab based on the file type
                file_extension = os.path.splitext(file_path)[1].lower()

                if file_extension == '.pdf':
                    # Switch to PDF tab
                    self.tab_widget.setCurrentWidget(self.pdf_section_tab)
                    self.pdf_section_tab.load_pdf(file_path)
                elif file_extension in ['.encrypted', '.sig']:
                    # Switch to encryption tab
                    self.tab_widget.setCurrentWidget(self.encryption_tab)
                    self.encryption_tab.load_file(file_path)
                elif file_extension == '.cosig':
                    # Switch to co-sign tab
                    self.tab_widget.setCurrentWidget(self.cosign_tab)
                    self.cosign_tab.signature_path_edit.setText(file_path)
                    self.cosign_tab.check_status()
                else:
                    # Default to encryption tab
                    self.tab_widget.setCurrentWidget(self.encryption_tab)
                    self.encryption_tab.load_file(file_path)
        else:  # Directory
            directory = QFileDialog.getExistingDirectory(
                self,
                "Open Directory",
                "",
                QFileDialog.Option.ShowDirsOnly
            )

            if directory:
                # Switch to directory tab
                self.tab_widget.setCurrentWidget(self.directory_tab)
                self.directory_tab.load_directory(directory)

    def generate_key(self):
        """Generate a new cryptographic key."""
        # Switch to key management tab
        self.tab_widget.setCurrentWidget(self.key_management_tab)
        self.key_management_tab.generate_key()

    def show_about(self):
        """Show the about dialog."""
        QMessageBox.about(
            self,
            "About Cryptographic System",
            "Cryptographic System v1.0.0\n\n"
            "A secure and user-friendly system for encrypting, "
            "decrypting, and signing files."
        )


def run_gui():
    """Run the GUI application."""
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
