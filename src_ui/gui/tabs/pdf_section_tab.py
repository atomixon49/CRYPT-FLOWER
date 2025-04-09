"""
PDF Section Encryption tab for the cryptographic system GUI.
"""

import os
import getpass
from typing import Optional, Dict, Any, List, Set
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox,
    QRadioButton, QButtonGroup, QFileDialog, QLineEdit, QProgressBar,
    QTextEdit, QGroupBox, QFormLayout, QCheckBox, QMessageBox,
    QSizePolicy, QFrame, QSpacerItem, QScrollArea, QGridLayout,
    QListWidget, QListWidgetItem, QAbstractItemView
)
from PyQt6.QtCore import Qt, QMimeData, QUrl, QSize
from PyQt6.QtGui import QDragEnterEvent, QDropEvent, QPixmap, QImage

from ....core.key_management import KeyManager
from ....core.encryption import EncryptionEngine
from ....file_handlers.pdf_section_handler import PDFSectionHandler

try:
    import pypdf
    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False

class PDFThumbnail(QLabel):
    """A thumbnail of a PDF page."""

    def __init__(self, page_number, parent=None):
        """Initialize the thumbnail."""
        super().__init__(parent)
        self.page_number = page_number
        self.selected = False
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setFixedSize(120, 160)
        self.setFrameStyle(QFrame.Shape.Box | QFrame.Shadow.Plain)
        self.setLineWidth(1)
        self.setStyleSheet("""
            QLabel {
                background-color: white;
                border: 1px solid #aaa;
                padding: 5px;
            }
        """)

        # Page number label
        self.page_label = QLabel(f"Page {page_number}", self)
        self.page_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.page_label.setStyleSheet("background-color: rgba(255, 255, 255, 0.7);")
        self.page_label.setGeometry(0, 140, 120, 20)

    def set_selected(self, selected):
        """Set whether the thumbnail is selected."""
        self.selected = selected
        if selected:
            self.setStyleSheet("""
                QLabel {
                    background-color: white;
                    border: 3px solid #3498db;
                    padding: 5px;
                }
            """)
        else:
            self.setStyleSheet("""
                QLabel {
                    background-color: white;
                    border: 1px solid #aaa;
                    padding: 5px;
                }
            """)

    def set_image(self, image):
        """Set the thumbnail image."""
        if isinstance(image, QPixmap):
            pixmap = image
        else:
            pixmap = QPixmap.fromImage(image)

        # Scale to fit
        pixmap = pixmap.scaled(
            110, 130,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation
        )
        self.setPixmap(pixmap)

    def mousePressEvent(self, event):
        """Handle mouse press events."""
        self.set_selected(not self.selected)
        self.parent().thumbnail_clicked(self)


class PDFSectionTab(QWidget):
    """PDF Section Encryption tab for the cryptographic system GUI."""

    def __init__(self, key_manager: KeyManager, encryption_engine: EncryptionEngine,
                 pdf_section_handler: PDFSectionHandler):
        """Initialize the PDF section tab."""
        super().__init__()

        self.key_manager = key_manager
        self.encryption_engine = encryption_engine
        self.pdf_section_handler = pdf_section_handler

        self.pdf_path = None
        self.output_path = None
        self.pdf_reader = None
        self.thumbnails = []
        self.selected_pages = set()

        # Set up the UI
        self.setup_ui()

    def setup_ui(self):
        """Set up the UI."""
        # Main layout
        main_layout = QVBoxLayout(self)

        # Check if pypdf is available
        if not PYPDF_AVAILABLE:
            warning_label = QLabel(
                "The pypdf library is not available. "
                "Please install it with 'pip install pypdf' to use this feature."
            )
            warning_label.setStyleSheet("color: red;")
            main_layout.addWidget(warning_label)
            return

        # File selection area
        file_selection_group = QGroupBox("PDF File")
        file_selection_layout = QHBoxLayout(file_selection_group)

        # File path display
        self.file_path_label = QLabel("No PDF file selected")
        file_selection_layout.addWidget(self.file_path_label)

        # Select file button
        select_file_button = QPushButton("Open PDF")
        select_file_button.clicked.connect(self.select_file)
        file_selection_layout.addWidget(select_file_button)

        main_layout.addWidget(file_selection_group)

        # PDF preview and page selection
        preview_group = QGroupBox("PDF Preview and Page Selection")
        preview_layout = QVBoxLayout(preview_group)

        # Instructions
        instructions_label = QLabel("Select the pages you want to encrypt/decrypt:")
        preview_layout.addWidget(instructions_label)

        # Thumbnail grid in a scroll area
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setMinimumHeight(200)

        self.thumbnail_widget = QWidget()
        self.thumbnail_layout = QGridLayout(self.thumbnail_widget)
        self.thumbnail_layout.setSpacing(10)

        scroll_area.setWidget(self.thumbnail_widget)
        preview_layout.addWidget(scroll_area)

        # Page selection buttons
        selection_layout = QHBoxLayout()

        select_all_button = QPushButton("Select All")
        select_all_button.clicked.connect(self.select_all_pages)
        selection_layout.addWidget(select_all_button)

        select_none_button = QPushButton("Select None")
        select_none_button.clicked.connect(self.select_no_pages)
        selection_layout.addWidget(select_none_button)

        select_even_button = QPushButton("Select Even")
        select_even_button.clicked.connect(self.select_even_pages)
        selection_layout.addWidget(select_even_button)

        select_odd_button = QPushButton("Select Odd")
        select_odd_button.clicked.connect(self.select_odd_pages)
        selection_layout.addWidget(select_odd_button)

        preview_layout.addLayout(selection_layout)

        # Selected pages display
        self.selected_pages_label = QLabel("Selected pages: None")
        preview_layout.addWidget(self.selected_pages_label)

        main_layout.addWidget(preview_group)

        # Operation selection
        operation_group = QGroupBox("Operation")
        operation_layout = QHBoxLayout(operation_group)

        # Encrypt/Decrypt radio buttons
        self.encrypt_radio = QRadioButton("Encrypt Pages")
        self.decrypt_radio = QRadioButton("Decrypt Pages")
        self.encrypt_radio.setChecked(True)

        operation_button_group = QButtonGroup(self)
        operation_button_group.addButton(self.encrypt_radio)
        operation_button_group.addButton(self.decrypt_radio)
        operation_button_group.buttonClicked.connect(self.update_ui_for_operation)

        operation_layout.addWidget(self.encrypt_radio)
        operation_layout.addWidget(self.decrypt_radio)
        operation_layout.addStretch()

        main_layout.addWidget(operation_group)

        # Encryption/Decryption options
        options_group = QGroupBox("Options")
        options_layout = QFormLayout(options_group)

        # Method selection (key or password)
        self.method_combo = QComboBox()
        self.method_combo.addItems(["Key", "Password"])
        self.method_combo.currentIndexChanged.connect(self.update_ui_for_method)
        options_layout.addRow("Method:", self.method_combo)

        # Algorithm selection (for encryption)
        self.algorithm_combo = QComboBox()
        self.algorithm_combo.addItems(["AES-GCM", "ChaCha20-Poly1305"])
        options_layout.addRow("Algorithm:", self.algorithm_combo)

        # Key selection
        self.key_combo = QComboBox()
        self.update_key_list()
        options_layout.addRow("Key:", self.key_combo)

        # Password field
        self.password_field = QLineEdit()
        self.password_field.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_field.setPlaceholderText("Enter password")
        options_layout.addRow("Password:", self.password_field)

        # Confirm password field (for encryption)
        self.confirm_password_field = QLineEdit()
        self.confirm_password_field.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_password_field.setPlaceholderText("Confirm password")
        options_layout.addRow("Confirm:", self.confirm_password_field)

        main_layout.addWidget(options_group)

        # Output options
        output_group = QGroupBox("Output")
        output_layout = QFormLayout(output_group)

        # Output path
        output_path_layout = QHBoxLayout()
        self.output_path_field = QLineEdit()
        self.output_path_field.setPlaceholderText("Same directory as input file")
        output_path_layout.addWidget(self.output_path_field)

        # Browse button
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_output_path)
        output_path_layout.addWidget(browse_button)

        output_layout.addRow("Output path:", output_path_layout)

        main_layout.addWidget(output_group)

        # Action buttons
        action_layout = QHBoxLayout()

        # Encrypt/Decrypt button
        self.action_button = QPushButton("Encrypt Selected Pages")
        self.action_button.clicked.connect(self.perform_action)
        action_layout.addWidget(self.action_button)

        main_layout.addLayout(action_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)

        # Results area
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout(results_group)

        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        results_layout.addWidget(self.results_text)

        main_layout.addWidget(results_group)

        # Initialize UI state
        self.update_ui_for_method(0)  # Key method
        self.update_ui_for_operation()

    def update_key_list(self):
        """Update the list of available keys."""
        self.key_combo.clear()

        # Add keys from key manager
        if hasattr(self.key_manager, 'active_keys'):
            for key_id in self.key_manager.active_keys:
                self.key_combo.addItem(key_id)

    def update_ui_for_method(self, index):
        """Update the UI based on the selected method."""
        if index == 0:  # Key
            self.key_combo.setVisible(True)
            self.password_field.setVisible(False)
            self.confirm_password_field.setVisible(False)
        else:  # Password
            self.key_combo.setVisible(False)
            self.password_field.setVisible(True)
            self.confirm_password_field.setVisible(self.encrypt_radio.isChecked())

    def update_ui_for_operation(self):
        """Update the UI based on the selected operation."""
        if self.encrypt_radio.isChecked():
            self.action_button.setText("Encrypt Selected Pages")
            self.algorithm_combo.setVisible(True)
            self.confirm_password_field.setVisible(self.method_combo.currentIndex() == 1)
        else:
            self.action_button.setText("Decrypt Selected Pages")
            self.algorithm_combo.setVisible(False)
            self.confirm_password_field.setVisible(False)

    def select_file(self):
        """Open a file dialog to select a PDF file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select PDF File",
            "",
            "PDF Files (*.pdf);;Encrypted PDF Files (*.pdf.encrypted *.encrypted);;All Files (*)"
        )

        if file_path:
            self.load_pdf(file_path)

    def load_pdf(self, file_path):
        """Load a PDF file."""
        if not PYPDF_AVAILABLE:
            QMessageBox.warning(self, "Library Missing", "The pypdf library is not available. Please install it with 'pip install pypdf'.")
            return

        try:
            self.pdf_path = file_path
            self.file_path_label.setText(os.path.basename(file_path))

            # Determine if this is an encrypted file
            is_encrypted = file_path.endswith('.encrypted') or file_path.endswith('.pdf.encrypted')

            # Set the appropriate operation
            self.encrypt_radio.setChecked(not is_encrypted)
            self.decrypt_radio.setChecked(is_encrypted)

            # Update UI
            self.update_ui_for_operation()

            # Suggest output path
            if is_encrypted:
                # For decryption, remove .encrypted extension
                if file_path.endswith('.pdf.encrypted'):
                    base_path = file_path[:-10]
                elif file_path.endswith('.encrypted'):
                    base_path = file_path[:-10] + '.pdf'
                else:
                    base_path = file_path + '.decrypted.pdf'
                self.output_path_field.setText(base_path)
            else:
                # For encryption, add .encrypted extension
                self.output_path_field.setText(file_path + '.section-encrypted.pdf')

            # Load the PDF
            with open(file_path, 'rb') as f:
                self.pdf_reader = pypdf.PdfReader(f)
                self.load_thumbnails()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load PDF: {str(e)}")

    def load_thumbnails(self):
        """Load thumbnails for the PDF pages."""
        if not self.pdf_reader:
            return

        # Clear existing thumbnails
        self.thumbnails = []
        self.selected_pages = set()

        # Clear the layout
        while self.thumbnail_layout.count():
            item = self.thumbnail_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        # Create thumbnails for each page
        for i, page in enumerate(self.pdf_reader.pages):
            page_number = i + 1

            # Create thumbnail
            thumbnail = PDFThumbnail(page_number, self)

            # Render the PDF page to an image for the thumbnail
            try:
                # Create a blank image as a fallback
                image = QImage(110, 130, QImage.Format.Format_RGB32)
                image.fill(Qt.GlobalColor.white)

                # Try to render the PDF page
                if hasattr(page, 'render'):
                    # For newer versions of pypdf that support direct rendering
                    page_image = page.render()
                    if page_image:
                        image = QImage(page_image)
                else:
                    # For older versions, we'll use a simple representation
                    # This is a placeholder - in a real implementation, we would use a PDF rendering library
                    # like PyMuPDF (fitz) or poppler-qt5

                    # Draw page number on the blank image
                    from PyQt6.QtGui import QPainter, QFont, QPen
                    painter = QPainter(image)
                    painter.setPen(QPen(Qt.GlobalColor.black))
                    font = QFont()
                    font.setPointSize(20)
                    painter.setFont(font)
                    painter.drawText(image.rect(), Qt.AlignmentFlag.AlignCenter, f"Page {page_number}")
                    painter.end()

                thumbnail.set_image(image)
            except Exception as e:
                # If rendering fails, use the blank image
                print(f"Error rendering PDF page {page_number}: {str(e)}")
                thumbnail.set_image(image)

            # Add to layout
            row = i // 5
            col = i % 5
            self.thumbnail_layout.addWidget(thumbnail, row, col)

            # Add to list
            self.thumbnails.append(thumbnail)

        # Update selected pages label
        self.update_selected_pages_label()

    def thumbnail_clicked(self, thumbnail):
        """Handle thumbnail click events."""
        if thumbnail.selected:
            self.selected_pages.add(thumbnail.page_number)
        else:
            self.selected_pages.discard(thumbnail.page_number)

        self.update_selected_pages_label()

    def select_all_pages(self):
        """Select all pages."""
        for thumbnail in self.thumbnails:
            thumbnail.set_selected(True)
            self.selected_pages.add(thumbnail.page_number)

        self.update_selected_pages_label()

    def select_no_pages(self):
        """Deselect all pages."""
        for thumbnail in self.thumbnails:
            thumbnail.set_selected(False)
            self.selected_pages.discard(thumbnail.page_number)

        self.update_selected_pages_label()

    def select_even_pages(self):
        """Select even-numbered pages."""
        for thumbnail in self.thumbnails:
            if thumbnail.page_number % 2 == 0:
                thumbnail.set_selected(True)
                self.selected_pages.add(thumbnail.page_number)
            else:
                thumbnail.set_selected(False)
                self.selected_pages.discard(thumbnail.page_number)

        self.update_selected_pages_label()

    def select_odd_pages(self):
        """Select odd-numbered pages."""
        for thumbnail in self.thumbnails:
            if thumbnail.page_number % 2 == 1:
                thumbnail.set_selected(True)
                self.selected_pages.add(thumbnail.page_number)
            else:
                thumbnail.set_selected(False)
                self.selected_pages.discard(thumbnail.page_number)

        self.update_selected_pages_label()

    def update_selected_pages_label(self):
        """Update the selected pages label."""
        if not self.selected_pages:
            self.selected_pages_label.setText("Selected pages: None")
        else:
            # Convert to list and sort
            pages_list = sorted(list(self.selected_pages))

            # Format as ranges
            ranges = []
            start = pages_list[0]
            end = start

            for i in range(1, len(pages_list)):
                if pages_list[i] == end + 1:
                    end = pages_list[i]
                else:
                    if start == end:
                        ranges.append(str(start))
                    else:
                        ranges.append(f"{start}-{end}")
                    start = end = pages_list[i]

            if start == end:
                ranges.append(str(start))
            else:
                ranges.append(f"{start}-{end}")

            self.selected_pages_label.setText(f"Selected pages: {', '.join(ranges)}")

    def browse_output_path(self):
        """Open a file dialog to select an output path."""
        if self.encrypt_radio.isChecked():
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Encrypted PDF",
                self.output_path_field.text() or (self.pdf_path + '.section-encrypted.pdf' if self.pdf_path else ""),
                "Encrypted PDF Files (*.pdf.encrypted *.section-encrypted.pdf);;All Files (*)"
            )
        else:
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Decrypted PDF",
                self.output_path_field.text() or (self.pdf_path[:-10] if self.pdf_path and (self.pdf_path.endswith('.encrypted') or self.pdf_path.endswith('.pdf.encrypted')) else ""),
                "PDF Files (*.pdf);;All Files (*)"
            )

        if file_path:
            self.output_path_field.setText(file_path)

    def perform_action(self):
        """Perform the selected action (encrypt or decrypt pages)."""
        if not self.pdf_path:
            QMessageBox.warning(self, "No PDF Selected", "Please select a PDF file first.")
            return

        if not self.selected_pages:
            QMessageBox.warning(self, "No Pages Selected", "Please select at least one page.")
            return

        # Get output path
        output_path = self.output_path_field.text()
        if not output_path:
            if self.encrypt_radio.isChecked():
                output_path = self.pdf_path + '.section-encrypted.pdf'
            else:
                if self.pdf_path.endswith('.pdf.encrypted'):
                    output_path = self.pdf_path[:-10]
                elif self.pdf_path.endswith('.encrypted'):
                    output_path = self.pdf_path[:-10] + '.pdf'
                else:
                    output_path = self.pdf_path + '.decrypted.pdf'

        # Check if output file already exists
        if os.path.exists(output_path):
            reply = QMessageBox.question(
                self,
                "File Exists",
                f"The file {output_path} already exists. Overwrite?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                return

        # Get key or password
        key = None
        key_id = None
        password = None

        if self.method_combo.currentIndex() == 0:  # Key
            if self.key_combo.count() == 0:
                QMessageBox.warning(self, "No Keys Available", "No keys available. Please generate or import a key first.")
                return

            key_id = self.key_combo.currentText()
        else:  # Password
            password = self.password_field.text()
            if not password:
                QMessageBox.warning(self, "No Password", "Please enter a password.")
                return

            if self.encrypt_radio.isChecked() and password != self.confirm_password_field.text():
                QMessageBox.warning(self, "Password Mismatch", "Passwords do not match.")
                return

        # Format selected pages
        pages_str = self.format_pages_for_command()

        # Show progress bar
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)

        try:
            # Perform action
            if self.encrypt_radio.isChecked():
                # Encrypt pages
                algorithm = self.algorithm_combo.currentText()

                result = self.pdf_section_handler.encrypt_pages(
                    input_path=self.pdf_path,
                    output_path=output_path,
                    pages=pages_str,
                    key=key,
                    key_id=key_id,
                    password=password,
                    algorithm=algorithm
                )

                # Show result
                self.results_text.append(f"PDF pages encrypted successfully.")
                self.results_text.append(f"Output file: {result['output_path']}")
                self.results_text.append(f"Metadata file: {result['metadata_path']}")
                self.results_text.append(f"Encrypted pages: {result['encrypted_pages']}")

            else:
                # Decrypt pages
                result = self.pdf_section_handler.decrypt_pages(
                    input_path=self.pdf_path,
                    output_path=output_path,
                    key=key,
                    key_id=key_id,
                    password=password
                )

                # Show result
                self.results_text.append(f"PDF pages decrypted successfully.")
                self.results_text.append(f"Output file: {result['output_path']}")
                self.results_text.append(f"Decrypted pages: {result['decrypted_pages']}")

            # Set progress to 100%
            self.progress_bar.setValue(100)

            # Ask if user wants to open the output file
            reply = QMessageBox.question(
                self,
                "Operation Complete",
                f"The operation completed successfully. Would you like to open the output file?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes
            )
            if reply == QMessageBox.StandardButton.Yes:
                # Open the output file
                import subprocess
                import platform

                if platform.system() == 'Windows':
                    os.startfile(output_path)
                elif platform.system() == 'Darwin':  # macOS
                    subprocess.call(('open', output_path))
                else:  # Linux
                    subprocess.call(('xdg-open', output_path))

        except Exception as e:
            # Show error
            self.results_text.append(f"Error: {str(e)}")
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")

        # Hide progress bar after a delay
        self.progress_bar.setVisible(False)

    def format_pages_for_command(self) -> str:
        """Format selected pages for the command."""
        if not self.selected_pages:
            return ""

        # Convert to list and sort
        pages_list = sorted(list(self.selected_pages))

        # Format as ranges
        ranges = []
        start = pages_list[0]
        end = start

        for i in range(1, len(pages_list)):
            if pages_list[i] == end + 1:
                end = pages_list[i]
            else:
                if start == end:
                    ranges.append(str(start))
                else:
                    ranges.append(f"{start}-{end}")
                start = end = pages_list[i]

        if start == end:
            ranges.append(str(start))
        else:
            ranges.append(f"{start}-{end}")

        return ",".join(ranges)
