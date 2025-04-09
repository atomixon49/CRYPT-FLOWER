"""
Encryption/Decryption tab for the cryptographic system GUI.
"""

import os
import getpass
from typing import Optional, Dict, Any
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox,
    QRadioButton, QButtonGroup, QFileDialog, QLineEdit, QProgressBar,
    QTextEdit, QGroupBox, QFormLayout, QCheckBox, QMessageBox,
    QSizePolicy, QFrame, QSpacerItem, QApplication
)
from PyQt6.QtCore import Qt, QMimeData, QUrl
from PyQt6.QtGui import QDragEnterEvent, QDropEvent

from ....core.key_management import KeyManager, POSTQUANTUM_AVAILABLE, PQ_SIGN_ALGORITHMS, PQ_KEM_ALGORITHMS
from ....core.encryption import EncryptionEngine
from ....file_handlers.text_handler import TextFileHandler
from ....file_handlers.pdf_handler import PDFHandler

class DropArea(QLabel):
    """A widget that accepts file drops."""

    def __init__(self, parent=None):
        """Initialize the drop area."""
        super().__init__(parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setText("Drag and drop files here\nor click to select")
        self.setStyleSheet("""
            QLabel {
                border: 2px dashed #aaa;
                border-radius: 5px;
                padding: 20px;
                background-color: #f8f8f8;
            }
        """)
        self.setAcceptDrops(True)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setMinimumHeight(200)

    def dragEnterEvent(self, event: QDragEnterEvent):
        """Handle drag enter events."""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        """Handle drop events."""
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls:
                file_path = urls[0].toLocalFile()
                self.parent().load_file(file_path)
                event.acceptProposedAction()

    def mousePressEvent(self, event):
        """Handle mouse press events."""
        self.parent().select_file()


class EncryptionTab(QWidget):
    """Encryption/Decryption tab for the cryptographic system GUI."""

    def __init__(self, key_manager: KeyManager, encryption_engine: EncryptionEngine,
                 text_handler: TextFileHandler, pdf_handler: PDFHandler):
        """Initialize the encryption tab."""
        super().__init__()

        self.key_manager = key_manager
        self.encryption_engine = encryption_engine
        self.text_handler = text_handler
        self.pdf_handler = pdf_handler

        self.file_path = None
        self.output_path = None

        # Set up the UI
        self.setup_ui()

    def setup_ui(self):
        """Set up the UI."""
        # Main layout
        main_layout = QVBoxLayout(self)

        # File selection area
        file_selection_group = QGroupBox("File Selection")
        file_selection_layout = QVBoxLayout(file_selection_group)

        # Drop area
        self.drop_area = DropArea(self)
        file_selection_layout.addWidget(self.drop_area)

        # File path display
        file_path_layout = QHBoxLayout()
        self.file_path_label = QLabel("No file selected")
        file_path_layout.addWidget(self.file_path_label)

        # Select file button
        select_file_button = QPushButton("Select File")
        select_file_button.clicked.connect(self.select_file)
        file_path_layout.addWidget(select_file_button)

        file_selection_layout.addLayout(file_path_layout)
        main_layout.addWidget(file_selection_group)

        # Operation selection
        operation_group = QGroupBox("Operation")
        operation_layout = QHBoxLayout(operation_group)

        # Encrypt/Decrypt radio buttons
        self.encrypt_radio = QRadioButton("Encrypt")
        self.decrypt_radio = QRadioButton("Decrypt")
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

        # Add post-quantum algorithms if available
        if POSTQUANTUM_AVAILABLE:
            # Only add KEM algorithms (for encryption)
            for alg in PQ_KEM_ALGORITHMS:
                self.algorithm_combo.addItem(alg)

        # Connect algorithm change to key list update
        self.algorithm_combo.currentIndexChanged.connect(self.update_key_list)

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
        self.action_button = QPushButton("Encrypt")
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

        # Get the selected algorithm
        algorithm = self.algorithm_combo.currentText()
        is_post_quantum = algorithm in PQ_KEM_ALGORITHMS

        # Add keys from key manager
        if hasattr(self.key_manager, 'active_keys'):
            for key_id, key_info in self.key_manager.active_keys.items():
                # For post-quantum algorithms, only show post-quantum keys
                key_is_pq = key_info.get('post_quantum', False)

                # Only show public keys for encryption
                is_public = key_id.endswith('.public') or key_info.get('key_type') == 'public'

                # Filter keys based on algorithm type
                if is_post_quantum and key_is_pq and is_public:
                    # For post-quantum, only show KEM keys
                    if key_info.get('algorithm') in PQ_KEM_ALGORITHMS:
                        self.key_combo.addItem(key_id)
                elif not is_post_quantum and not key_is_pq:
                    # For traditional algorithms, show traditional keys
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
            self.action_button.setText("Encrypt")
            self.algorithm_combo.setVisible(True)
            self.confirm_password_field.setVisible(self.method_combo.currentIndex() == 1)
        else:
            self.action_button.setText("Decrypt")
            self.algorithm_combo.setVisible(False)
            self.confirm_password_field.setVisible(False)

    def select_file(self):
        """Open a file dialog to select a file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File",
            "",
            "All Files (*)"
        )

        if file_path:
            self.load_file(file_path)

    def load_file(self, file_path):
        """Load a file."""
        self.file_path = file_path
        self.file_path_label.setText(os.path.basename(file_path))

        # Determine if this is an encrypted file
        is_encrypted = file_path.endswith('.encrypted')

        # Set the appropriate operation
        self.encrypt_radio.setChecked(not is_encrypted)
        self.decrypt_radio.setChecked(is_encrypted)

        # Update UI
        self.update_ui_for_operation()

        # Suggest output path
        if is_encrypted:
            # For decryption, remove .encrypted extension
            base_path = file_path[:-10] if file_path.endswith('.encrypted') else file_path
            self.output_path_field.setText(base_path)
        else:
            # For encryption, add .encrypted extension
            self.output_path_field.setText(file_path + '.encrypted')

    def browse_output_path(self):
        """Open a file dialog to select an output path."""
        if self.encrypt_radio.isChecked():
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Encrypted File",
                self.output_path_field.text() or (self.file_path + '.encrypted' if self.file_path else ""),
                "Encrypted Files (*.encrypted);;All Files (*)"
            )
        else:
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Decrypted File",
                self.output_path_field.text() or (self.file_path[:-10] if self.file_path and self.file_path.endswith('.encrypted') else ""),
                "All Files (*)"
            )

        if file_path:
            self.output_path_field.setText(file_path)

    def perform_action(self):
        """Perform the selected action (encrypt or decrypt)."""
        if not self.file_path:
            QMessageBox.warning(self, "No File Selected", "Please select a file first.")
            return

        # Get output path
        output_path = self.output_path_field.text()
        if not output_path:
            if self.encrypt_radio.isChecked():
                output_path = self.file_path + '.encrypted'
            else:
                output_path = self.file_path[:-10] if self.file_path.endswith('.encrypted') else self.file_path + '.decrypted'

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

        # Show progress bar and status message
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("%p% - Preparing operation...")

        # Create status label if it doesn't exist
        if not hasattr(self, 'status_label'):
            self.status_label = QLabel("")
            self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.layout().insertWidget(self.layout().count()-1, self.status_label)

        # Show status
        self.status_label.setText("Starting operation...")
        self.status_label.setVisible(True)

        # Update UI
        QApplication.processEvents()

        try:
            # Determine file type and handler
            is_pdf = self.file_path.lower().endswith('.pdf') or (
                self.file_path.lower().endswith('.encrypted') and
                os.path.splitext(os.path.splitext(self.file_path)[0])[1].lower() == '.pdf'
            )

            handler = self.pdf_handler if is_pdf else self.text_handler

            # Perform action
            if self.encrypt_radio.isChecked():
                # Encrypt
                algorithm = self.algorithm_combo.currentText()
                is_post_quantum = algorithm in PQ_KEM_ALGORITHMS

                # For post-quantum encryption, we need to handle it differently
                if is_post_quantum:
                    # Check if we have a key (post-quantum encryption requires a key)
                    if not key_id:
                        QMessageBox.warning(self, "No Key Selected", "Post-quantum encryption requires a key. Please select a key.")
                        self.progress_bar.setVisible(False)
                        return

                    # Get the key info
                    key_info = self.key_manager.active_keys.get(key_id)
                    if not key_info or not key_info.get('post_quantum'):
                        QMessageBox.warning(self, "Invalid Key", "The selected key is not a post-quantum key.")
                        self.progress_bar.setVisible(False)
                        return

                    # Get the key
                    key = key_info.get('key')

                    # Update status
                    self.status_label.setText(f"Reading file: {os.path.basename(self.file_path)}")
                    self.progress_bar.setFormat("%p% - Reading file...")
                    self.progress_bar.setValue(10)
                    QApplication.processEvents()

                    # Read the file content
                    with open(self.file_path, 'rb') as f:
                        file_content = f.read()

                    # Update status
                    self.status_label.setText(f"Encrypting with {algorithm}...")
                    self.progress_bar.setFormat("%p% - Encrypting...")
                    self.progress_bar.setValue(40)
                    QApplication.processEvents()

                    # Encrypt with post-quantum algorithm
                    try:
                        encrypted_data = self.encryption_engine.encrypt(
                            data=file_content,
                            key=key,
                            algorithm=algorithm
                        )

                        # Update status
                        self.status_label.setText("Writing encrypted file...")
                        self.progress_bar.setFormat("%p% - Writing file...")
                        self.progress_bar.setValue(70)
                        QApplication.processEvents()

                        # Write the encrypted data to the output file
                        with open(output_path, 'wb') as f:
                            f.write(encrypted_data['ciphertext'])

                        # Create a result dictionary similar to the handlers
                        result = {
                            'output_path': output_path,
                            'algorithm': algorithm,
                            'post_quantum': True
                        }

                        # Update status
                        self.status_label.setText("Encryption completed successfully!")
                        self.progress_bar.setFormat("%p% - Complete")
                        self.progress_bar.setValue(100)
                        QApplication.processEvents()

                        # Show result
                        self.results_text.append(f"File encrypted successfully with post-quantum algorithm.")
                        self.results_text.append(f"Algorithm: {algorithm}")
                        self.results_text.append(f"Output file: {result['output_path']}")
                    except Exception as e:
                        QMessageBox.critical(self, "Encryption Error", f"Error encrypting file: {str(e)}")
                        self.progress_bar.setVisible(False)
                        return
                else:
                    # Traditional encryption
                    if is_pdf:
                        result = handler.encrypt_pdf(
                            input_path=self.file_path,
                            output_path=output_path,
                            key=key,
                            key_id=key_id,
                            password=password,
                            algorithm=algorithm
                        )
                    else:
                        result = handler.encrypt_file(
                            input_path=self.file_path,
                            output_path=output_path,
                            key=key,
                            key_id=key_id,
                            password=password,
                            algorithm=algorithm
                        )

                    # Show result
                    self.results_text.append(f"File encrypted successfully.")
                    self.results_text.append(f"Output file: {result['output_path']}")

            else:
                # Decrypt
                # Check if this is a post-quantum encrypted file
                is_post_quantum = False

                # Try to determine if this is a post-quantum encrypted file
                # This is a simplified approach - in a real implementation, you would
                # store metadata in the encrypted file to identify the algorithm
                if key_id:
                    key_info = self.key_manager.active_keys.get(key_id)
                    if key_info and key_info.get('post_quantum'):
                        is_post_quantum = True

                if is_post_quantum:
                    # Check if we have a key (post-quantum decryption requires a key)
                    if not key_id:
                        QMessageBox.warning(self, "No Key Selected", "Post-quantum decryption requires a key. Please select a key.")
                        self.progress_bar.setVisible(False)
                        return

                    # Get the key info
                    key_info = self.key_manager.active_keys.get(key_id)
                    if not key_info or not key_info.get('post_quantum'):
                        QMessageBox.warning(self, "Invalid Key", "The selected key is not a post-quantum key.")
                        self.progress_bar.setVisible(False)
                        return

                    # Get the key
                    key = key_info.get('key')
                    algorithm = key_info.get('algorithm')

                    # Update status
                    self.status_label.setText(f"Reading encrypted file: {os.path.basename(self.file_path)}")
                    self.progress_bar.setFormat("%p% - Reading file...")
                    self.progress_bar.setValue(10)
                    QApplication.processEvents()

                    # Read the encrypted file content
                    with open(self.file_path, 'rb') as f:
                        encrypted_content = f.read()

                    # Update status
                    self.status_label.setText(f"Decrypting with {algorithm}...")
                    self.progress_bar.setFormat("%p% - Decrypting...")
                    self.progress_bar.setValue(40)
                    QApplication.processEvents()

                    # Decrypt with post-quantum algorithm
                    try:
                        # This is a simplified approach - in a real implementation, you would
                        # need to extract the KEM ciphertext and other metadata from the file
                        decrypted_data = self.encryption_engine.decrypt(
                            ciphertext=encrypted_content,
                            key=key,
                            algorithm=algorithm
                        )

                        # Update status
                        self.status_label.setText("Writing decrypted file...")
                        self.progress_bar.setFormat("%p% - Writing file...")
                        self.progress_bar.setValue(70)
                        QApplication.processEvents()

                        # Write the decrypted data to the output file
                        with open(output_path, 'wb') as f:
                            f.write(decrypted_data)

                        # Create a result dictionary similar to the handlers
                        result = {
                            'output_path': output_path,
                            'algorithm': algorithm,
                            'post_quantum': True
                        }

                        # Update status
                        self.status_label.setText("Decryption completed successfully!")
                        self.progress_bar.setFormat("%p% - Complete")
                        self.progress_bar.setValue(100)
                        QApplication.processEvents()

                        # Show result
                        self.results_text.append(f"File decrypted successfully with post-quantum algorithm.")
                        self.results_text.append(f"Algorithm: {algorithm}")
                        self.results_text.append(f"Output file: {result['output_path']}")
                    except Exception as e:
                        QMessageBox.critical(self, "Decryption Error", f"Error decrypting file: {str(e)}")
                        self.progress_bar.setVisible(False)
                        return
                else:
                    # Traditional decryption
                    if is_pdf:
                        result = handler.decrypt_pdf(
                            input_path=self.file_path,
                            output_path=output_path,
                            key=key,
                            key_id=key_id,
                            password=password
                        )
                    else:
                        result = handler.decrypt_file(
                            input_path=self.file_path,
                            output_path=output_path,
                            key=key,
                            key_id=key_id,
                            password=password
                        )

                    # Show result
                    self.results_text.append(f"File decrypted successfully.")
                    self.results_text.append(f"Output file: {result['output_path']}")

            # Set progress to 100% and update status
            self.progress_bar.setValue(100)
            self.progress_bar.setFormat("%p% - Complete")
            if hasattr(self, 'status_label'):
                self.status_label.setText("Operation completed successfully!")

        except Exception as e:
            # Show error
            self.results_text.append(f"Error: {str(e)}")
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")

            # Hide progress bar and status
            self.progress_bar.setVisible(False)
            if hasattr(self, 'status_label'):
                self.status_label.setVisible(False)
            return

        # Keep progress bar and status visible for a few seconds
        # We'll use a timer to hide them after 3 seconds
        from PyQt6.QtCore import QTimer
        QTimer.singleShot(3000, lambda: self.progress_bar.setVisible(False))
        if hasattr(self, 'status_label'):
            QTimer.singleShot(3000, lambda: self.status_label.setVisible(False))
