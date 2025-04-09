"""
Directory Encryption/Decryption tab for the cryptographic system GUI.
"""

import os
import getpass
from typing import Optional, Dict, Any, List
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox,
    QRadioButton, QButtonGroup, QFileDialog, QLineEdit, QProgressBar,
    QTextEdit, QGroupBox, QFormLayout, QCheckBox, QMessageBox,
    QSizePolicy, QFrame, QSpacerItem, QTreeView, QHeaderView
)
from PyQt6.QtCore import Qt, QMimeData, QUrl, QDir, QThread, pyqtSignal, QModelIndex
from PyQt6.QtGui import QDragEnterEvent, QDropEvent, QStandardItemModel, QStandardItem

from ....core.key_management import KeyManager
from ....core.encryption import EncryptionEngine
from ....file_handlers.directory_handler import DirectoryHandler

class DirectoryWorker(QThread):
    """Worker thread for directory operations."""
    
    progress = pyqtSignal(int, int, str)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, operation, directory_handler, **kwargs):
        """Initialize the worker thread."""
        super().__init__()
        self.operation = operation
        self.directory_handler = directory_handler
        self.kwargs = kwargs
    
    def run(self):
        """Run the operation."""
        try:
            # Add progress callback
            self.kwargs['progress_callback'] = self.progress_callback
            
            # Run the operation
            if self.operation == 'encrypt':
                result = self.directory_handler.encrypt_directory(**self.kwargs)
            else:  # decrypt
                result = self.directory_handler.decrypt_directory(**self.kwargs)
            
            # Emit finished signal
            self.finished.emit(result)
        
        except Exception as e:
            # Emit error signal
            self.error.emit(str(e))
    
    def progress_callback(self, processed, total, current_file):
        """Progress callback function."""
        self.progress.emit(processed, total, current_file)


class DirectoryTab(QWidget):
    """Directory Encryption/Decryption tab for the cryptographic system GUI."""
    
    def __init__(self, key_manager: KeyManager, encryption_engine: EncryptionEngine):
        """Initialize the directory tab."""
        super().__init__()
        
        self.key_manager = key_manager
        self.encryption_engine = encryption_engine
        self.directory_handler = DirectoryHandler(key_manager, encryption_engine)
        
        self.input_path = None
        self.output_path = None
        self.worker = None
        
        # Set up the UI
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the UI."""
        # Main layout
        main_layout = QVBoxLayout(self)
        
        # Directory selection area
        directory_selection_group = QGroupBox("Directory Selection")
        directory_selection_layout = QVBoxLayout(directory_selection_group)
        
        # Input directory
        input_dir_layout = QHBoxLayout()
        self.input_dir_label = QLabel("No directory selected")
        input_dir_layout.addWidget(QLabel("Input Directory:"))
        input_dir_layout.addWidget(self.input_dir_label, 1)
        
        # Select input directory button
        select_input_button = QPushButton("Select Directory")
        select_input_button.clicked.connect(self.select_input_directory)
        input_dir_layout.addWidget(select_input_button)
        
        directory_selection_layout.addLayout(input_dir_layout)
        
        # Directory tree view
        self.directory_model = QStandardItemModel()
        self.directory_model.setHorizontalHeaderLabels(["Name", "Type", "Size"])
        
        self.directory_tree = QTreeView()
        self.directory_tree.setModel(self.directory_model)
        self.directory_tree.setAlternatingRowColors(True)
        self.directory_tree.setSortingEnabled(True)
        self.directory_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.directory_tree.setMinimumHeight(200)
        
        directory_selection_layout.addWidget(self.directory_tree)
        
        main_layout.addWidget(directory_selection_group)
        
        # Operation selection
        operation_group = QGroupBox("Operation")
        operation_layout = QHBoxLayout(operation_group)
        
        # Encrypt/Decrypt radio buttons
        self.encrypt_radio = QRadioButton("Encrypt Directory")
        self.decrypt_radio = QRadioButton("Decrypt Directory")
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
        self.output_path_field.setPlaceholderText("Same directory as input with .dir.encrypted extension")
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
        self.action_button = QPushButton("Encrypt Directory")
        self.action_button.clicked.connect(self.perform_action)
        action_layout.addWidget(self.action_button)
        
        # Cancel button
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.cancel_operation)
        self.cancel_button.setEnabled(False)
        action_layout.addWidget(self.cancel_button)
        
        main_layout.addLayout(action_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)
        
        # Progress label
        self.progress_label = QLabel("")
        self.progress_label.setVisible(False)
        main_layout.addWidget(self.progress_label)
        
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
            self.action_button.setText("Encrypt Directory")
            self.algorithm_combo.setVisible(True)
            self.confirm_password_field.setVisible(self.method_combo.currentIndex() == 1)
        else:
            self.action_button.setText("Decrypt Directory")
            self.algorithm_combo.setVisible(False)
            self.confirm_password_field.setVisible(False)
    
    def select_input_directory(self):
        """Open a directory dialog to select an input directory."""
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select Directory",
            "",
            QFileDialog.Option.ShowDirsOnly
        )
        
        if directory:
            self.load_directory(directory)
    
    def load_directory(self, directory):
        """Load a directory."""
        self.input_path = directory
        self.input_dir_label.setText(os.path.basename(directory) or directory)
        
        # Determine if this is an encrypted directory
        is_encrypted = directory.endswith('.dir.encrypted')
        
        # Set the appropriate operation
        self.encrypt_radio.setChecked(not is_encrypted)
        self.decrypt_radio.setChecked(is_encrypted)
        
        # Update UI
        self.update_ui_for_operation()
        
        # Suggest output path
        if is_encrypted:
            # For decryption, remove .dir.encrypted extension
            base_path = directory[:-14] if directory.endswith('.dir.encrypted') else directory
            self.output_path_field.setText(base_path + '.decrypted')
        else:
            # For encryption, add .dir.encrypted extension
            self.output_path_field.setText(directory + '.dir.encrypted')
        
        # Populate directory tree
        self.populate_directory_tree(directory)
    
    def populate_directory_tree(self, directory):
        """Populate the directory tree view."""
        self.directory_model.clear()
        self.directory_model.setHorizontalHeaderLabels(["Name", "Type", "Size"])
        
        root_item = self.directory_model.invisibleRootItem()
        
        # Add the root directory
        root_dir_item = QStandardItem(os.path.basename(directory) or directory)
        root_dir_item.setData(directory, Qt.ItemDataRole.UserRole)
        root_item.appendRow([
            root_dir_item,
            QStandardItem("Directory"),
            QStandardItem("")
        ])
        
        # Expand the root directory
        self.directory_tree.setExpanded(root_dir_item.index(), True)
        
        # Add subdirectories and files (limit to first level for performance)
        try:
            for item in os.listdir(directory):
                item_path = os.path.join(directory, item)
                
                if os.path.isdir(item_path):
                    # Add directory
                    dir_item = QStandardItem(item)
                    dir_item.setData(item_path, Qt.ItemDataRole.UserRole)
                    root_dir_item.appendRow([
                        dir_item,
                        QStandardItem("Directory"),
                        QStandardItem("")
                    ])
                else:
                    # Add file
                    file_size = os.path.getsize(item_path)
                    file_size_str = self.format_size(file_size)
                    
                    file_item = QStandardItem(item)
                    file_item.setData(item_path, Qt.ItemDataRole.UserRole)
                    root_dir_item.appendRow([
                        file_item,
                        QStandardItem("File"),
                        QStandardItem(file_size_str)
                    ])
        
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Error reading directory: {str(e)}")
    
    def format_size(self, size_bytes):
        """Format file size in human-readable format."""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
    
    def browse_output_path(self):
        """Open a directory dialog to select an output path."""
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select Output Directory",
            self.output_path_field.text() or "",
            QFileDialog.Option.ShowDirsOnly
        )
        
        if directory:
            self.output_path_field.setText(directory)
    
    def perform_action(self):
        """Perform the selected action (encrypt or decrypt)."""
        if not self.input_path:
            QMessageBox.warning(self, "No Directory Selected", "Please select a directory first.")
            return
        
        # Get output path
        output_path = self.output_path_field.text()
        if not output_path:
            if self.encrypt_radio.isChecked():
                output_path = self.input_path + '.dir.encrypted'
            else:
                output_path = self.input_path[:-14] if self.input_path.endswith('.dir.encrypted') else self.input_path + '.decrypted'
        
        # Check if output directory already exists
        if os.path.exists(output_path):
            reply = QMessageBox.question(
                self,
                "Directory Exists",
                f"The directory {output_path} already exists. Overwrite?",
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
        
        # Prepare worker thread parameters
        operation = 'encrypt' if self.encrypt_radio.isChecked() else 'decrypt'
        kwargs = {
            'input_path': self.input_path,
            'output_path': output_path,
            'key': key,
            'key_id': key_id,
            'password': password
        }
        
        if operation == 'encrypt':
            kwargs['algorithm'] = self.algorithm_combo.currentText()
        
        # Show progress bar
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.progress_label.setVisible(True)
        self.progress_label.setText("Preparing...")
        
        # Disable UI elements
        self.action_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        
        # Create and start worker thread
        self.worker = DirectoryWorker(operation, self.directory_handler, **kwargs)
        self.worker.progress.connect(self.update_progress)
        self.worker.finished.connect(self.operation_finished)
        self.worker.error.connect(self.operation_error)
        self.worker.start()
    
    def update_progress(self, processed, total, current_file):
        """Update the progress bar and label."""
        percent = (processed / total) * 100 if total > 0 else 0
        self.progress_bar.setValue(int(percent))
        self.progress_label.setText(f"Processing: {current_file}")
    
    def operation_finished(self, result):
        """Handle operation finished."""
        # Enable UI elements
        self.action_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        
        # Hide progress bar
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)
        
        # Show result
        operation = 'encrypted' if self.encrypt_radio.isChecked() else 'decrypted'
        self.results_text.append(f"Directory {operation} successfully.")
        self.results_text.append(f"Output directory: {result['output_path']}")
        self.results_text.append(f"Total files: {result['total_files']}")
        self.results_text.append(f"Processed files: {result['processed_files']}")
        
        time_key = 'encryption_time' if self.encrypt_radio.isChecked() else 'decryption_time'
        self.results_text.append(f"Processing time: {result[time_key]:.2f} seconds")
        
        if result.get('key_id'):
            self.results_text.append(f"Key ID: {result['key_id']}")
            self.results_text.append("Keep this Key ID for decryption!")
        
        # Ask if user wants to open the output directory
        reply = QMessageBox.question(
            self,
            "Operation Complete",
            f"The operation completed successfully. Would you like to open the output directory?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes
        )
        if reply == QMessageBox.StandardButton.Yes:
            # Open the output directory
            import subprocess
            import platform
            
            if platform.system() == 'Windows':
                os.startfile(result['output_path'])
            elif platform.system() == 'Darwin':  # macOS
                subprocess.call(('open', result['output_path']))
            else:  # Linux
                subprocess.call(('xdg-open', result['output_path']))
    
    def operation_error(self, error_message):
        """Handle operation error."""
        # Enable UI elements
        self.action_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        
        # Hide progress bar
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)
        
        # Show error
        self.results_text.append(f"Error: {error_message}")
        QMessageBox.critical(self, "Error", f"An error occurred: {error_message}")
    
    def cancel_operation(self):
        """Cancel the current operation."""
        if self.worker and self.worker.isRunning():
            # Terminate the worker thread
            self.worker.terminate()
            self.worker.wait()
            
            # Enable UI elements
            self.action_button.setEnabled(True)
            self.cancel_button.setEnabled(False)
            
            # Hide progress bar
            self.progress_bar.setVisible(False)
            self.progress_label.setVisible(False)
            
            # Show message
            self.results_text.append("Operation cancelled.")
            QMessageBox.information(self, "Operation Cancelled", "The operation was cancelled.")
