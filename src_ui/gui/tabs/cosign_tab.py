"""
Co-Signing Tab

This module provides a GUI tab for co-signing documents.
"""

import os
import json
import base64
from typing import List, Dict, Any, Optional
import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QFileDialog, QMessageBox, QListWidget, QListWidgetItem, QCheckBox,
    QComboBox, QGroupBox, QFormLayout, QSplitter, QTextEdit, QTableWidget,
    QTableWidgetItem, QHeaderView
)
from PyQt6.QtCore import Qt, pyqtSignal

from ....core.cosign import CoSignatureManager
from ....core.key_management import KeyManager

class CoSignTab(QWidget):
    """Tab for co-signing operations."""
    
    def __init__(self, parent=None):
        """Initialize the co-sign tab."""
        super().__init__(parent)
        
        # Initialize components
        self.key_manager = KeyManager()
        self.cosign_manager = CoSignatureManager(self.key_manager)
        
        # Set up the UI
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        # Main layout
        main_layout = QVBoxLayout()
        
        # File selection section
        file_group = QGroupBox("File Selection")
        file_layout = QFormLayout()
        
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setReadOnly(True)
        
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_file)
        
        file_path_layout = QHBoxLayout()
        file_path_layout.addWidget(self.file_path_edit)
        file_path_layout.addWidget(browse_button)
        
        file_layout.addRow("File to sign:", file_path_layout)
        
        self.signature_path_edit = QLineEdit()
        self.signature_path_edit.setReadOnly(True)
        
        signature_browse_button = QPushButton("Browse...")
        signature_browse_button.clicked.connect(self.browse_signature)
        
        signature_path_layout = QHBoxLayout()
        signature_path_layout.addWidget(self.signature_path_edit)
        signature_path_layout.addWidget(signature_browse_button)
        
        file_layout.addRow("Signature file:", signature_path_layout)
        
        file_group.setLayout(file_layout)
        main_layout.addWidget(file_group)
        
        # Signing key section
        key_group = QGroupBox("Signing Key")
        key_layout = QFormLayout()
        
        self.key_combo = QComboBox()
        self.key_combo.setMinimumWidth(300)
        
        refresh_keys_button = QPushButton("Refresh")
        refresh_keys_button.clicked.connect(self.load_keys)
        
        key_layout_row = QHBoxLayout()
        key_layout_row.addWidget(self.key_combo)
        key_layout_row.addWidget(refresh_keys_button)
        
        key_layout.addRow("Your signing key:", key_layout_row)
        
        self.algorithm_combo = QComboBox()
        self.algorithm_combo.addItems(["RSA-PSS", "RSA-PKCS1v15"])
        
        key_layout.addRow("Signature algorithm:", self.algorithm_combo)
        
        key_group.setLayout(key_layout)
        main_layout.addWidget(key_group)
        
        # Required signers section
        signers_group = QGroupBox("Required Signers")
        signers_layout = QVBoxLayout()
        
        # Available keys list
        keys_layout = QHBoxLayout()
        
        available_keys_layout = QVBoxLayout()
        available_keys_label = QLabel("Available Keys:")
        self.available_keys_list = QListWidget()
        self.available_keys_list.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        
        available_keys_layout.addWidget(available_keys_label)
        available_keys_layout.addWidget(self.available_keys_list)
        
        # Buttons for adding/removing signers
        buttons_layout = QVBoxLayout()
        self.add_signer_button = QPushButton("Add >")
        self.add_signer_button.clicked.connect(self.add_signer)
        
        self.remove_signer_button = QPushButton("< Remove")
        self.remove_signer_button.clicked.connect(self.remove_signer)
        
        buttons_layout.addStretch()
        buttons_layout.addWidget(self.add_signer_button)
        buttons_layout.addWidget(self.remove_signer_button)
        buttons_layout.addStretch()
        
        # Selected signers list
        selected_signers_layout = QVBoxLayout()
        selected_signers_label = QLabel("Required Signers:")
        self.selected_signers_list = QListWidget()
        self.selected_signers_list.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        
        selected_signers_layout.addWidget(selected_signers_label)
        selected_signers_layout.addWidget(self.selected_signers_list)
        
        keys_layout.addLayout(available_keys_layout)
        keys_layout.addLayout(buttons_layout)
        keys_layout.addLayout(selected_signers_layout)
        
        signers_layout.addLayout(keys_layout)
        
        signers_group.setLayout(signers_layout)
        main_layout.addWidget(signers_group)
        
        # Signature status section
        status_group = QGroupBox("Signature Status")
        status_layout = QVBoxLayout()
        
        self.status_table = QTableWidget()
        self.status_table.setColumnCount(4)
        self.status_table.setHorizontalHeaderLabels(["Sequence", "Signer", "Timestamp", "Status"])
        self.status_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        status_layout.addWidget(self.status_table)
        
        status_group.setLayout(status_layout)
        main_layout.addWidget(status_group)
        
        # Action buttons
        actions_layout = QHBoxLayout()
        
        self.create_button = QPushButton("Create Signature Chain")
        self.create_button.clicked.connect(self.create_signature_chain)
        
        self.sign_button = QPushButton("Sign")
        self.sign_button.clicked.connect(self.sign_document)
        
        self.verify_button = QPushButton("Verify")
        self.verify_button.clicked.connect(self.verify_signatures)
        
        self.status_button = QPushButton("Check Status")
        self.status_button.clicked.connect(self.check_status)
        
        actions_layout.addWidget(self.create_button)
        actions_layout.addWidget(self.sign_button)
        actions_layout.addWidget(self.verify_button)
        actions_layout.addWidget(self.status_button)
        
        main_layout.addLayout(actions_layout)
        
        # Set the main layout
        self.setLayout(main_layout)
        
        # Load keys
        self.load_keys()
    
    def load_keys(self):
        """Load available keys from the key manager."""
        try:
            # Clear the lists
            self.available_keys_list.clear()
            self.key_combo.clear()
            
            # Get all keys
            keys = self.key_manager.active_keys
            
            # Add private keys to the key combo
            for key_id, key_data in keys.items():
                # Only show private keys for signing
                if key_id.endswith('.private') or key_data.get('key_type') == 'private':
                    # Add to the combo box
                    self.key_combo.addItem(key_id)
            
            # Add public keys to the available keys list
            for key_id, key_data in keys.items():
                # Only show public keys for required signers
                if key_id.endswith('.public') or key_data.get('key_type') == 'public':
                    # Create a list item with the key ID
                    item = QListWidgetItem(key_id)
                    
                    # Add key info as tooltip
                    key_info = self.key_manager.get_key_info(key_id)
                    tooltip = f"ID: {key_id}\n"
                    tooltip += f"Algorithm: {key_info.get('algorithm', 'Unknown')}\n"
                    tooltip += f"Created: {key_info.get('created_str', 'Unknown')}"
                    
                    item.setToolTip(tooltip)
                    
                    # Add to the list
                    self.available_keys_list.addItem(item)
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load keys: {str(e)}")
    
    def browse_file(self):
        """Browse for a file to sign."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File to Sign", "", "All Files (*)"
        )
        
        if file_path:
            self.file_path_edit.setText(file_path)
            
            # Set default signature path
            signature_path = file_path + ".cosig"
            self.signature_path_edit.setText(signature_path)
    
    def browse_signature(self):
        """Browse for a signature file."""
        signature_path, _ = QFileDialog.getOpenFileName(
            self, "Select Signature File", "", "Signature Files (*.cosig);;All Files (*)"
        )
        
        if signature_path:
            self.signature_path_edit.setText(signature_path)
            
            # Try to load and display signature status
            self.check_status()
    
    def add_signer(self):
        """Add selected keys to the required signers list."""
        # Get selected items
        selected_items = self.available_keys_list.selectedItems()
        
        for item in selected_items:
            # Check if the key is already in the signers list
            existing_items = self.selected_signers_list.findItems(
                item.text(), Qt.MatchFlag.MatchExactly
            )
            
            if not existing_items:
                # Add to signers list
                self.selected_signers_list.addItem(item.text())
    
    def remove_signer(self):
        """Remove selected keys from the required signers list."""
        # Get selected items
        selected_items = self.selected_signers_list.selectedItems()
        
        for item in selected_items:
            # Remove from the list
            row = self.selected_signers_list.row(item)
            self.selected_signers_list.takeItem(row)
    
    def create_signature_chain(self):
        """Create a new co-signature chain."""
        try:
            # Get the file path
            file_path = self.file_path_edit.text()
            if not file_path:
                QMessageBox.warning(self, "Warning", "Please select a file to sign.")
                return
            
            # Get the signature path
            signature_path = self.signature_path_edit.text()
            if not signature_path:
                QMessageBox.warning(self, "Warning", "Please specify a signature file path.")
                return
            
            # Get the signing key
            signer_key_id = self.key_combo.currentText()
            if not signer_key_id:
                QMessageBox.warning(self, "Warning", "Please select a signing key.")
                return
            
            # Get the algorithm
            algorithm = self.algorithm_combo.currentText()
            
            # Get the required signers
            required_signers = []
            for i in range(self.selected_signers_list.count()):
                required_signers.append(self.selected_signers_list.item(i).text())
            
            # Read the file
            with open(file_path, "rb") as f:
                file_data = f.read()
            
            # Prepare metadata
            metadata = {
                "filename": os.path.basename(file_path),
                "file_size": len(file_data),
                "created": datetime.datetime.now().isoformat()
            }
            
            # Create the signature chain
            signature_chain = self.cosign_manager.create_signature_chain(
                data=file_data,
                signer_key_id=signer_key_id,
                algorithm=algorithm,
                metadata=metadata,
                required_signers=required_signers
            )
            
            # Write the signature chain to the output file
            with open(signature_path, "w") as f:
                json.dump(signature_chain, f, indent=2)
            
            # Update the status display
            self.update_status_display(signature_chain)
            
            QMessageBox.information(
                self,
                "Success",
                f"Signature chain created successfully.\n\n"
                f"Output saved to: {signature_path}"
            )
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create signature chain: {str(e)}")
    
    def sign_document(self):
        """Sign a document with an existing signature chain."""
        try:
            # Get the file path
            file_path = self.file_path_edit.text()
            if not file_path:
                QMessageBox.warning(self, "Warning", "Please select a file to sign.")
                return
            
            # Get the signature path
            signature_path = self.signature_path_edit.text()
            if not signature_path:
                QMessageBox.warning(self, "Warning", "Please select a signature file.")
                return
            
            # Check if the signature file exists
            if not os.path.exists(signature_path):
                QMessageBox.warning(self, "Warning", "Signature file does not exist.")
                return
            
            # Get the signing key
            signer_key_id = self.key_combo.currentText()
            if not signer_key_id:
                QMessageBox.warning(self, "Warning", "Please select a signing key.")
                return
            
            # Get the algorithm
            algorithm = self.algorithm_combo.currentText()
            
            # Read the file
            with open(file_path, "rb") as f:
                file_data = f.read()
            
            # Read the signature chain
            with open(signature_path, "r") as f:
                signature_chain = json.load(f)
            
            # Add the signature
            updated_chain = self.cosign_manager.add_signature(
                data=file_data,
                signature_chain=signature_chain,
                signer_key_id=signer_key_id,
                algorithm=algorithm
            )
            
            # Write the updated signature chain to the output file
            with open(signature_path, "w") as f:
                json.dump(updated_chain, f, indent=2)
            
            # Update the status display
            self.update_status_display(updated_chain)
            
            QMessageBox.information(
                self,
                "Success",
                f"Signature added successfully.\n\n"
                f"Output saved to: {signature_path}"
            )
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to sign document: {str(e)}")
    
    def verify_signatures(self):
        """Verify signatures in a signature chain."""
        try:
            # Get the file path
            file_path = self.file_path_edit.text()
            if not file_path:
                QMessageBox.warning(self, "Warning", "Please select the original file.")
                return
            
            # Get the signature path
            signature_path = self.signature_path_edit.text()
            if not signature_path:
                QMessageBox.warning(self, "Warning", "Please select a signature file.")
                return
            
            # Check if the signature file exists
            if not os.path.exists(signature_path):
                QMessageBox.warning(self, "Warning", "Signature file does not exist.")
                return
            
            # Read the file
            with open(file_path, "rb") as f:
                file_data = f.read()
            
            # Read the signature chain
            with open(signature_path, "r") as f:
                signature_chain = json.load(f)
            
            # Verify the signature chain
            verification_result = self.cosign_manager.verify_signature_chain(
                data=file_data,
                signature_chain=signature_chain,
                verify_all=True
            )
            
            # Display the results
            result_message = f"Document hash valid: {'Yes' if verification_result['hash_valid'] else 'No'}\n"
            result_message += f"All signatures valid: {'Yes' if verification_result['signatures_valid'] else 'No'}\n"
            result_message += f"Status: {verification_result['status']}\n"
            result_message += f"Complete: {'Yes' if verification_result['complete'] else 'No'}\n\n"
            
            if verification_result['missing_signers']:
                result_message += f"Missing signers: {len(verification_result['missing_signers'])}\n"
                result_message += "Missing signers:\n"
                for signer in verification_result['missing_signers']:
                    result_message += f"  - {signer}\n"
                result_message += "\n"
            
            result_message += "Detailed verification results:\n"
            for result in verification_result['verification_results']:
                signer_id = result['signer_id']
                signer_name = result['signer_info'].get('name', signer_id)
                valid = result['valid']
                sequence = result['sequence']
                
                status_str = "Valid" if valid else "Invalid"
                if 'error' in result:
                    status_str += f" ({result['error']})"
                
                result_message += f"  {sequence}. {signer_name} ({signer_id}): {status_str}\n"
            
            QMessageBox.information(
                self,
                "Verification Results",
                result_message
            )
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to verify signatures: {str(e)}")
    
    def check_status(self):
        """Check the status of a signature chain."""
        try:
            # Get the signature path
            signature_path = self.signature_path_edit.text()
            if not signature_path:
                QMessageBox.warning(self, "Warning", "Please select a signature file.")
                return
            
            # Check if the signature file exists
            if not os.path.exists(signature_path):
                QMessageBox.warning(self, "Warning", "Signature file does not exist.")
                return
            
            # Read the signature chain
            with open(signature_path, "r") as f:
                signature_chain = json.load(f)
            
            # Update the status display
            self.update_status_display(signature_chain)
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to check signature status: {str(e)}")
    
    def update_status_display(self, signature_chain: Dict[str, Any]):
        """Update the status display with signature chain information."""
        try:
            # Get the status
            status = self.cosign_manager.get_signature_status(signature_chain)
            
            # Clear the table
            self.status_table.setRowCount(0)
            
            # Add rows for each signature
            signatures = status.get('signatures', [])
            self.status_table.setRowCount(len(signatures))
            
            for i, sig in enumerate(signatures):
                # Sequence
                sequence_item = QTableWidgetItem(str(sig.get('sequence', i+1)))
                self.status_table.setItem(i, 0, sequence_item)
                
                # Signer
                signer_id = sig.get('signer_id', '')
                signer_name = sig.get('signer_info', {}).get('name', signer_id)
                signer_item = QTableWidgetItem(f"{signer_name} ({signer_id})")
                self.status_table.setItem(i, 1, signer_item)
                
                # Timestamp
                timestamp = sig.get('timestamp', 0)
                timestamp_str = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                timestamp_item = QTableWidgetItem(timestamp_str)
                self.status_table.setItem(i, 2, timestamp_item)
                
                # Status
                status_item = QTableWidgetItem("Signed")
                self.status_table.setItem(i, 3, status_item)
            
            # Add rows for missing signers
            missing_signers = status.get('missing_signers', [])
            if missing_signers:
                current_row = self.status_table.rowCount()
                self.status_table.setRowCount(current_row + len(missing_signers))
                
                for i, signer_id in enumerate(missing_signers):
                    row = current_row + i
                    
                    # Sequence
                    sequence_item = QTableWidgetItem("?")
                    self.status_table.setItem(row, 0, sequence_item)
                    
                    # Signer
                    signer_item = QTableWidgetItem(signer_id)
                    self.status_table.setItem(row, 1, signer_item)
                    
                    # Timestamp
                    timestamp_item = QTableWidgetItem("-")
                    self.status_table.setItem(row, 2, timestamp_item)
                    
                    # Status
                    status_item = QTableWidgetItem("Pending")
                    self.status_table.setItem(row, 3, status_item)
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to update status display: {str(e)}")
