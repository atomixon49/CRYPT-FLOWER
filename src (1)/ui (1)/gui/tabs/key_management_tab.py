"""
Key Management tab for the cryptographic system GUI.
"""

import os
from typing import Optional, Dict, Any
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox,
    QRadioButton, QButtonGroup, QFileDialog, QLineEdit, QProgressBar,
    QTextEdit, QGroupBox, QFormLayout, QCheckBox, QMessageBox,
    QListWidget, QListWidgetItem, QDialog, QDialogButtonBox
)
from PyQt6.QtCore import Qt

from ....core.key_management import KeyManager, POSTQUANTUM_AVAILABLE, PQ_SIGN_ALGORITHMS, PQ_KEM_ALGORITHMS
from ....core.hybrid_crypto import HybridCrypto

class PasswordDialog(QDialog):
    """Dialog for entering a password."""

    def __init__(self, title="Enter Password", message="Enter password:", parent=None):
        """Initialize the password dialog."""
        super().__init__(parent)

        self.setWindowTitle(title)

        # Layout
        layout = QVBoxLayout(self)

        # Message
        layout.addWidget(QLabel(message))

        # Password field
        self.password_field = QLineEdit()
        self.password_field.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password_field)

        # Buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def get_password(self):
        """Get the entered password."""
        return self.password_field.text()


class KeyManagementTab(QWidget):
    """Key Management tab for the cryptographic system GUI."""

    def __init__(self, key_manager: KeyManager):
        """Initialize the key management tab."""
        super().__init__()

        self.key_manager = key_manager
        self.hybrid_crypto = HybridCrypto(key_manager)

        # Set up the UI
        self.setup_ui()

    def setup_ui(self):
        """Set up the UI."""
        # Main layout
        main_layout = QVBoxLayout(self)

        # Key list
        key_list_group = QGroupBox("Available Keys")
        key_list_layout = QVBoxLayout(key_list_group)

        self.key_list = QListWidget()
        self.key_list.itemSelectionChanged.connect(self.update_key_details)
        key_list_layout.addWidget(self.key_list)

        # Key list buttons
        key_list_buttons_layout = QHBoxLayout()

        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self.refresh_key_list)
        key_list_buttons_layout.addWidget(refresh_button)

        key_list_layout.addLayout(key_list_buttons_layout)

        main_layout.addWidget(key_list_group)

        # Key details
        key_details_group = QGroupBox("Key Details")
        key_details_layout = QFormLayout(key_details_group)

        self.key_id_label = QLabel("")
        key_details_layout.addRow("Key ID:", self.key_id_label)

        self.key_type_label = QLabel("")
        key_details_layout.addRow("Type:", self.key_type_label)

        self.key_algorithm_label = QLabel("")
        key_details_layout.addRow("Algorithm:", self.key_algorithm_label)

        self.key_size_label = QLabel("")
        key_details_layout.addRow("Size:", self.key_size_label)

        main_layout.addWidget(key_details_group)

        # Key actions
        key_actions_group = QGroupBox("Key Actions")
        key_actions_layout = QHBoxLayout(key_actions_group)

        generate_key_button = QPushButton("Generate Key")
        generate_key_button.clicked.connect(self.generate_key)
        key_actions_layout.addWidget(generate_key_button)

        import_key_button = QPushButton("Import Key")
        import_key_button.clicked.connect(self.import_key)
        key_actions_layout.addWidget(import_key_button)

        export_key_button = QPushButton("Export Key")
        export_key_button.clicked.connect(self.export_key)
        key_actions_layout.addWidget(export_key_button)

        delete_key_button = QPushButton("Delete Key")
        delete_key_button.clicked.connect(self.delete_key)
        key_actions_layout.addWidget(delete_key_button)

        main_layout.addWidget(key_actions_group)

        # Storage actions
        storage_actions_group = QGroupBox("Storage Actions")
        storage_actions_layout = QHBoxLayout(storage_actions_group)

        init_storage_button = QPushButton("Initialize Storage")
        init_storage_button.clicked.connect(self.init_storage)
        storage_actions_layout.addWidget(init_storage_button)

        change_password_button = QPushButton("Change Master Password")
        change_password_button.clicked.connect(self.change_master_password)
        storage_actions_layout.addWidget(change_password_button)

        main_layout.addWidget(storage_actions_group)

        # Results area
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout(results_group)

        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        results_layout.addWidget(self.results_text)

        main_layout.addWidget(results_group)

        # Initialize key list
        self.refresh_key_list()

    def refresh_key_list(self):
        """Refresh the list of keys."""
        self.key_list.clear()

        # Add keys from key manager
        if hasattr(self.key_manager, 'active_keys'):
            for key_id in self.key_manager.active_keys:
                self.key_list.addItem(key_id)

        # Update key details
        self.update_key_details()

    def update_key_details(self):
        """Update the key details display."""
        selected_items = self.key_list.selectedItems()
        if not selected_items:
            # Clear details
            self.key_id_label.setText("")
            self.key_type_label.setText("")
            self.key_algorithm_label.setText("")
            self.key_size_label.setText("")
            return

        key_id = selected_items[0].text()

        # Get key details
        if hasattr(self.key_manager, 'active_keys') and key_id in self.key_manager.active_keys:
            key_info = self.key_manager.active_keys[key_id]

            # Display key details
            self.key_id_label.setText(key_id)

            # Check key type
            is_post_quantum = key_info.get('post_quantum', False)
            is_hybrid = key_info.get('type') == 'hybrid'

            if is_hybrid:
                # For hybrid keys, show special information
                self.key_type_label.setText("Hybrid (Classical + Post-Quantum)")

                # Display classical algorithm and key size
                classical_info = key_info.get('classical', {})
                classical_algorithm = classical_info.get('algorithm', 'Unknown')
                classical_key_size = classical_info.get('key_size', 'Unknown')

                # Display post-quantum algorithm if available
                pq_info = key_info.get('post_quantum', {})
                pq_algorithm = pq_info.get('algorithm', 'None')

                # Combine information
                algorithm_text = f"Classical: {classical_algorithm}, PQ: {pq_algorithm}"
                self.key_algorithm_label.setText(algorithm_text)

                # Display key size
                self.key_size_label.setText(f"Classical: {classical_key_size} bits + PQ Security")

            elif is_post_quantum:
                # For post-quantum keys, show special information
                key_type = key_info.get('key_type', 'Unknown')
                self.key_type_label.setText(f"Post-Quantum {key_type}")

                # Determine the purpose of the key
                algorithm = key_info.get('algorithm', 'Unknown')
                if algorithm in PQ_SIGN_ALGORITHMS:
                    purpose = "Digital Signature"
                elif algorithm in PQ_KEM_ALGORITHMS:
                    purpose = "Key Encapsulation"
                else:
                    purpose = key_info.get('purpose', 'Unknown')

                self.key_algorithm_label.setText(f"{algorithm} ({purpose})")

                # Post-quantum keys don't have a traditional key size
                self.key_size_label.setText("Post-Quantum Security")
            else:
                # Determine key type for traditional keys
                if 'type' in key_info:
                    self.key_type_label.setText(key_info['type'])
                elif 'key_type' in key_info:
                    self.key_type_label.setText(key_info['key_type'])
                else:
                    self.key_type_label.setText("Unknown")

                # Display algorithm
                if 'algorithm' in key_info:
                    self.key_algorithm_label.setText(key_info['algorithm'])
                else:
                    self.key_algorithm_label.setText("Unknown")

                # Display key size
                if 'key_size' in key_info:
                    self.key_size_label.setText(f"{key_info['key_size']} bits")
                else:
                    self.key_size_label.setText("Unknown")

    def generate_key(self):
        """Generate a new key."""
        # Create a dialog for key generation options
        dialog = QDialog(self)
        dialog.setWindowTitle("Generate Key")
        dialog.setMinimumWidth(300)

        # Layout
        layout = QVBoxLayout(dialog)

        # Key type selection
        key_type_group = QGroupBox("Key Type")
        key_type_layout = QVBoxLayout(key_type_group)

        symmetric_radio = QRadioButton("Symmetric")
        asymmetric_radio = QRadioButton("Asymmetric")
        postquantum_radio = QRadioButton("Post-Quantum")
        hybrid_radio = QRadioButton("Hybrid (Classical + Post-Quantum)")
        symmetric_radio.setChecked(True)

        # Disable post-quantum and hybrid options if not available
        if not POSTQUANTUM_AVAILABLE:
            postquantum_radio.setEnabled(False)
            postquantum_radio.setToolTip("Post-quantum cryptography is not available. Install pqcrypto library.")
            hybrid_radio.setEnabled(False)
            hybrid_radio.setToolTip("Hybrid cryptography requires post-quantum support. Install pqcrypto library.")

        key_type_layout.addWidget(symmetric_radio)
        key_type_layout.addWidget(asymmetric_radio)
        key_type_layout.addWidget(postquantum_radio)
        key_type_layout.addWidget(hybrid_radio)

        layout.addWidget(key_type_group)

        # Algorithm selection
        algorithm_group = QGroupBox("Algorithm")
        algorithm_layout = QFormLayout(algorithm_group)

        algorithm_combo = QComboBox()
        algorithm_combo.addItems(["AES", "ChaCha20"])
        algorithm_layout.addRow("Algorithm:", algorithm_combo)

        key_size_combo = QComboBox()
        key_size_combo.addItems(["128", "192", "256"])
        key_size_combo.setCurrentText("256")
        algorithm_layout.addRow("Key Size (bits):", key_size_combo)

        # Function to update algorithm options based on key type
        def update_algorithm_options():
            algorithm_combo.clear()
            key_size_combo.clear()

            if symmetric_radio.isChecked():
                algorithm_combo.addItems(["AES", "ChaCha20"])
                key_size_combo.addItems(["128", "192", "256"])
                key_size_combo.setCurrentText("256")
                key_size_combo.setEnabled(True)
            elif asymmetric_radio.isChecked():
                algorithm_combo.addItems(["RSA", "ECC"])
                key_size_combo.addItems(["2048", "3072", "4096"])
                key_size_combo.setCurrentText("3072")
                key_size_combo.setEnabled(True)
            elif postquantum_radio.isChecked():
                # Add post-quantum algorithms
                sign_algorithms = [alg for alg in PQ_SIGN_ALGORITHMS]
                kem_algorithms = [alg for alg in PQ_KEM_ALGORITHMS]
                algorithm_combo.addItems(sign_algorithms + kem_algorithms)
                # Post-quantum algorithms don't use key size in the same way
                key_size_combo.setEnabled(False)
            elif hybrid_radio.isChecked():
                # For hybrid keys, we use post-quantum algorithms for the quantum part
                # and RSA for the classical part
                sign_algorithms = [alg for alg in PQ_SIGN_ALGORITHMS]
                kem_algorithms = [alg for alg in PQ_KEM_ALGORITHMS]
                algorithm_combo.addItems(sign_algorithms + kem_algorithms)
                # For the classical part, we use RSA with different key sizes
                key_size_combo.addItems(["2048", "3072", "4096"])
                key_size_combo.setCurrentText("3072")
                key_size_combo.setEnabled(True)

        # Connect radio buttons to update function
        symmetric_radio.toggled.connect(update_algorithm_options)
        asymmetric_radio.toggled.connect(update_algorithm_options)
        postquantum_radio.toggled.connect(update_algorithm_options)
        hybrid_radio.toggled.connect(update_algorithm_options)

        # Initial update
        update_algorithm_options()

        layout.addWidget(algorithm_group)

        # Key ID
        key_id_group = QGroupBox("Key Identifier")
        key_id_layout = QFormLayout(key_id_group)

        key_id_field = QLineEdit()
        key_id_field.setPlaceholderText("Leave blank for auto-generated ID")
        key_id_layout.addRow("Key ID:", key_id_field)

        layout.addWidget(key_id_group)

        # Buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)
        layout.addWidget(button_box)

        # Show dialog
        if dialog.exec() == QDialog.DialogCode.Accepted:
            try:
                # Get values
                if symmetric_radio.isChecked():
                    key_type = "symmetric"
                elif asymmetric_radio.isChecked():
                    key_type = "asymmetric"
                elif postquantum_radio.isChecked():
                    key_type = "post-quantum"
                else:
                    key_type = "hybrid"

                algorithm = algorithm_combo.currentText()
                key_id = key_id_field.text() or None

                # Get key size if applicable
                key_size = None
                if key_size_combo.isEnabled():
                    key_size = int(key_size_combo.currentText())

                # Generate key
                if key_type == "symmetric":
                    key = self.key_manager.generate_symmetric_key(
                        algorithm=algorithm,
                        key_size=key_size,
                        key_id=key_id
                    )

                    # Get the key ID (in case it was auto-generated)
                    if key_id is None:
                        key_id = list(self.key_manager.active_keys.keys())[-1]

                    # Show result
                    self.results_text.append(f"Symmetric key generated successfully.")
                    self.results_text.append(f"Key ID: {key_id}")
                    self.results_text.append(f"Algorithm: {algorithm}")
                    self.results_text.append(f"Key Size: {key_size} bits")

                    # Refresh key list
                    self.refresh_key_list()

                    # Select the new key
                    for i in range(self.key_list.count()):
                        if self.key_list.item(i).text() == key_id:
                            self.key_list.setCurrentRow(i)
                            break

                elif key_type == "post-quantum":
                    # For post-quantum keys, we use the asymmetric keypair method
                    try:
                        public_key, private_key = self.key_manager.generate_asymmetric_keypair(
                            algorithm=algorithm
                        )

                        # Get the key ID (in case it was auto-generated)
                        if key_id is None:
                            # Find the key ID by looking at the last two keys added
                            keys = list(self.key_manager.active_keys.keys())
                            if len(keys) >= 2:
                                key_id = keys[-2].split('.')[0]  # Remove .public/.private suffix

                        # Show result
                        self.results_text.append(f"Post-quantum key pair generated successfully.")
                        self.results_text.append(f"Key ID: {key_id}")
                        self.results_text.append(f"Algorithm: {algorithm}")
                        self.results_text.append(f"Type: {'Signature' if algorithm in PQ_SIGN_ALGORITHMS else 'Encryption'}")

                        # Refresh key list
                        self.refresh_key_list()

                        # Select the new key
                        for i in range(self.key_list.count()):
                            if self.key_list.item(i).text().startswith(key_id):
                                self.key_list.setCurrentRow(i)
                                break
                    except Exception as e:
                        self.results_text.append(f"Error generating post-quantum key: {str(e)}")
                        QMessageBox.critical(self, "Error", f"Error generating post-quantum key: {str(e)}")
                        return

                elif key_type == "hybrid":
                    # For hybrid keys, we use the hybrid crypto module
                    try:
                        # Generate hybrid key pair
                        hybrid_key_info = self.hybrid_crypto.generate_hybrid_keypair(
                            classical_algorithm="RSA",
                            classical_key_size=key_size or 3072,
                            pq_algorithm=algorithm if algorithm in PQ_SIGN_ALGORITHMS else None,
                            key_id=key_id
                        )

                        # Get the key ID
                        key_id = hybrid_key_info["id"]

                        # Show result
                        self.results_text.append(f"Hybrid key pair generated successfully.")
                        self.results_text.append(f"Key ID: {key_id}")
                        self.results_text.append(f"Classical Algorithm: {hybrid_key_info['classical']['algorithm']}")
                        self.results_text.append(f"Classical Key Size: {hybrid_key_info['classical']['key_size']} bits")

                        if "post_quantum" in hybrid_key_info:
                            self.results_text.append(f"Post-Quantum Algorithm: {hybrid_key_info['post_quantum']['algorithm']}")

                        # Refresh key list
                        self.refresh_key_list()

                        # Select the new key
                        for i in range(self.key_list.count()):
                            if self.key_list.item(i).text() == key_id:
                                self.key_list.setCurrentRow(i)
                                break
                    except Exception as e:
                        self.results_text.append(f"Error generating hybrid key: {str(e)}")
                        QMessageBox.critical(self, "Error", f"Error generating hybrid key: {str(e)}")
                        return

                else:  # asymmetric
                    # For asymmetric keys, we need to handle key pairs
                    key_pair = self.key_manager.generate_asymmetric_key_pair(
                        algorithm=algorithm,
                        key_size=key_size,
                        key_id=key_id
                    )

                    # Get the key ID (in case it was auto-generated)
                    if key_id is None:
                        # Find the key ID by looking at the last two keys added
                        keys = list(self.key_manager.active_keys.keys())
                        if len(keys) >= 2:
                            key_id = keys[-2].split('.')[0]  # Remove .public/.private suffix

                    # Show result
                    self.results_text.append(f"Asymmetric key pair generated successfully.")
                    self.results_text.append(f"Key ID: {key_id}")
                    self.results_text.append(f"Algorithm: {algorithm}")
                    self.results_text.append(f"Key Size: {key_size} bits")

                    # Refresh key list
                    self.refresh_key_list()

                    # Select the new key
                    for i in range(self.key_list.count()):
                        if self.key_list.item(i).text().startswith(key_id):
                            self.key_list.setCurrentRow(i)
                            break

                QMessageBox.information(self, "Key Generated", f"Key '{key_id}' generated successfully.")

            except Exception as e:
                # Show error
                self.results_text.append(f"Error: {str(e)}")
                QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")

    def import_key(self):
        """Import a key from a file."""
        # Open file dialog
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Key",
            "",
            "Key Files (*.key *.private *.public);;All Files (*)"
        )

        if not file_path:
            return

        # Ask for key ID
        key_id, ok = QMessageBox.getText(
            self,
            "Key ID",
            "Enter a key ID (leave blank for auto-generated ID):"
        )

        if not ok:
            return

        # If key ID is empty, use None for auto-generation
        key_id = key_id.strip() or None

        try:
            # Read the key file
            with open(file_path, 'rb') as f:
                key_data = f.read()

            # Determine key type from file extension
            file_ext = os.path.splitext(file_path)[1].lower()

            if file_ext == '.private':
                # Import private key
                key_id = self.key_manager.import_private_key(
                    private_key=key_data,
                    key_id=key_id
                )
                self.results_text.append(f"Private key imported successfully.")
                self.results_text.append(f"Key ID: {key_id}")

            elif file_ext == '.public':
                # Import public key
                key_id = self.key_manager.import_public_key(
                    public_key=key_data,
                    key_id=key_id
                )
                self.results_text.append(f"Public key imported successfully.")
                self.results_text.append(f"Key ID: {key_id}")

            else:  # .key or other
                # Import symmetric key
                key_id = self.key_manager.import_symmetric_key(
                    key=key_data,
                    key_id=key_id
                )
                self.results_text.append(f"Symmetric key imported successfully.")
                self.results_text.append(f"Key ID: {key_id}")

            # Refresh key list
            self.refresh_key_list()

            # Select the imported key
            for i in range(self.key_list.count()):
                if self.key_list.item(i).text() == key_id:
                    self.key_list.setCurrentRow(i)
                    break

            QMessageBox.information(self, "Key Imported", f"Key '{key_id}' imported successfully.")

        except Exception as e:
            # Show error
            self.results_text.append(f"Error: {str(e)}")
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")

    def export_key(self):
        """Export a key to a file."""
        # Check if a key is selected
        selected_items = self.key_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Key Selected", "Please select a key to export.")
            return

        key_id = selected_items[0].text()

        # Determine key type
        key_type = "unknown"
        if hasattr(self.key_manager, 'active_keys') and key_id in self.key_manager.active_keys:
            key_info = self.key_manager.active_keys[key_id]
            if 'type' in key_info:
                key_type = key_info['type']
            elif 'key_type' in key_info:
                key_type = key_info['key_type']

        # Determine file extension based on key type
        file_ext = ".key"  # Default for symmetric keys
        if key_type == "asymmetric":
            if ".public" in key_id:
                file_ext = ".public"
            elif ".private" in key_id:
                file_ext = ".private"

        # Open file dialog
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Key",
            f"{key_id}{file_ext}",
            "Key Files (*.key *.private *.public);;All Files (*)"
        )

        if not file_path:
            return

        try:
            # Get the key
            key_data = self.key_manager.export_key(key_id)

            # Save the key
            with open(file_path, 'wb') as f:
                f.write(key_data)

            # Show result
            self.results_text.append(f"Key exported successfully.")
            self.results_text.append(f"Key ID: {key_id}")
            self.results_text.append(f"Output file: {file_path}")

            QMessageBox.information(self, "Key Exported", f"Key '{key_id}' exported successfully to {file_path}.")

        except Exception as e:
            # Show error
            self.results_text.append(f"Error: {str(e)}")
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")

    def delete_key(self):
        """Delete a key."""
        # Check if a key is selected
        selected_items = self.key_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Key Selected", "Please select a key to delete.")
            return

        key_id = selected_items[0].text()

        # Confirm deletion
        reply = QMessageBox.question(
            self,
            "Confirm Deletion",
            f"Are you sure you want to delete the key '{key_id}'? This action cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            # Delete the key
            self.key_manager.delete_key(key_id)

            # Show result
            self.results_text.append(f"Key deleted successfully.")
            self.results_text.append(f"Key ID: {key_id}")

            # Refresh key list
            self.refresh_key_list()

            QMessageBox.information(self, "Key Deleted", f"Key '{key_id}' deleted successfully.")

        except Exception as e:
            # Show error
            self.results_text.append(f"Error: {str(e)}")
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")

    def init_storage(self):
        """Initialize the key storage."""
        # Ask for confirmation
        reply = QMessageBox.question(
            self,
            "Initialize Storage",
            "This will initialize the key storage. If a storage already exists, you will be asked to confirm overwriting it. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        # Ask for master password
        password_dialog = PasswordDialog(
            title="Set Master Password",
            message="Enter a master password for the key storage:",
            parent=self
        )

        if password_dialog.exec() != QDialog.DialogCode.Accepted:
            return

        master_password = password_dialog.get_password()

        if not master_password:
            QMessageBox.warning(self, "No Password", "A master password is required.")
            return

        # Confirm password
        confirm_dialog = PasswordDialog(
            title="Confirm Master Password",
            message="Confirm the master password:",
            parent=self
        )

        if confirm_dialog.exec() != QDialog.DialogCode.Accepted:
            return

        confirm_password = confirm_dialog.get_password()

        if master_password != confirm_password:
            QMessageBox.warning(self, "Password Mismatch", "Passwords do not match.")
            return

        try:
            # Initialize storage
            self.key_manager.initialize_storage(master_password, force=True)

            # Show result
            self.results_text.append(f"Key storage initialized successfully.")
            self.results_text.append(f"Remember your master password! There is no way to recover it if lost.")

            # Refresh key list
            self.refresh_key_list()

            QMessageBox.information(self, "Storage Initialized", "Key storage initialized successfully.")

        except Exception as e:
            # Show error
            self.results_text.append(f"Error: {str(e)}")
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")

    def change_master_password(self):
        """Change the master password."""
        # Ask for current password
        current_dialog = PasswordDialog(
            title="Current Master Password",
            message="Enter your current master password:",
            parent=self
        )

        if current_dialog.exec() != QDialog.DialogCode.Accepted:
            return

        current_password = current_dialog.get_password()

        if not current_password:
            QMessageBox.warning(self, "No Password", "Current master password is required.")
            return

        # Ask for new password
        new_dialog = PasswordDialog(
            title="New Master Password",
            message="Enter a new master password:",
            parent=self
        )

        if new_dialog.exec() != QDialog.DialogCode.Accepted:
            return

        new_password = new_dialog.get_password()

        if not new_password:
            QMessageBox.warning(self, "No Password", "New master password is required.")
            return

        # Confirm new password
        confirm_dialog = PasswordDialog(
            title="Confirm New Master Password",
            message="Confirm the new master password:",
            parent=self
        )

        if confirm_dialog.exec() != QDialog.DialogCode.Accepted:
            return

        confirm_password = confirm_dialog.get_password()

        if new_password != confirm_password:
            QMessageBox.warning(self, "Password Mismatch", "Passwords do not match.")
            return

        try:
            # Change master password
            success = self.key_manager.change_master_password(current_password, new_password)

            if not success:
                QMessageBox.warning(self, "Password Change Failed", "Failed to change master password. Check your current password.")
                return

            # Show result
            self.results_text.append(f"Master password changed successfully.")

            QMessageBox.information(self, "Password Changed", "Master password changed successfully.")

        except Exception as e:
            # Show error
            self.results_text.append(f"Error: {str(e)}")
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")
