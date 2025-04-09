"""
Digital Signatures tab for the cryptographic system GUI.
"""

import os
from typing import Optional, Dict, Any
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox,
    QRadioButton, QButtonGroup, QFileDialog, QLineEdit, QProgressBar,
    QTextEdit, QGroupBox, QFormLayout, QCheckBox, QMessageBox
)
from PyQt6.QtCore import Qt

from ....core.key_management import KeyManager, POSTQUANTUM_AVAILABLE, PQ_SIGN_ALGORITHMS, PQ_KEM_ALGORITHMS
from ....core.signatures import SignatureEngine
from ....core.post_quantum import PostQuantumCrypto

class SignaturesTab(QWidget):
    """Digital Signatures tab for the cryptographic system GUI."""

    def __init__(self, key_manager: KeyManager, signature_engine: SignatureEngine):
        """Initialize the signatures tab."""
        super().__init__()

        self.key_manager = key_manager
        self.signature_engine = signature_engine

        # Initialize post-quantum crypto if available
        self.pq_crypto = None
        if POSTQUANTUM_AVAILABLE:
            try:
                self.pq_crypto = PostQuantumCrypto()
            except ImportError:
                # Post-quantum crypto is not available
                pass

        self.file_path = None
        self.signature_path = None

        # Set up the UI
        self.setup_ui()

    def setup_ui(self):
        """Set up the UI."""
        # Main layout
        main_layout = QVBoxLayout(self)

        # File selection area
        file_selection_group = QGroupBox("File Selection")
        file_selection_layout = QVBoxLayout(file_selection_group)

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

        # Sign/Verify radio buttons
        self.sign_radio = QRadioButton("Sign")
        self.verify_radio = QRadioButton("Verify")
        self.sign_radio.setChecked(True)

        operation_button_group = QButtonGroup(self)
        operation_button_group.addButton(self.sign_radio)
        operation_button_group.addButton(self.verify_radio)
        operation_button_group.buttonClicked.connect(self.update_ui_for_operation)

        operation_layout.addWidget(self.sign_radio)
        operation_layout.addWidget(self.verify_radio)
        operation_layout.addStretch()

        main_layout.addWidget(operation_group)

        # Signature options
        options_group = QGroupBox("Options")
        options_layout = QFormLayout(options_group)

        # Algorithm selection (for signing)
        self.algorithm_combo = QComboBox()
        self.algorithm_combo.addItems(["RSA-PSS", "RSA-PKCS1v15"])

        # Add post-quantum algorithms if available
        if POSTQUANTUM_AVAILABLE and self.pq_crypto:
            # Only add signature algorithms (for signing)
            for alg in PQ_SIGN_ALGORITHMS:
                self.algorithm_combo.addItem(alg)

        # Connect algorithm change to key list update
        self.algorithm_combo.currentIndexChanged.connect(self.update_key_list)

        options_layout.addRow("Algorithm:", self.algorithm_combo)

        # Key selection
        self.key_combo = QComboBox()
        self.update_key_list()
        options_layout.addRow("Key:", self.key_combo)

        # Signature file (for verification)
        signature_file_layout = QHBoxLayout()
        self.signature_file_field = QLineEdit()
        self.signature_file_field.setPlaceholderText("Signature file path")
        signature_file_layout.addWidget(self.signature_file_field)

        # Browse button
        browse_signature_button = QPushButton("Browse...")
        browse_signature_button.clicked.connect(self.browse_signature_file)
        signature_file_layout.addWidget(browse_signature_button)

        options_layout.addRow("Signature file:", signature_file_layout)

        main_layout.addWidget(options_group)

        # Output options (for signing)
        output_group = QGroupBox("Output")
        output_layout = QFormLayout(output_group)

        # Output path
        output_path_layout = QHBoxLayout()
        self.output_path_field = QLineEdit()
        self.output_path_field.setPlaceholderText("Same directory as input file")
        output_path_layout.addWidget(self.output_path_field)

        # Browse button
        browse_output_button = QPushButton("Browse...")
        browse_output_button.clicked.connect(self.browse_output_path)
        output_path_layout.addWidget(browse_output_button)

        output_layout.addRow("Output path:", output_path_layout)

        main_layout.addWidget(output_group)

        # Action buttons
        action_layout = QHBoxLayout()

        # Sign/Verify button
        self.action_button = QPushButton("Sign")
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
        self.update_ui_for_operation()

    def update_key_list(self):
        """Update the list of available keys."""
        self.key_combo.clear()

        # Get the selected algorithm
        algorithm = self.algorithm_combo.currentText()
        is_post_quantum = algorithm in PQ_SIGN_ALGORITHMS

        # Add keys from key manager
        if hasattr(self.key_manager, 'active_keys'):
            for key_id, key_info in self.key_manager.active_keys.items():
                # For post-quantum algorithms, only show post-quantum keys
                key_is_pq = key_info.get('post_quantum', False)

                # Only show private keys for signing, public keys for verification
                is_private = key_id.endswith('.private') or key_info.get('key_type') == 'private'
                is_public = key_id.endswith('.public') or key_info.get('key_type') == 'public'

                # Filter keys based on operation and algorithm type
                if self.sign_radio.isChecked():
                    # For signing, we need private keys
                    if is_post_quantum and key_is_pq and is_private:
                        # For post-quantum, only show signature keys
                        if key_info.get('algorithm') in PQ_SIGN_ALGORITHMS:
                            self.key_combo.addItem(key_id)
                    elif not is_post_quantum and not key_is_pq and is_private:
                        # For traditional algorithms, show traditional keys
                        self.key_combo.addItem(key_id)
                else:  # verify
                    # For verification, we need public keys
                    if is_post_quantum and key_is_pq and is_public:
                        # For post-quantum, only show signature keys
                        if key_info.get('algorithm') in PQ_SIGN_ALGORITHMS:
                            self.key_combo.addItem(key_id)
                    elif not is_post_quantum and not key_is_pq and is_public:
                        # For traditional algorithms, show traditional keys
                        self.key_combo.addItem(key_id)

    def update_ui_for_operation(self):
        """Update the UI based on the selected operation."""
        if self.sign_radio.isChecked():
            self.action_button.setText("Sign")
            self.algorithm_combo.setVisible(True)
            self.signature_file_field.setVisible(False)
            self.output_path_field.setVisible(True)
            self.output_path_field.parentWidget().parentWidget().setVisible(True)
        else:
            self.action_button.setText("Verify")
            self.algorithm_combo.setVisible(True)
            self.signature_file_field.setVisible(True)
            self.output_path_field.setVisible(False)
            self.output_path_field.parentWidget().parentWidget().setVisible(False)

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

        # Suggest output path for signature
        if self.sign_radio.isChecked():
            self.output_path_field.setText(file_path + '.sig')

    def browse_signature_file(self):
        """Open a file dialog to select a signature file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Signature File",
            "",
            "Signature Files (*.sig);;All Files (*)"
        )

        if file_path:
            self.signature_file_field.setText(file_path)

    def browse_output_path(self):
        """Open a file dialog to select an output path."""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Signature File",
            self.output_path_field.text() or (self.file_path + '.sig' if self.file_path else ""),
            "Signature Files (*.sig);;All Files (*)"
        )

        if file_path:
            self.output_path_field.setText(file_path)

    def perform_action(self):
        """Perform the selected action (sign or verify)."""
        if not self.file_path:
            QMessageBox.warning(self, "No File Selected", "Please select a file first.")
            return

        # Get key
        if self.key_combo.count() == 0:
            QMessageBox.warning(self, "No Keys Available", "No keys available. Please generate or import a key first.")
            return

        key_id = self.key_combo.currentText()

        # Get algorithm
        algorithm = self.algorithm_combo.currentText()

        if self.sign_radio.isChecked():
            # Sign the file
            self._sign_file(key_id, algorithm)
        else:
            # Verify the file
            self._verify_file(key_id, algorithm)

    def _sign_file(self, key_id, algorithm):
        """Sign a file."""
        # Get output path
        output_path = self.output_path_field.text()
        if not output_path:
            output_path = self.file_path + '.sig'

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

        try:
            # Check if this is a post-quantum algorithm
            is_post_quantum = algorithm in PQ_SIGN_ALGORITHMS

            if is_post_quantum:
                # For post-quantum signatures, we need to use the post-quantum crypto module
                if not self.pq_crypto:
                    QMessageBox.warning(self, "Post-Quantum Not Available", "Post-quantum cryptography is not available.")
                    return

                # Get the key info
                key_info = self.key_manager.active_keys.get(key_id)
                if not key_info or not key_info.get('post_quantum'):
                    QMessageBox.warning(self, "Invalid Key", "The selected key is not a post-quantum key.")
                    return

                # Get the private key
                private_key = key_info.get('key')

                # Read the file
                with open(self.file_path, 'rb') as f:
                    file_data = f.read()

                # Sign the file with post-quantum algorithm
                try:
                    signature = self.pq_crypto.sign(
                        message=file_data,
                        private_key=private_key,
                        algorithm=algorithm
                    )

                    # Create a signature result similar to the signature engine
                    signature_result = {
                        'signature': signature,
                        'algorithm': algorithm,
                        'post_quantum': True
                    }

                    # Save the signature
                    with open(output_path, 'wb') as f:
                        f.write(signature)
                except Exception as e:
                    QMessageBox.critical(self, "Signature Error", f"Error signing file: {str(e)}")
                    return
            else:
                # Traditional signature
                # Get the private key
                private_key = self.key_manager.get_key(key_id, private=True)
                if private_key is None:
                    QMessageBox.warning(self, "Key Error", f"Could not retrieve private key with ID {key_id}.")
                    return

                # Read the file
                with open(self.file_path, 'rb') as f:
                    file_data = f.read()

                # Sign the file
                signature_result = self.signature_engine.sign(
                    data=file_data,
                    private_key=private_key,
                    algorithm=algorithm
                )

                # Save the signature
                with open(output_path, 'wb') as f:
                    f.write(signature_result['signature'])

            # Show result
            self.results_text.append(f"File signed successfully.")
            self.results_text.append(f"Output file: {output_path}")
            self.results_text.append(f"Algorithm: {algorithm}")

            # Ask if user wants to verify the signature
            reply = QMessageBox.question(
                self,
                "Signature Created",
                f"The signature was created successfully. Would you like to verify it now?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes
            )
            if reply == QMessageBox.StandardButton.Yes:
                # Switch to verify mode
                self.verify_radio.setChecked(True)
                self.update_ui_for_operation()
                self.signature_file_field.setText(output_path)
                self._verify_file(key_id, algorithm)

        except Exception as e:
            # Show error
            self.results_text.append(f"Error: {str(e)}")
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")

    def _verify_file(self, key_id, algorithm):
        """Verify a file."""
        # Get signature file
        signature_path = self.signature_file_field.text()
        if not signature_path:
            QMessageBox.warning(self, "No Signature File", "Please select a signature file.")
            return

        if not os.path.exists(signature_path):
            QMessageBox.warning(self, "File Not Found", f"Signature file {signature_path} not found.")
            return

        try:
            # Check if this is a post-quantum algorithm
            is_post_quantum = algorithm in PQ_SIGN_ALGORITHMS

            if is_post_quantum:
                # For post-quantum signatures, we need to use the post-quantum crypto module
                if not self.pq_crypto:
                    QMessageBox.warning(self, "Post-Quantum Not Available", "Post-quantum cryptography is not available.")
                    return

                # Get the key info
                key_info = self.key_manager.active_keys.get(key_id)
                if not key_info or not key_info.get('post_quantum'):
                    QMessageBox.warning(self, "Invalid Key", "The selected key is not a post-quantum key.")
                    return

                # Get the public key
                public_key = key_info.get('key')

                # Read the file
                with open(self.file_path, 'rb') as f:
                    file_data = f.read()

                # Read the signature
                with open(signature_path, 'rb') as f:
                    signature = f.read()

                # Verify the signature with post-quantum algorithm
                try:
                    is_valid = self.pq_crypto.verify(
                        message=file_data,
                        signature=signature,
                        public_key=public_key,
                        algorithm=algorithm
                    )
                except Exception as e:
                    QMessageBox.critical(self, "Verification Error", f"Error verifying signature: {str(e)}")
                    return
            else:
                # Traditional verification
                # Get the public key
                public_key = self.key_manager.get_key(key_id, private=False)
                if public_key is None:
                    QMessageBox.warning(self, "Key Error", f"Could not retrieve public key with ID {key_id}.")
                    return

                # Read the file
                with open(self.file_path, 'rb') as f:
                    file_data = f.read()

                # Read the signature
                with open(signature_path, 'rb') as f:
                    signature = f.read()

                # Create signature result
                signature_result = {
                    'algorithm': algorithm,
                    'signature': signature
                }

                # Verify the signature
                is_valid = self.signature_engine.verify(
                    data=file_data,
                    signature_result=signature_result,
                    public_key=public_key
                )

            # Show result
            if is_valid:
                self.results_text.append(f"Signature is valid.")
                self.results_text.append(f"File: {self.file_path}")
                self.results_text.append(f"Signature: {signature_path}")
                self.results_text.append(f"Algorithm: {algorithm}")
                self.results_text.append(f"Key ID: {key_id}")

                QMessageBox.information(self, "Verification Successful", "The signature is valid.")
            else:
                self.results_text.append(f"Signature is invalid.")
                self.results_text.append(f"File: {self.file_path}")
                self.results_text.append(f"Signature: {signature_path}")
                self.results_text.append(f"Algorithm: {algorithm}")
                self.results_text.append(f"Key ID: {key_id}")

                QMessageBox.warning(self, "Verification Failed", "The signature is invalid.")

        except Exception as e:
            # Show error
            self.results_text.append(f"Error: {str(e)}")
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")
