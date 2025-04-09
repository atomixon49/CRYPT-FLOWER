"""
Certificate Revocation tab for the cryptographic system GUI.
"""

import os
import datetime
from typing import Optional, Dict, Any, List
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox,
    QRadioButton, QButtonGroup, QFileDialog, QLineEdit, QProgressBar,
    QTextEdit, QGroupBox, QFormLayout, QCheckBox, QMessageBox,
    QSizePolicy, QFrame, QSpacerItem, QScrollArea, QGridLayout,
    QListWidget, QListWidgetItem, QAbstractItemView, QTabWidget
)
from PyQt6.QtCore import Qt, QMimeData, QUrl
from PyQt6.QtGui import QDragEnterEvent, QDropEvent

from ....core.key_management import KeyManager
from ....core.cert_revocation import CertificateRevocationChecker


class CertRevocationTab(QWidget):
    """Certificate Revocation tab for the cryptographic system GUI."""

    def __init__(self, key_manager: KeyManager, revocation_checker: CertificateRevocationChecker):
        """Initialize the certificate revocation tab."""
        super().__init__()

        self.key_manager = key_manager
        self.revocation_checker = revocation_checker

        # Set up the UI
        self.setup_ui()

    def setup_ui(self):
        """Set up the UI."""
        # Main layout
        main_layout = QVBoxLayout(self)

        # Create tab widget for different revocation checking methods
        tab_widget = QTabWidget()
        main_layout.addWidget(tab_widget)

        # Create tabs for different methods
        self.create_crl_tab(tab_widget)
        self.create_ocsp_tab(tab_widget)
        self.create_cache_tab(tab_widget)

    def create_crl_tab(self, parent_tab_widget):
        """Create the CRL tab."""
        crl_tab = QWidget()
        crl_layout = QVBoxLayout(crl_tab)

        # Certificate selection
        cert_group = QGroupBox("Certificate")
        cert_layout = QFormLayout(cert_group)

        # Certificate file selection
        cert_file_layout = QHBoxLayout()
        self.cert_file_field = QLineEdit()
        self.cert_file_field.setPlaceholderText("Select certificate file")
        cert_file_layout.addWidget(self.cert_file_field)

        cert_file_button = QPushButton("Browse...")
        cert_file_button.clicked.connect(self.browse_cert_file)
        cert_file_layout.addWidget(cert_file_button)

        cert_layout.addRow("Certificate:", cert_file_layout)

        # Issuer certificate selection
        issuer_file_layout = QHBoxLayout()
        self.issuer_file_field = QLineEdit()
        self.issuer_file_field.setPlaceholderText("Select issuer certificate file")
        issuer_file_layout.addWidget(self.issuer_file_field)

        issuer_file_button = QPushButton("Browse...")
        issuer_file_button.clicked.connect(self.browse_issuer_file)
        issuer_file_layout.addWidget(issuer_file_button)

        cert_layout.addRow("Issuer Certificate:", issuer_file_layout)

        crl_layout.addWidget(cert_group)

        # CRL options
        crl_options_group = QGroupBox("CRL Options")
        crl_options_layout = QFormLayout(crl_options_group)

        # CRL file selection
        crl_file_layout = QHBoxLayout()
        self.crl_file_field = QLineEdit()
        self.crl_file_field.setPlaceholderText("Optional: Select CRL file")
        crl_file_layout.addWidget(self.crl_file_field)

        crl_file_button = QPushButton("Browse...")
        crl_file_button.clicked.connect(self.browse_crl_file)
        crl_file_layout.addWidget(crl_file_button)

        crl_options_layout.addRow("CRL File:", crl_file_layout)

        # Force download checkbox
        self.force_download_checkbox = QCheckBox("Force download (ignore cache)")
        crl_options_layout.addRow("", self.force_download_checkbox)

        crl_layout.addWidget(crl_options_group)

        # Action buttons
        action_layout = QHBoxLayout()

        check_crl_button = QPushButton("Check Certificate Revocation (CRL)")
        check_crl_button.clicked.connect(self.check_crl_revocation)
        action_layout.addWidget(check_crl_button)

        crl_layout.addLayout(action_layout)

        # Progress bar
        self.crl_progress_bar = QProgressBar()
        self.crl_progress_bar.setVisible(False)
        crl_layout.addWidget(self.crl_progress_bar)

        # Results area
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout(results_group)

        self.crl_results_text = QTextEdit()
        self.crl_results_text.setReadOnly(True)
        results_layout.addWidget(self.crl_results_text)

        crl_layout.addWidget(results_group)

        # Add the tab
        parent_tab_widget.addTab(crl_tab, "CRL Check")

    def create_ocsp_tab(self, parent_tab_widget):
        """Create the OCSP tab."""
        ocsp_tab = QWidget()
        ocsp_layout = QVBoxLayout(ocsp_tab)

        # Certificate selection
        cert_group = QGroupBox("Certificate")
        cert_layout = QFormLayout(cert_group)

        # Certificate file selection
        cert_file_layout = QHBoxLayout()
        self.ocsp_cert_file_field = QLineEdit()
        self.ocsp_cert_file_field.setPlaceholderText("Select certificate file")
        cert_file_layout.addWidget(self.ocsp_cert_file_field)

        cert_file_button = QPushButton("Browse...")
        cert_file_button.clicked.connect(self.browse_ocsp_cert_file)
        cert_file_layout.addWidget(cert_file_button)

        cert_layout.addRow("Certificate:", cert_file_layout)

        # Issuer certificate selection
        issuer_file_layout = QHBoxLayout()
        self.ocsp_issuer_file_field = QLineEdit()
        self.ocsp_issuer_file_field.setPlaceholderText("Select issuer certificate file")
        issuer_file_layout.addWidget(self.ocsp_issuer_file_field)

        issuer_file_button = QPushButton("Browse...")
        issuer_file_button.clicked.connect(self.browse_ocsp_issuer_file)
        issuer_file_layout.addWidget(issuer_file_button)

        cert_layout.addRow("Issuer Certificate:", issuer_file_layout)

        ocsp_layout.addWidget(cert_group)

        # OCSP options
        ocsp_options_group = QGroupBox("OCSP Options")
        ocsp_options_layout = QFormLayout(ocsp_options_group)

        # OCSP responder URL
        self.ocsp_url_field = QLineEdit()
        self.ocsp_url_field.setPlaceholderText("Optional: OCSP responder URL")
        ocsp_options_layout.addRow("OCSP URL:", self.ocsp_url_field)

        ocsp_layout.addWidget(ocsp_options_group)

        # Action buttons
        action_layout = QHBoxLayout()

        check_ocsp_button = QPushButton("Check Certificate Revocation (OCSP)")
        check_ocsp_button.clicked.connect(self.check_ocsp_revocation)
        action_layout.addWidget(check_ocsp_button)

        ocsp_layout.addLayout(action_layout)

        # Progress bar
        self.ocsp_progress_bar = QProgressBar()
        self.ocsp_progress_bar.setVisible(False)
        ocsp_layout.addWidget(self.ocsp_progress_bar)

        # Results area
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout(results_group)

        self.ocsp_results_text = QTextEdit()
        self.ocsp_results_text.setReadOnly(True)
        results_layout.addWidget(self.ocsp_results_text)

        ocsp_layout.addWidget(results_group)

        # Add the tab
        parent_tab_widget.addTab(ocsp_tab, "OCSP Check")

    def create_cache_tab(self, parent_tab_widget):
        """Create the cache management tab."""
        cache_tab = QWidget()
        cache_layout = QVBoxLayout(cache_tab)

        # Cache info
        cache_info_group = QGroupBox("Cache Information")
        cache_info_layout = QVBoxLayout(cache_info_group)

        self.cache_info_text = QTextEdit()
        self.cache_info_text.setReadOnly(True)
        cache_info_layout.addWidget(self.cache_info_text)

        cache_layout.addWidget(cache_info_group)

        # Action buttons
        action_layout = QHBoxLayout()

        refresh_cache_button = QPushButton("Refresh Cache Info")
        refresh_cache_button.clicked.connect(self.refresh_cache_info)
        action_layout.addWidget(refresh_cache_button)

        clear_cache_button = QPushButton("Clear Cache")
        clear_cache_button.clicked.connect(self.clear_cache)
        action_layout.addWidget(clear_cache_button)

        cache_layout.addLayout(action_layout)

        # Add the tab
        parent_tab_widget.addTab(cache_tab, "Cache Management")

        # Initialize cache info
        self.refresh_cache_info()

    def browse_cert_file(self):
        """Open a file dialog to select a certificate file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Certificate File",
            "",
            "Certificate Files (*.pem *.der *.crt *.cer);;All Files (*)"
        )

        if file_path:
            self.cert_file_field.setText(file_path)

    def browse_issuer_file(self):
        """Open a file dialog to select an issuer certificate file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Issuer Certificate File",
            "",
            "Certificate Files (*.pem *.der *.crt *.cer);;All Files (*)"
        )

        if file_path:
            self.issuer_file_field.setText(file_path)

    def browse_crl_file(self):
        """Open a file dialog to select a CRL file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select CRL File",
            "",
            "CRL Files (*.crl *.pem);;All Files (*)"
        )

        if file_path:
            self.crl_file_field.setText(file_path)

    def browse_ocsp_cert_file(self):
        """Open a file dialog to select a certificate file for OCSP."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Certificate File",
            "",
            "Certificate Files (*.pem *.der *.crt *.cer);;All Files (*)"
        )

        if file_path:
            self.ocsp_cert_file_field.setText(file_path)

    def browse_ocsp_issuer_file(self):
        """Open a file dialog to select an issuer certificate file for OCSP."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Issuer Certificate File",
            "",
            "Certificate Files (*.pem *.der *.crt *.cer);;All Files (*)"
        )

        if file_path:
            self.ocsp_issuer_file_field.setText(file_path)

    def check_crl_revocation(self):
        """Check certificate revocation using CRL."""
        # Validate inputs
        cert_file = self.cert_file_field.text()
        if not cert_file:
            QMessageBox.warning(self, "Missing Certificate", "Please select a certificate file.")
            return

        issuer_file = self.issuer_file_field.text()
        if not issuer_file:
            QMessageBox.warning(self, "Missing Issuer Certificate", "Please select an issuer certificate file.")
            return

        # Read certificate and issuer files
        try:
            with open(cert_file, 'rb') as f:
                cert_data = f.read()

            with open(issuer_file, 'rb') as f:
                issuer_data = f.read()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to read certificate files: {str(e)}")
            return

        # Read CRL file if provided
        crl_data = None
        if self.crl_file_field.text():
            try:
                with open(self.crl_file_field.text(), 'rb') as f:
                    crl_data = f.read()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to read CRL file: {str(e)}")
                return

        # Show progress bar
        self.crl_progress_bar.setVisible(True)
        self.crl_progress_bar.setValue(0)

        # Clear results
        self.crl_results_text.clear()
        self.crl_results_text.append("Checking certificate revocation status...")

        try:
            # Check revocation
            if crl_data:
                # Check against the provided CRL
                self.crl_progress_bar.setValue(50)
                result = self.revocation_checker.check_certificate_against_crl(
                    certificate=cert_data,
                    crl_data=crl_data,
                    issuer_certificate=issuer_data
                )

                # Display result
                self.crl_results_text.append("\nCRL Check Result:")
                self.crl_results_text.append(f"Status: {result['status']}")
                if result['status'] == 'revoked':
                    self.crl_results_text.append(f"Revoked: {result['revoked']}")
                    if 'reason' in result and result['reason']:
                        self.crl_results_text.append(f"Reason: {result['reason']}")
                    if 'revocation_time_str' in result:
                        self.crl_results_text.append(f"Revocation Time: {result['revocation_time_str']}")
                elif result['status'] == 'good':
                    self.crl_results_text.append(f"Revoked: {result['revoked']}")
                    if 'crl_last_update_str' in result:
                        self.crl_results_text.append(f"CRL Last Update: {result['crl_last_update_str']}")
                    if 'crl_next_update_str' in result and result['crl_next_update_str']:
                        self.crl_results_text.append(f"CRL Next Update: {result['crl_next_update_str']}")
            else:
                # Check against CRLs from the certificate
                self.crl_progress_bar.setValue(30)
                results = self.revocation_checker.check_certificate_crl(
                    certificate=cert_data,
                    issuer_certificate=issuer_data,
                    force_download=self.force_download_checkbox.isChecked()
                )

                # Display results
                self.crl_results_text.append("\nCRL Check Results:")
                for i, result in enumerate(results):
                    self.crl_progress_bar.setValue(30 + (i + 1) * 70 // len(results))
                    self.crl_results_text.append(f"\nResult {i+1}:")
                    self.crl_results_text.append(f"Status: {result['status']}")
                    if 'crl_url' in result:
                        self.crl_results_text.append(f"CRL URL: {result['crl_url']}")

                    if result['status'] == 'revoked':
                        self.crl_results_text.append(f"Revoked: {result['revoked']}")
                        if 'reason' in result and result['reason']:
                            self.crl_results_text.append(f"Reason: {result['reason']}")
                        if 'revocation_time_str' in result:
                            self.crl_results_text.append(f"Revocation Time: {result['revocation_time_str']}")
                    elif result['status'] == 'good':
                        self.crl_results_text.append(f"Revoked: {result['revoked']}")
                        if 'crl_last_update_str' in result:
                            self.crl_results_text.append(f"CRL Last Update: {result['crl_last_update_str']}")
                        if 'crl_next_update_str' in result and result['crl_next_update_str']:
                            self.crl_results_text.append(f"CRL Next Update: {result['crl_next_update_str']}")
                    elif result['status'] == 'error':
                        self.crl_results_text.append(f"Error: {result.get('error', 'Unknown error')}")

            # Set progress to 100%
            self.crl_progress_bar.setValue(100)

        except Exception as e:
            # Show error
            self.crl_results_text.append(f"\nError: {str(e)}")
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")

        # Hide progress bar after a delay
        self.crl_progress_bar.setVisible(False)

    def check_ocsp_revocation(self):
        """Check certificate revocation using OCSP."""
        # Validate inputs
        cert_file = self.ocsp_cert_file_field.text()
        if not cert_file:
            QMessageBox.warning(self, "Missing Certificate", "Please select a certificate file.")
            return

        issuer_file = self.ocsp_issuer_file_field.text()
        if not issuer_file:
            QMessageBox.warning(self, "Missing Issuer Certificate", "Please select an issuer certificate file.")
            return

        # Read certificate and issuer files
        try:
            with open(cert_file, 'rb') as f:
                cert_data = f.read()

            with open(issuer_file, 'rb') as f:
                issuer_data = f.read()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to read certificate files: {str(e)}")
            return

        # Show progress bar
        self.ocsp_progress_bar.setVisible(True)
        self.ocsp_progress_bar.setValue(0)

        # Clear results
        self.ocsp_results_text.clear()
        self.ocsp_results_text.append("Checking certificate revocation status...")

        try:
            # Check revocation
            if self.ocsp_url_field.text():
                # Check against the provided OCSP responder
                self.ocsp_progress_bar.setValue(50)
                result = self.revocation_checker.check_certificate_with_ocsp(
                    certificate=cert_data,
                    issuer_certificate=issuer_data,
                    ocsp_url=self.ocsp_url_field.text()
                )

                # Display result
                self.ocsp_results_text.append("\nOCSP Check Result:")
                self.ocsp_results_text.append(f"Status: {result['status']}")
                self.ocsp_results_text.append(f"OCSP URL: {result['ocsp_url']}")

                if result['status'] == 'revoked':
                    self.ocsp_results_text.append(f"Revoked: {result['revoked']}")
                    if 'reason' in result and result['reason']:
                        self.ocsp_results_text.append(f"Reason: {result['reason']}")
                    if 'revocation_time_str' in result:
                        self.ocsp_results_text.append(f"Revocation Time: {result['revocation_time_str']}")
                elif result['status'] == 'good':
                    self.ocsp_results_text.append(f"Revoked: {result['revoked']}")
                    if 'this_update_str' in result:
                        self.ocsp_results_text.append(f"This Update: {result['this_update_str']}")
                    if 'next_update_str' in result and result['next_update_str']:
                        self.ocsp_results_text.append(f"Next Update: {result['next_update_str']}")
                elif result['status'] == 'error':
                    self.ocsp_results_text.append(f"Error: {result.get('error', 'Unknown error')}")
            else:
                # Check against OCSP responders from the certificate
                self.ocsp_progress_bar.setValue(30)
                results = self.revocation_checker.check_certificate_ocsp(
                    certificate=cert_data,
                    issuer_certificate=issuer_data
                )

                # Display results
                self.ocsp_results_text.append("\nOCSP Check Results:")
                for i, result in enumerate(results):
                    self.ocsp_progress_bar.setValue(30 + (i + 1) * 70 // len(results))
                    self.ocsp_results_text.append(f"\nResult {i+1}:")
                    self.ocsp_results_text.append(f"Status: {result['status']}")
                    if 'ocsp_url' in result:
                        self.ocsp_results_text.append(f"OCSP URL: {result['ocsp_url']}")

                    if result['status'] == 'revoked':
                        self.ocsp_results_text.append(f"Revoked: {result['revoked']}")
                        if 'reason' in result and result['reason']:
                            self.ocsp_results_text.append(f"Reason: {result['reason']}")
                        if 'revocation_time_str' in result:
                            self.ocsp_results_text.append(f"Revocation Time: {result['revocation_time_str']}")
                    elif result['status'] == 'good':
                        self.ocsp_results_text.append(f"Revoked: {result['revoked']}")
                        if 'this_update_str' in result:
                            self.ocsp_results_text.append(f"This Update: {result['this_update_str']}")
                        if 'next_update_str' in result and result['next_update_str']:
                            self.ocsp_results_text.append(f"Next Update: {result['next_update_str']}")
                    elif result['status'] == 'error':
                        self.ocsp_results_text.append(f"Error: {result.get('error', 'Unknown error')}")

            # Set progress to 100%
            self.ocsp_progress_bar.setValue(100)

        except Exception as e:
            # Show error
            self.ocsp_results_text.append(f"\nError: {str(e)}")
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")

        # Hide progress bar after a delay
        self.ocsp_progress_bar.setVisible(False)

    def refresh_cache_info(self):
        """Refresh the cache information."""
        try:
            # Get cache info
            cache_info = self.revocation_checker.get_cache_info()

            # Display cache info
            self.cache_info_text.clear()
            self.cache_info_text.append(f"Cache Directory: {cache_info['cache_dir']}")
            self.cache_info_text.append(f"Number of Files: {cache_info['file_count']}")
            self.cache_info_text.append(f"Total Size: {cache_info['total_size']} bytes")
            self.cache_info_text.append(f"Cache Entries: {len(cache_info['cache_entries'])}")

            # Display cache entries
            if cache_info['cache_entries']:
                self.cache_info_text.append("\nCache Entries:")
                for url, entry in cache_info['cache_entries'].items():
                    self.cache_info_text.append(f"\nURL: {url}")
                    self.cache_info_text.append(f"File: {entry['file']}")
                    self.cache_info_text.append(f"Last Updated: {datetime.datetime.fromtimestamp(entry['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}")
                    self.cache_info_text.append(f"Expires: {datetime.datetime.fromtimestamp(entry['expires']).strftime('%Y-%m-%d %H:%M:%S')}")
            else:
                self.cache_info_text.append("\nNo cache entries found.")

        except Exception as e:
            # Show error
            self.cache_info_text.append(f"\nError: {str(e)}")
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")

    def clear_cache(self):
        """Clear the CRL cache."""
        try:
            # Confirm with user
            reply = QMessageBox.question(
                self,
                "Clear Cache",
                "Are you sure you want to clear the CRL cache?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                return

            # Clear cache
            self.revocation_checker.clear_cache()

            # Refresh cache info
            self.refresh_cache_info()

            # Show success message
            QMessageBox.information(self, "Cache Cleared", "The CRL cache has been cleared successfully.")

        except Exception as e:
            # Show error
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")
