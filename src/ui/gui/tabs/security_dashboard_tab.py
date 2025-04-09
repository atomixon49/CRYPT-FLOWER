"""
Security Dashboard Tab

This module provides a dashboard for visualizing the security status of the system.
"""

import os
import time
import datetime
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
    QGroupBox, QProgressBar, QTableWidget, QTableWidgetItem,
    QHeaderView, QSplitter, QFrame, QScrollArea
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QPalette, QFont, QIcon

from ....core.key_management import KeyManager
from ....core.crypto_audit import CryptoAuditLogger
from ....core.cert_revocation import CertificateRevocationChecker

class SecurityScoreWidget(QWidget):
    """Widget for displaying a security score."""
    
    def __init__(self, title, parent=None):
        super().__init__(parent)
        self.title = title
        self.score = 0
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Title
        title_label = QLabel(self.title)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_font = QFont()
        title_font.setBold(True)
        title_label.setFont(title_font)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%v%")
        
        # Score label
        self.score_label = QLabel("Score: 0/100")
        self.score_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Add to layout
        layout.addWidget(title_label)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.score_label)
    
    def set_score(self, score):
        """Set the security score."""
        self.score = score
        self.progress_bar.setValue(score)
        self.score_label.setText(f"Score: {score}/100")
        
        # Set color based on score
        if score < 50:
            self.progress_bar.setStyleSheet("QProgressBar::chunk { background-color: #e74c3c; }")
        elif score < 80:
            self.progress_bar.setStyleSheet("QProgressBar::chunk { background-color: #f39c12; }")
        else:
            self.progress_bar.setStyleSheet("QProgressBar::chunk { background-color: #2ecc71; }")

class SecurityAlertWidget(QWidget):
    """Widget for displaying security alerts."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.alerts = []
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Title
        title_label = QLabel("Security Alerts")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_font = QFont()
        title_font.setBold(True)
        title_label.setFont(title_font)
        
        # Alerts table
        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(4)
        self.alerts_table.setHorizontalHeaderLabels(["Severity", "Type", "Description", "Time"])
        self.alerts_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        # Add to layout
        layout.addWidget(title_label)
        layout.addWidget(self.alerts_table)
    
    def add_alert(self, severity, alert_type, description):
        """Add a new security alert."""
        # Create a new row
        row = self.alerts_table.rowCount()
        self.alerts_table.insertRow(row)
        
        # Create items
        severity_item = QTableWidgetItem(severity)
        type_item = QTableWidgetItem(alert_type)
        description_item = QTableWidgetItem(description)
        time_item = QTableWidgetItem(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        # Set colors based on severity
        if severity == "High":
            severity_item.setBackground(QColor("#e74c3c"))
            severity_item.setForeground(QColor("#ffffff"))
        elif severity == "Medium":
            severity_item.setBackground(QColor("#f39c12"))
        elif severity == "Low":
            severity_item.setBackground(QColor("#2ecc71"))
        
        # Add items to the table
        self.alerts_table.setItem(row, 0, severity_item)
        self.alerts_table.setItem(row, 1, type_item)
        self.alerts_table.setItem(row, 2, description_item)
        self.alerts_table.setItem(row, 3, time_item)
        
        # Store the alert
        self.alerts.append({
            "severity": severity,
            "type": alert_type,
            "description": description,
            "time": datetime.datetime.now()
        })
    
    def clear_alerts(self):
        """Clear all security alerts."""
        self.alerts_table.setRowCount(0)
        self.alerts = []

class KeyStatusWidget(QWidget):
    """Widget for displaying key status information."""
    
    def __init__(self, key_manager, parent=None):
        super().__init__(parent)
        self.key_manager = key_manager
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Title
        title_label = QLabel("Key Status")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_font = QFont()
        title_font.setBold(True)
        title_label.setFont(title_font)
        
        # Key status table
        self.key_table = QTableWidget()
        self.key_table.setColumnCount(5)
        self.key_table.setHorizontalHeaderLabels(["Key ID", "Type", "Algorithm", "Strength", "Status"])
        self.key_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        # Refresh button
        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self.refresh_keys)
        
        # Add to layout
        layout.addWidget(title_label)
        layout.addWidget(self.key_table)
        layout.addWidget(refresh_button)
        
        # Initial refresh
        self.refresh_keys()
    
    def refresh_keys(self):
        """Refresh the key status information."""
        self.key_table.setRowCount(0)
        
        # Get all keys
        keys = self.key_manager.active_keys
        
        # Add keys to the table
        for key_id, key_data in keys.items():
            row = self.key_table.rowCount()
            self.key_table.insertRow(row)
            
            # Get key info
            key_info = self.key_manager.get_key_info(key_id)
            
            # Create items
            key_id_item = QTableWidgetItem(key_id)
            key_type_item = QTableWidgetItem(key_info.get("key_type", "Unknown"))
            algorithm_item = QTableWidgetItem(key_info.get("algorithm", "Unknown"))
            
            # Calculate key strength
            strength = self._calculate_key_strength(key_info)
            strength_item = QTableWidgetItem(strength["label"])
            
            # Set color based on strength
            if strength["score"] < 50:
                strength_item.setBackground(QColor("#e74c3c"))
                strength_item.setForeground(QColor("#ffffff"))
            elif strength["score"] < 80:
                strength_item.setBackground(QColor("#f39c12"))
            else:
                strength_item.setBackground(QColor("#2ecc71"))
            
            # Determine key status
            status = self._determine_key_status(key_info)
            status_item = QTableWidgetItem(status["label"])
            
            # Set color based on status
            if status["score"] < 50:
                status_item.setBackground(QColor("#e74c3c"))
                status_item.setForeground(QColor("#ffffff"))
            elif status["score"] < 80:
                status_item.setBackground(QColor("#f39c12"))
            else:
                status_item.setBackground(QColor("#2ecc71"))
            
            # Add items to the table
            self.key_table.setItem(row, 0, key_id_item)
            self.key_table.setItem(row, 1, key_type_item)
            self.key_table.setItem(row, 2, algorithm_item)
            self.key_table.setItem(row, 3, strength_item)
            self.key_table.setItem(row, 4, status_item)
    
    def _calculate_key_strength(self, key_info):
        """Calculate the strength of a key."""
        algorithm = key_info.get("algorithm", "").upper()
        key_size = key_info.get("key_size", 0)
        
        # Default values
        score = 0
        label = "Unknown"
        
        # Evaluate based on algorithm and key size
        if algorithm == "RSA":
            if key_size >= 4096:
                score = 100
                label = "Excellent"
            elif key_size >= 3072:
                score = 90
                label = "Very Good"
            elif key_size >= 2048:
                score = 70
                label = "Good"
            else:
                score = 30
                label = "Weak"
        
        elif algorithm == "ECC":
            if key_size >= 384:
                score = 100
                label = "Excellent"
            elif key_size >= 256:
                score = 90
                label = "Very Good"
            else:
                score = 50
                label = "Moderate"
        
        elif algorithm == "AES":
            if key_size >= 256:
                score = 100
                label = "Excellent"
            elif key_size >= 192:
                score = 90
                label = "Very Good"
            elif key_size >= 128:
                score = 80
                label = "Good"
            else:
                score = 30
                label = "Weak"
        
        elif algorithm == "CHACHA20":
            score = 90
            label = "Very Good"
        
        elif algorithm.startswith("KYBER") or algorithm.startswith("DILITHIUM"):
            score = 100
            label = "Post-Quantum"
        
        return {"score": score, "label": label}
    
    def _determine_key_status(self, key_info):
        """Determine the status of a key."""
        # Check creation date
        created = key_info.get("created", 0)
        current_time = time.time()
        age_days = (current_time - created) / (24 * 60 * 60) if created else 0
        
        # Check expiration
        expires = key_info.get("expires", 0)
        days_until_expiry = (expires - current_time) / (24 * 60 * 60) if expires else float('inf')
        
        # Default values
        score = 100
        label = "Active"
        
        # Check for expiration
        if expires and expires < current_time:
            score = 0
            label = "Expired"
        elif days_until_expiry < 30:
            score = 30
            label = "Expiring Soon"
        
        # Check for age
        if age_days > 365 * 2:  # Older than 2 years
            score = min(score, 50)
            label = "Rotation Recommended"
        
        # Check for revocation
        if key_info.get("revoked", False):
            score = 0
            label = "Revoked"
        
        return {"score": score, "label": label}

class SecurityRecommendationWidget(QWidget):
    """Widget for displaying security recommendations."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.recommendations = []
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Title
        title_label = QLabel("Security Recommendations")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_font = QFont()
        title_font.setBold(True)
        title_label.setFont(title_font)
        
        # Recommendations table
        self.recommendations_table = QTableWidget()
        self.recommendations_table.setColumnCount(3)
        self.recommendations_table.setHorizontalHeaderLabels(["Priority", "Recommendation", "Action"])
        self.recommendations_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        # Add to layout
        layout.addWidget(title_label)
        layout.addWidget(self.recommendations_table)
    
    def add_recommendation(self, priority, recommendation, action):
        """Add a new security recommendation."""
        # Create a new row
        row = self.recommendations_table.rowCount()
        self.recommendations_table.insertRow(row)
        
        # Create items
        priority_item = QTableWidgetItem(priority)
        recommendation_item = QTableWidgetItem(recommendation)
        action_item = QTableWidgetItem(action)
        
        # Set colors based on priority
        if priority == "High":
            priority_item.setBackground(QColor("#e74c3c"))
            priority_item.setForeground(QColor("#ffffff"))
        elif priority == "Medium":
            priority_item.setBackground(QColor("#f39c12"))
        elif priority == "Low":
            priority_item.setBackground(QColor("#2ecc71"))
        
        # Add items to the table
        self.recommendations_table.setItem(row, 0, priority_item)
        self.recommendations_table.setItem(row, 1, recommendation_item)
        self.recommendations_table.setItem(row, 2, action_item)
        
        # Store the recommendation
        self.recommendations.append({
            "priority": priority,
            "recommendation": recommendation,
            "action": action
        })
    
    def clear_recommendations(self):
        """Clear all security recommendations."""
        self.recommendations_table.setRowCount(0)
        self.recommendations = []

class SecurityDashboardTab(QWidget):
    """Tab for displaying security dashboard."""
    
    def __init__(self, key_manager, audit_logger, cert_checker=None):
        super().__init__()
        self.key_manager = key_manager
        self.audit_logger = audit_logger
        self.cert_checker = cert_checker or CertificateRevocationChecker()
        
        # Set up the UI
        self.setup_ui()
        
        # Set up timer for periodic updates
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update_dashboard)
        self.update_timer.start(60000)  # Update every minute
        
        # Initial update
        self.update_dashboard()
    
    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        
        # Create a scroll area
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        
        # Security scores
        scores_group = QGroupBox("Security Scores")
        scores_layout = QHBoxLayout()
        
        self.overall_score = SecurityScoreWidget("Overall Security")
        self.key_score = SecurityScoreWidget("Key Management")
        self.encryption_score = SecurityScoreWidget("Encryption")
        self.authentication_score = SecurityScoreWidget("Authentication")
        
        scores_layout.addWidget(self.overall_score)
        scores_layout.addWidget(self.key_score)
        scores_layout.addWidget(self.encryption_score)
        scores_layout.addWidget(self.authentication_score)
        
        scores_group.setLayout(scores_layout)
        
        # Key status
        self.key_status = KeyStatusWidget(self.key_manager)
        
        # Security alerts
        self.security_alerts = SecurityAlertWidget()
        
        # Security recommendations
        self.security_recommendations = SecurityRecommendationWidget()
        
        # Add widgets to layout
        scroll_layout.addWidget(scores_group)
        scroll_layout.addWidget(self.key_status)
        scroll_layout.addWidget(self.security_alerts)
        scroll_layout.addWidget(self.security_recommendations)
        
        # Set the scroll area widget
        scroll_area.setWidget(scroll_content)
        
        # Add scroll area to main layout
        main_layout.addWidget(scroll_area)
        
        # Add refresh button
        refresh_button = QPushButton("Refresh Dashboard")
        refresh_button.clicked.connect(self.update_dashboard)
        main_layout.addWidget(refresh_button)
    
    def update_dashboard(self):
        """Update the security dashboard."""
        # Update security scores
        self._update_security_scores()
        
        # Update key status
        self.key_status.refresh_keys()
        
        # Update security alerts
        self._update_security_alerts()
        
        # Update security recommendations
        self._update_security_recommendations()
    
    def _update_security_scores(self):
        """Update the security scores."""
        # Calculate scores
        key_score = self._calculate_key_score()
        encryption_score = self._calculate_encryption_score()
        authentication_score = self._calculate_authentication_score()
        
        # Calculate overall score
        overall_score = int((key_score + encryption_score + authentication_score) / 3)
        
        # Update widgets
        self.overall_score.set_score(overall_score)
        self.key_score.set_score(key_score)
        self.encryption_score.set_score(encryption_score)
        self.authentication_score.set_score(authentication_score)
    
    def _calculate_key_score(self):
        """Calculate the key management security score."""
        score = 100
        
        # Get all keys
        keys = self.key_manager.active_keys
        
        if not keys:
            return 0
        
        # Check each key
        weak_keys = 0
        old_keys = 0
        expired_keys = 0
        revoked_keys = 0
        
        for key_id, key_data in keys.items():
            key_info = self.key_manager.get_key_info(key_id)
            
            # Check algorithm and key size
            algorithm = key_info.get("algorithm", "").upper()
            key_size = key_info.get("key_size", 0)
            
            if algorithm == "RSA" and key_size < 2048:
                weak_keys += 1
            elif algorithm == "ECC" and key_size < 256:
                weak_keys += 1
            elif algorithm == "AES" and key_size < 128:
                weak_keys += 1
            
            # Check age
            created = key_info.get("created", 0)
            current_time = time.time()
            age_days = (current_time - created) / (24 * 60 * 60) if created else 0
            
            if age_days > 365 * 2:  # Older than 2 years
                old_keys += 1
            
            # Check expiration
            expires = key_info.get("expires", 0)
            if expires and expires < current_time:
                expired_keys += 1
            
            # Check revocation
            if key_info.get("revoked", False):
                revoked_keys += 1
        
        # Calculate penalties
        total_keys = len(keys)
        weak_penalty = (weak_keys / total_keys) * 40 if total_keys > 0 else 0
        old_penalty = (old_keys / total_keys) * 20 if total_keys > 0 else 0
        expired_penalty = (expired_keys / total_keys) * 30 if total_keys > 0 else 0
        revoked_penalty = (revoked_keys / total_keys) * 30 if total_keys > 0 else 0
        
        # Apply penalties
        score -= int(weak_penalty + old_penalty + expired_penalty + revoked_penalty)
        
        # Ensure score is within range
        return max(0, min(100, score))
    
    def _calculate_encryption_score(self):
        """Calculate the encryption security score."""
        # This is a simplified calculation
        # In a real implementation, you would analyze encryption settings and usage
        
        score = 80  # Default score
        
        # Check if post-quantum algorithms are available
        has_pq = False
        for key_id, key_data in self.key_manager.active_keys.items():
            key_info = self.key_manager.get_key_info(key_id)
            algorithm = key_info.get("algorithm", "").upper()
            if algorithm.startswith("KYBER") or algorithm.startswith("DILITHIUM"):
                has_pq = True
                break
        
        if has_pq:
            score += 10
        
        # Check for weak algorithms
        has_weak = False
        for key_id, key_data in self.key_manager.active_keys.items():
            key_info = self.key_manager.get_key_info(key_id)
            algorithm = key_info.get("algorithm", "").upper()
            key_size = key_info.get("key_size", 0)
            
            if algorithm == "RSA" and key_size < 2048:
                has_weak = True
                break
            elif algorithm == "AES" and key_size < 128:
                has_weak = True
                break
        
        if has_weak:
            score -= 30
        
        # Ensure score is within range
        return max(0, min(100, score))
    
    def _calculate_authentication_score(self):
        """Calculate the authentication security score."""
        # This is a simplified calculation
        # In a real implementation, you would analyze authentication settings and usage
        
        score = 70  # Default score
        
        # Check for digital signatures
        has_signatures = False
        for key_id, key_data in self.key_manager.active_keys.items():
            if key_id.endswith('.private') and 'RSA' in key_id:
                has_signatures = True
                break
        
        if has_signatures:
            score += 15
        
        # Check for certificate validation
        has_cert_validation = self.cert_checker is not None
        if has_cert_validation:
            score += 15
        
        # Ensure score is within range
        return max(0, min(100, score))
    
    def _update_security_alerts(self):
        """Update the security alerts."""
        # Clear existing alerts
        self.security_alerts.clear_alerts()
        
        # Check for weak keys
        for key_id, key_data in self.key_manager.active_keys.items():
            key_info = self.key_manager.get_key_info(key_id)
            
            # Check algorithm and key size
            algorithm = key_info.get("algorithm", "").upper()
            key_size = key_info.get("key_size", 0)
            
            if algorithm == "RSA" and key_size < 2048:
                self.security_alerts.add_alert(
                    "High",
                    "Weak Key",
                    f"Key {key_id} uses RSA with key size {key_size}, which is considered weak."
                )
            elif algorithm == "ECC" and key_size < 256:
                self.security_alerts.add_alert(
                    "Medium",
                    "Weak Key",
                    f"Key {key_id} uses ECC with key size {key_size}, which is below recommended strength."
                )
            elif algorithm == "AES" and key_size < 128:
                self.security_alerts.add_alert(
                    "High",
                    "Weak Key",
                    f"Key {key_id} uses AES with key size {key_size}, which is considered weak."
                )
            
            # Check expiration
            expires = key_info.get("expires", 0)
            current_time = time.time()
            
            if expires and expires < current_time:
                self.security_alerts.add_alert(
                    "High",
                    "Expired Key",
                    f"Key {key_id} has expired on {datetime.datetime.fromtimestamp(expires).strftime('%Y-%m-%d')}."
                )
            elif expires and (expires - current_time) < 30 * 24 * 60 * 60:  # Less than 30 days
                self.security_alerts.add_alert(
                    "Medium",
                    "Expiring Key",
                    f"Key {key_id} will expire on {datetime.datetime.fromtimestamp(expires).strftime('%Y-%m-%d')}."
                )
            
            # Check revocation
            if key_info.get("revoked", False):
                self.security_alerts.add_alert(
                    "High",
                    "Revoked Key",
                    f"Key {key_id} has been revoked and should not be used."
                )
        
        # Check for missing post-quantum algorithms
        has_pq = False
        for key_id, key_data in self.key_manager.active_keys.items():
            key_info = self.key_manager.get_key_info(key_id)
            algorithm = key_info.get("algorithm", "").upper()
            if algorithm.startswith("KYBER") or algorithm.startswith("DILITHIUM"):
                has_pq = True
                break
        
        if not has_pq:
            self.security_alerts.add_alert(
                "Low",
                "Post-Quantum Readiness",
                "No post-quantum cryptographic algorithms are in use. Consider adding post-quantum keys."
            )
    
    def _update_security_recommendations(self):
        """Update the security recommendations."""
        # Clear existing recommendations
        self.security_recommendations.clear_recommendations()
        
        # Check for weak keys
        weak_keys = []
        for key_id, key_data in self.key_manager.active_keys.items():
            key_info = self.key_manager.get_key_info(key_id)
            
            # Check algorithm and key size
            algorithm = key_info.get("algorithm", "").upper()
            key_size = key_info.get("key_size", 0)
            
            if algorithm == "RSA" and key_size < 2048:
                weak_keys.append(key_id)
        
        if weak_keys:
            self.security_recommendations.add_recommendation(
                "High",
                "Replace weak RSA keys with stronger ones",
                "Generate new RSA keys with at least 3072 bits"
            )
        
        # Check for old keys
        old_keys = []
        for key_id, key_data in self.key_manager.active_keys.items():
            key_info = self.key_manager.get_key_info(key_id)
            
            # Check age
            created = key_info.get("created", 0)
            current_time = time.time()
            age_days = (current_time - created) / (24 * 60 * 60) if created else 0
            
            if age_days > 365 * 2:  # Older than 2 years
                old_keys.append(key_id)
        
        if old_keys:
            self.security_recommendations.add_recommendation(
                "Medium",
                "Rotate old keys",
                "Generate new keys and replace keys older than 2 years"
            )
        
        # Check for post-quantum readiness
        has_pq = False
        for key_id, key_data in self.key_manager.active_keys.items():
            key_info = self.key_manager.get_key_info(key_id)
            algorithm = key_info.get("algorithm", "").upper()
            if algorithm.startswith("KYBER") or algorithm.startswith("DILITHIUM"):
                has_pq = True
                break
        
        if not has_pq:
            self.security_recommendations.add_recommendation(
                "Medium",
                "Add post-quantum cryptographic keys",
                "Generate KYBER or DILITHIUM keys for post-quantum security"
            )
        
        # Add general recommendations
        self.security_recommendations.add_recommendation(
            "Low",
            "Enable certificate revocation checking",
            "Configure CRL and OCSP checking for all certificate operations"
        )
        
        self.security_recommendations.add_recommendation(
            "Low",
            "Use timestamping for all signatures",
            "Configure automatic timestamping with a trusted TSA"
        )
