"""
Notification Widget

This module provides a widget for displaying a notification.
"""

import time
from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout, QLabel, QPushButton,
    QGraphicsOpacityEffect, QSizePolicy
)
from PyQt6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QSize
from PyQt6.QtGui import QIcon, QColor, QPalette, QFont

from .notification_manager import Notification, NotificationType

class NotificationWidget(QWidget):
    """Widget for displaying a notification."""
    
    def __init__(self, notification: Notification, parent=None):
        """
        Initialize the notification widget.
        
        Args:
            notification: The notification to display
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.notification = notification
        self.setup_ui()
        
        # Set up timeout
        if notification.timeout > 0:
            QTimer.singleShot(notification.timeout, self.close_animation)
    
    def setup_ui(self):
        """Set up the user interface."""
        # Set up the widget
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Tool)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setMinimumWidth(300)
        self.setMaximumWidth(400)
        
        # Create layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Create content widget
        content_widget = QWidget()
        content_widget.setObjectName("notification_content")
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(10, 10, 10, 10)
        content_layout.setSpacing(5)
        
        # Set style based on notification type
        self._set_style()
        
        # Create header layout
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(5)
        
        # Add icon
        icon_label = QLabel()
        icon_label.setFixedSize(24, 24)
        icon = self._get_icon()
        if icon:
            icon_label.setPixmap(icon.pixmap(QSize(24, 24)))
        header_layout.addWidget(icon_label)
        
        # Add title
        title_label = QLabel(self.notification.title)
        title_font = QFont()
        title_font.setBold(True)
        title_label.setFont(title_font)
        header_layout.addWidget(title_label, 1)
        
        # Add close button
        close_button = QPushButton()
        close_button.setIcon(QIcon.fromTheme("window-close"))
        close_button.setFixedSize(24, 24)
        close_button.setFlat(True)
        close_button.clicked.connect(self.close_animation)
        header_layout.addWidget(close_button)
        
        # Add header to content layout
        content_layout.addLayout(header_layout)
        
        # Add message
        message_label = QLabel(self.notification.message)
        message_label.setWordWrap(True)
        content_layout.addWidget(message_label)
        
        # Add actions if any
        if self.notification.actions:
            actions_layout = QHBoxLayout()
            actions_layout.setContentsMargins(0, 5, 0, 0)
            actions_layout.setSpacing(5)
            
            for action in self.notification.actions:
                action_button = QPushButton(action.get("text", "Action"))
                if "icon" in action:
                    action_button.setIcon(QIcon.fromTheme(action["icon"]))
                
                # Connect the action callback
                if "callback" in action and callable(action["callback"]):
                    action_button.clicked.connect(action["callback"])
                
                actions_layout.addWidget(action_button)
            
            content_layout.addLayout(actions_layout)
        
        # Add content widget to main layout
        main_layout.addWidget(content_widget)
        
        # Set up opacity effect for animations
        self.opacity_effect = QGraphicsOpacityEffect(self)
        self.opacity_effect.setOpacity(0.0)
        self.setGraphicsEffect(self.opacity_effect)
        
        # Start show animation
        self.show_animation()
    
    def _set_style(self):
        """Set the style based on the notification type."""
        style = ""
        
        if self.notification.type == NotificationType.INFO:
            style = """
                #notification_content {
                    background-color: #3498db;
                    color: white;
                    border-radius: 5px;
                }
            """
        elif self.notification.type == NotificationType.WARNING:
            style = """
                #notification_content {
                    background-color: #f39c12;
                    color: white;
                    border-radius: 5px;
                }
            """
        elif self.notification.type == NotificationType.ERROR:
            style = """
                #notification_content {
                    background-color: #e74c3c;
                    color: white;
                    border-radius: 5px;
                }
            """
        elif self.notification.type == NotificationType.SECURITY:
            style = """
                #notification_content {
                    background-color: #9b59b6;
                    color: white;
                    border-radius: 5px;
                }
            """
        elif self.notification.type == NotificationType.SUCCESS:
            style = """
                #notification_content {
                    background-color: #2ecc71;
                    color: white;
                    border-radius: 5px;
                }
            """
        
        self.setStyleSheet(style)
    
    def _get_icon(self):
        """Get the icon for the notification type."""
        if self.notification.type == NotificationType.INFO:
            return QIcon.fromTheme("dialog-information")
        elif self.notification.type == NotificationType.WARNING:
            return QIcon.fromTheme("dialog-warning")
        elif self.notification.type == NotificationType.ERROR:
            return QIcon.fromTheme("dialog-error")
        elif self.notification.type == NotificationType.SECURITY:
            return QIcon.fromTheme("security-high")
        elif self.notification.type == NotificationType.SUCCESS:
            return QIcon.fromTheme("dialog-ok")
        
        return None
    
    def show_animation(self):
        """Show the notification with an animation."""
        self.animation = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.animation.setDuration(250)
        self.animation.setStartValue(0.0)
        self.animation.setEndValue(1.0)
        self.animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.animation.start()
    
    def close_animation(self):
        """Close the notification with an animation."""
        self.animation = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.animation.setDuration(250)
        self.animation.setStartValue(1.0)
        self.animation.setEndValue(0.0)
        self.animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.animation.finished.connect(self.close)
        self.animation.start()
    
    def mousePressEvent(self, event):
        """Handle mouse press events."""
        if event.button() == Qt.MouseButton.LeftButton:
            # Mark the notification as read
            self.notification.mark_as_read()
            
            # Close the notification
            self.close_animation()
        
        super().mousePressEvent(event)
