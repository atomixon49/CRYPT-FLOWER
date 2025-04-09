"""
Notification Center

This module provides a center for displaying and managing notifications.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QFrame, QSizePolicy, QSpacerItem
)
from PyQt6.QtCore import Qt, QTimer, QPoint, QSize
from PyQt6.QtGui import QIcon, QFont

from .notification_manager import NotificationManager, Notification
from .notification_widget import NotificationWidget

class NotificationCenter(QWidget):
    """Widget for displaying and managing notifications."""
    
    def __init__(self, notification_manager: NotificationManager, parent=None):
        """
        Initialize the notification center.
        
        Args:
            notification_manager: The notification manager
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.notification_manager = notification_manager
        self.notifications = {}  # id -> NotificationWidget
        self.setup_ui()
        
        # Connect signals
        self.notification_manager.notification_added.connect(self.add_notification)
        self.notification_manager.notification_removed.connect(self.remove_notification)
        self.notification_manager.notifications_cleared.connect(self.clear_notifications)
    
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
        content_widget.setObjectName("notification_center_content")
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(10, 10, 10, 10)
        content_layout.setSpacing(10)
        
        # Set style
        self.setStyleSheet("""
            #notification_center_content {
                background-color: rgba(240, 240, 240, 240);
                border-radius: 5px;
            }
        """)
        
        # Create header
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(5)
        
        # Add title
        title_label = QLabel("Notifications")
        title_font = QFont()
        title_font.setBold(True)
        title_font.setPointSize(12)
        title_label.setFont(title_font)
        header_layout.addWidget(title_label, 1)
        
        # Add clear button
        clear_button = QPushButton("Clear All")
        clear_button.clicked.connect(self.notification_manager.clear_notifications)
        header_layout.addWidget(clear_button)
        
        # Add close button
        close_button = QPushButton()
        close_button.setIcon(QIcon.fromTheme("window-close"))
        close_button.setFixedSize(24, 24)
        close_button.setFlat(True)
        close_button.clicked.connect(self.hide)
        header_layout.addWidget(close_button)
        
        # Add header to content layout
        content_layout.addLayout(header_layout)
        
        # Add separator
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFrameShadow(QFrame.Shadow.Sunken)
        content_layout.addWidget(separator)
        
        # Create scroll area for notifications
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        
        # Create widget for notifications
        self.notifications_widget = QWidget()
        self.notifications_layout = QVBoxLayout(self.notifications_widget)
        self.notifications_layout.setContentsMargins(0, 0, 0, 0)
        self.notifications_layout.setSpacing(10)
        self.notifications_layout.addStretch()
        
        # Add notifications widget to scroll area
        scroll_area.setWidget(self.notifications_widget)
        
        # Add scroll area to content layout
        content_layout.addWidget(scroll_area)
        
        # Add content widget to main layout
        main_layout.addWidget(content_widget)
        
        # Add existing notifications
        for notification in self.notification_manager.get_all_notifications():
            self.add_notification(notification)
    
    def add_notification(self, notification: Notification):
        """
        Add a notification to the center.
        
        Args:
            notification: The notification to add
        """
        # Create notification widget
        notification_widget = NotificationWidget(notification)
        
        # Add to layout (before the stretch)
        self.notifications_layout.insertWidget(0, notification_widget)
        
        # Store the widget
        self.notifications[notification.id] = notification_widget
        
        # Show the notification if not in the center
        if not self.isVisible():
            self._show_popup(notification_widget)
    
    def remove_notification(self, notification_id: str):
        """
        Remove a notification from the center.
        
        Args:
            notification_id: ID of the notification to remove
        """
        if notification_id in self.notifications:
            # Remove the widget
            notification_widget = self.notifications[notification_id]
            self.notifications_layout.removeWidget(notification_widget)
            notification_widget.deleteLater()
            
            # Remove from storage
            del self.notifications[notification_id]
    
    def clear_notifications(self):
        """Clear all notifications."""
        # Remove all widgets
        for notification_widget in self.notifications.values():
            self.notifications_layout.removeWidget(notification_widget)
            notification_widget.deleteLater()
        
        # Clear storage
        self.notifications.clear()
    
    def _show_popup(self, notification_widget: NotificationWidget):
        """
        Show a notification as a popup.
        
        Args:
            notification_widget: The notification widget to show
        """
        # Create a copy of the widget for the popup
        popup = NotificationWidget(notification_widget.notification)
        
        # Position the popup in the bottom right corner
        screen_geometry = self.screen().geometry()
        popup_x = screen_geometry.width() - popup.width() - 20
        popup_y = screen_geometry.height() - popup.height() - 20
        
        # Adjust for existing popups
        popup_y -= len([w for w in self.findChildren(NotificationWidget) if w.isVisible()]) * (popup.height() + 10)
        
        # Set position
        popup.move(popup_x, popup_y)
        
        # Show the popup
        popup.show()
    
    def toggle_visibility(self):
        """Toggle the visibility of the notification center."""
        if self.isVisible():
            self.hide()
        else:
            self.show()
            
            # Position in the top right corner
            screen_geometry = self.screen().geometry()
            center_x = screen_geometry.width() - self.width() - 20
            center_y = 40
            
            self.move(center_x, center_y)
