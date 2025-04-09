"""
Base wizard class for guided operations.

This module provides a base class for all wizards in the application.
"""

from PyQt6.QtWidgets import QWizard, QWizardPage, QVBoxLayout, QLabel, QApplication
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QPixmap, QFont

class BaseWizardPage(QWizardPage):
    """Base class for wizard pages."""
    
    def __init__(self, title, subtitle=None, parent=None):
        """Initialize the wizard page."""
        super().__init__(parent)
        
        self.setTitle(title)
        if subtitle:
            self.setSubTitle(subtitle)
        
        # Create layout
        self.layout = QVBoxLayout(self)
        
        # Set up the page
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the user interface for the page."""
        # To be implemented by subclasses
        pass

class BaseWizard(QWizard):
    """Base class for all wizards in the application."""
    
    # Signal emitted when the wizard completes successfully
    completed = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        """Initialize the wizard."""
        super().__init__(parent)
        
        # Set wizard style
        self.setWizardStyle(QWizard.WizardStyle.ModernStyle)
        
        # Set window properties
        self.setWindowTitle("Operation Wizard")
        self.setMinimumSize(700, 500)
        
        # Set wizard options
        self.setOption(QWizard.WizardOption.HaveHelpButton, True)
        self.setOption(QWizard.WizardOption.HelpButtonOnRight, False)
        
        # Connect signals
        self.helpRequested.connect(self.show_help)
        self.finished.connect(self.handle_finished)
        
        # Initialize result data
        self.result_data = {}
        
        # Set up the wizard
        self.setup_ui()
        self.add_pages()
    
    def setup_ui(self):
        """Set up the user interface for the wizard."""
        # Set up the sidebar
        self.setPixmap(QWizard.WizardPixmap.WatermarkPixmap, QPixmap("assets/wizard_watermark.png"))
        self.setPixmap(QWizard.WizardPixmap.LogoPixmap, QPixmap("assets/wizard_logo.png"))
        self.setPixmap(QWizard.WizardPixmap.BannerPixmap, QPixmap("assets/wizard_banner.png"))
        
        # Set up the button text
        self.setButtonText(QWizard.WizardButton.NextButton, "Next >")
        self.setButtonText(QWizard.WizardButton.BackButton, "< Back")
        self.setButtonText(QWizard.WizardButton.FinishButton, "Finish")
        self.setButtonText(QWizard.WizardButton.CancelButton, "Cancel")
        self.setButtonText(QWizard.WizardButton.HelpButton, "Help")
    
    def add_pages(self):
        """Add pages to the wizard."""
        # To be implemented by subclasses
        pass
    
    def show_help(self):
        """Show help for the current page."""
        current_page = self.currentPage()
        page_title = current_page.title()
        
        # Create a simple help message based on the page title
        help_text = f"Help for {page_title}\n\n"
        help_text += "This is a generic help message. Each wizard should provide specific help content."
        
        from PyQt6.QtWidgets import QMessageBox
        QMessageBox.information(self, "Help", help_text)
    
    def handle_finished(self, result):
        """Handle the wizard finishing."""
        if result == QWizard.DialogCode.Accepted:
            # Collect data from all fields
            self.collect_data()
            
            # Emit the completed signal with the result data
            self.completed.emit(self.result_data)
    
    def collect_data(self):
        """Collect data from all fields."""
        # To be implemented by subclasses
        pass
    
    def get_result_data(self):
        """Get the result data from the wizard."""
        return self.result_data
