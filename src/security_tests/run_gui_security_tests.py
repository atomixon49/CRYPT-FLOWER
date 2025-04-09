"""
Run GUI Security Tests Script

This script runs security tests specifically for the GUI components.
"""

import os
import sys
import time
import logging
import argparse
import datetime
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.security_tests.penetration_tests import UISecurityTester
from src.security_tests.fuzzing import FuzzingEngine, FuzzGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("gui_security_tests.log")
    ]
)
logger = logging.getLogger("gui_security_tests")

def run_ui_security_tests(output_dir: str) -> None:
    """
    Run UI security tests.
    
    Args:
        output_dir: Directory to save the results
    """
    logger.info("Running UI security tests...")
    
    # Create the UI security tester
    tester = UISecurityTester()
    
    # Test input validation for various GUI components
    
    # Test file path validation
    def validate_file_path(path: str) -> str:
        if not path:
            return "Path cannot be empty"
        
        if not os.path.exists(path):
            return f"Path does not exist: {path}"
        
        if os.path.isdir(path):
            return f"Path is a directory: {path}"
        
        return "Valid file path"
    
    # Test password validation
    def validate_password(password: str) -> str:
        if not password:
            return "Password cannot be empty"
        
        if len(password) < 8:
            return "Password must be at least 8 characters long"
        
        if not any(c.isupper() for c in password):
            return "Password must contain at least one uppercase letter"
        
        if not any(c.islower() for c in password):
            return "Password must contain at least one lowercase letter"
        
        if not any(c.isdigit() for c in password):
            return "Password must contain at least one digit"
        
        return "Valid password"
    
    # Test email validation
    def validate_email(email: str) -> str:
        if not email:
            return "Email cannot be empty"
        
        if "@" not in email:
            return "Email must contain @"
        
        if "." not in email:
            return "Email must contain a domain"
        
        return "Valid email"
    
    # Test key ID validation
    def validate_key_id(key_id: str) -> str:
        if not key_id:
            return "Key ID cannot be empty"
        
        if not key_id.isalnum():
            return "Key ID must be alphanumeric"
        
        return "Valid key ID"
    
    # Run the tests
    file_path_result = tester.test_input_validation(validate_file_path)
    password_result = tester.test_input_validation(validate_password)
    email_result = tester.test_input_validation(validate_email)
    key_id_result = tester.test_input_validation(validate_key_id)
    
    # Test XSS for various GUI components
    
    # Test HTML display
    def display_html(html: str) -> str:
        # Simulate a function that displays HTML in the GUI
        return f"<div>{html}</div>"
    
    # Test file content display
    def display_file_content(content: str) -> str:
        # Simulate a function that displays file content in the GUI
        return f"<pre>{content}</pre>"
    
    # Test key info display
    def display_key_info(key_info: str) -> str:
        # Simulate a function that displays key information in the GUI
        return f"<div>Key Info: {key_info}</div>"
    
    # Run the tests
    html_result = tester.test_xss(display_html)
    file_content_result = tester.test_xss(display_file_content)
    key_info_result = tester.test_xss(display_key_info)
    
    # Generate the report
    output_file = os.path.join(output_dir, "ui_security_test_report.md")
    tester.generate_report(output_file)
    
    logger.info("UI security tests completed.")
    logger.info(f"Report saved to {output_file}")

def run_gui_fuzzing(output_dir: str) -> None:
    """
    Run fuzzing on GUI components.
    
    Args:
        output_dir: Directory to save the results
    """
    logger.info("Running GUI fuzzing...")
    
    # Create the fuzzing engine
    engine = FuzzingEngine()
    
    # Create a fuzz generator
    generator = FuzzGenerator()
    
    # Test file path handling
    def process_file_path(path: str) -> str:
        try:
            # Simulate file path processing in the GUI
            if not path:
                return "Empty path"
            
            if os.path.exists(path):
                return f"File exists: {path}"
            else:
                return f"File does not exist: {path}"
        except Exception as e:
            return str(e)
    
    # Test password handling
    def process_password(password: str) -> str:
        try:
            # Simulate password processing in the GUI
            if not password:
                return "Empty password"
            
            # Hash the password (for demonstration purposes)
            import hashlib
            hashed = hashlib.sha256(password.encode()).hexdigest()
            
            return f"Password processed: {hashed[:10]}..."
        except Exception as e:
            return str(e)
    
    # Test key ID handling
    def process_key_id(key_id: str) -> str:
        try:
            # Simulate key ID processing in the GUI
            if not key_id:
                return "Empty key ID"
            
            # Validate the key ID
            if not key_id.isalnum():
                return f"Invalid key ID: {key_id}"
            
            return f"Valid key ID: {key_id}"
        except Exception as e:
            return str(e)
    
    # Add fuzzing targets
    engine.add_function(
        name="file_path_processing",
        function=process_file_path,
        input_types=["str"],
        iterations=500
    )
    
    engine.add_function(
        name="password_processing",
        function=process_password,
        input_types=["str"],
        iterations=500
    )
    
    engine.add_function(
        name="key_id_processing",
        function=process_key_id,
        input_types=["str"],
        iterations=500
    )
    
    # Run fuzzing
    engine.run()
    
    # Generate the report
    output_file = os.path.join(output_dir, "gui_fuzzing_report.md")
    engine.generate_report(output_file)
    
    logger.info("GUI fuzzing completed.")
    logger.info(f"Report saved to {output_file}")

def main():
    """Main function."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Run GUI security tests.")
    parser.add_argument("--output-dir", default="gui_security_test_results",
                        help="Directory to save the results")
    parser.add_argument("--ui-tests", action="store_true",
                        help="Run UI security tests")
    parser.add_argument("--fuzzing", action="store_true",
                        help="Run GUI fuzzing")
    parser.add_argument("--all", action="store_true",
                        help="Run all tests")
    
    args = parser.parse_args()
    
    # Create the output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Create a subdirectory for this run
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(args.output_dir, f"run_{timestamp}")
    os.makedirs(run_dir, exist_ok=True)
    
    # Run the tests
    if args.all or args.ui_tests:
        run_ui_security_tests(run_dir)
    
    if args.all or args.fuzzing:
        run_gui_fuzzing(run_dir)
    
    logger.info(f"All GUI security tests completed. Results saved to {run_dir}")

if __name__ == "__main__":
    main()
