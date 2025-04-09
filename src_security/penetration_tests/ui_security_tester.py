"""
UI Security Tester Module

This module provides a tester for UI security vulnerabilities.
"""

import os
import time
import logging
import random
import string
from typing import List, Dict, Any, Optional, Tuple, Callable

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ui_security_tester")

class UISecurityTest:
    """Base class for UI security tests."""
    
    def __init__(self, name: str, description: str):
        """
        Initialize a UI security test.
        
        Args:
            name: Test name
            description: Test description
        """
        self.name = name
        self.description = description
        self.result = None
        self.success = None
        self.start_time = None
        self.end_time = None
        self.duration = None
    
    def run(self, *args, **kwargs) -> bool:
        """
        Run the UI security test.
        
        Returns:
            True if the test was successful, False otherwise
        """
        self.start_time = time.time()
        
        try:
            self.success = self._run_test(*args, **kwargs)
            self.result = "Success" if self.success else "Failure"
        except Exception as e:
            self.success = False
            self.result = f"Error: {str(e)}"
            logger.exception(f"Error running test {self.name}")
        
        self.end_time = time.time()
        self.duration = self.end_time - self.start_time
        
        return self.success
    
    def _run_test(self, *args, **kwargs) -> bool:
        """
        Run the actual test logic.
        
        Returns:
            True if the test was successful, False otherwise
        """
        raise NotImplementedError("Subclasses must implement this method")
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the test to a dictionary.
        
        Returns:
            Dictionary representation of the test
        """
        return {
            "name": self.name,
            "description": self.description,
            "result": self.result,
            "success": self.success,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.duration
        }

class InputValidationTest(UISecurityTest):
    """Test for input validation vulnerabilities."""
    
    def __init__(self, target_function: Callable, input_payloads: List[str]):
        """
        Initialize an input validation test.
        
        Args:
            target_function: Function to test
            input_payloads: List of input payloads to try
        """
        super().__init__(
            name="input_validation_test",
            description="Test for input validation vulnerabilities"
        )
        self.target_function = target_function
        self.input_payloads = input_payloads
        self.vulnerable_payloads = []
    
    def _run_test(self, *args, **kwargs) -> bool:
        """
        Run the input validation test.
        
        Returns:
            True if no vulnerabilities were found, False otherwise
        """
        logger.info(f"Running input validation test with {len(self.input_payloads)} payloads")
        
        for payload in self.input_payloads:
            try:
                result = self.target_function(payload)
                
                # Check if the payload was successful
                # This depends on the specific vulnerability being tested
                if self._check_payload_success(result, payload):
                    self.vulnerable_payloads.append(payload)
                    logger.warning(f"Found vulnerable payload: {payload}")
            except Exception as e:
                # Some exceptions might indicate a successful payload
                if self._check_exception_indicates_vulnerability(e):
                    self.vulnerable_payloads.append(payload)
                    logger.warning(f"Found vulnerable payload (exception): {payload}")
        
        return len(self.vulnerable_payloads) == 0
    
    def _check_payload_success(self, result: Any, payload: str) -> bool:
        """
        Check if a payload was successful.
        
        Args:
            result: Result of the target function
            payload: Input payload
        
        Returns:
            True if the payload was successful, False otherwise
        """
        # This is a simplified check and should be customized for specific vulnerabilities
        
        # Check for common indicators of successful payload
        if isinstance(result, str):
            indicators = [
                "error",
                "exception",
                "invalid",
                "failed"
            ]
            
            for indicator in indicators:
                if indicator in result.lower():
                    return True
        
        return False
    
    def _check_exception_indicates_vulnerability(self, exception: Exception) -> bool:
        """
        Check if an exception indicates a vulnerability.
        
        Args:
            exception: Exception to check
        
        Returns:
            True if the exception indicates a vulnerability, False otherwise
        """
        # This is a simplified check and should be customized for specific vulnerabilities
        
        # Check for common exception types that might indicate a vulnerability
        exception_str = str(exception).lower()
        indicators = [
            "invalid",
            "format",
            "type",
            "value",
            "argument"
        ]
        
        for indicator in indicators:
            if indicator in exception_str:
                return True
        
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the test to a dictionary.
        
        Returns:
            Dictionary representation of the test
        """
        result = super().to_dict()
        result.update({
            "vulnerable_payloads": self.vulnerable_payloads
        })
        return result

class XSSTest(UISecurityTest):
    """Test for cross-site scripting (XSS) vulnerabilities."""
    
    def __init__(self, target_function: Callable, xss_payloads: List[str]):
        """
        Initialize an XSS test.
        
        Args:
            target_function: Function to test
            xss_payloads: List of XSS payloads to try
        """
        super().__init__(
            name="xss_test",
            description="Test for cross-site scripting (XSS) vulnerabilities"
        )
        self.target_function = target_function
        self.xss_payloads = xss_payloads
        self.vulnerable_payloads = []
    
    def _run_test(self, *args, **kwargs) -> bool:
        """
        Run the XSS test.
        
        Returns:
            True if no vulnerabilities were found, False otherwise
        """
        logger.info(f"Running XSS test with {len(self.xss_payloads)} payloads")
        
        for payload in self.xss_payloads:
            try:
                result = self.target_function(payload)
                
                # Check if the payload was successful
                if self._check_xss_success(result, payload):
                    self.vulnerable_payloads.append(payload)
                    logger.warning(f"Found vulnerable XSS payload: {payload}")
            except Exception:
                # Ignore exceptions
                pass
        
        return len(self.vulnerable_payloads) == 0
    
    def _check_xss_success(self, result: Any, payload: str) -> bool:
        """
        Check if an XSS payload was successful.
        
        Args:
            result: Result of the target function
            payload: XSS payload
        
        Returns:
            True if the payload was successful, False otherwise
        """
        # This is a simplified check and should be customized for specific vulnerabilities
        
        # Check if the payload is reflected in the result
        if isinstance(result, str):
            # Check if the payload is included unescaped
            if payload in result:
                return True
            
            # Check for script tags
            if "<script" in payload.lower() and "<script" in result.lower():
                return True
            
            # Check for event handlers
            if "on" in payload.lower() and "=" in payload and "on" in result.lower():
                return True
        
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the test to a dictionary.
        
        Returns:
            Dictionary representation of the test
        """
        result = super().to_dict()
        result.update({
            "vulnerable_payloads": self.vulnerable_payloads
        })
        return result

class UISecurityTester:
    """
    Tester for UI security vulnerabilities.
    
    This class provides methods for:
    - Testing for input validation vulnerabilities
    - Testing for cross-site scripting (XSS) vulnerabilities
    - Generating test reports
    """
    
    def __init__(self):
        """Initialize the UI security tester."""
        self.tests = []
    
    def add_test(self, test: UISecurityTest):
        """
        Add a test to the tester.
        
        Args:
            test: Test to add
        """
        self.tests.append(test)
    
    def run_tests(self) -> Dict[str, Any]:
        """
        Run all tests.
        
        Returns:
            Dictionary with test results
        """
        logger.info(f"Running {len(self.tests)} UI security tests")
        
        for test in self.tests:
            logger.info(f"Running test: {test.name}")
            test.run()
        
        return self.get_results()
    
    def get_results(self) -> Dict[str, Any]:
        """
        Get the results of all tests.
        
        Returns:
            Dictionary with test results
        """
        results = {
            "total_tests": len(self.tests),
            "successful_tests": sum(1 for test in self.tests if test.success),
            "failed_tests": sum(1 for test in self.tests if test.success is False),
            "tests": [test.to_dict() for test in self.tests]
        }
        
        return results
    
    def generate_report(self, output_file: str = None) -> str:
        """
        Generate a report of the test results.
        
        Args:
            output_file: Output file path (if None, returns the report as a string)
        
        Returns:
            Report as a string if output_file is None, otherwise None
        """
        results = self.get_results()
        
        # Generate report content
        content = "# UI Security Testing Report\n\n"
        
        # Summary
        content += "## Summary\n\n"
        content += f"- **Total tests:** {results['total_tests']}\n"
        content += f"- **Successful tests:** {results['successful_tests']}\n"
        content += f"- **Failed tests:** {results['failed_tests']}\n\n"
        
        # Test results
        content += "## Test Results\n\n"
        
        for test in results["tests"]:
            content += f"### {test['name']}\n\n"
            content += f"- **Description:** {test['description']}\n"
            content += f"- **Result:** {test['result']}\n"
            content += f"- **Duration:** {test['duration']:.2f} seconds\n"
            
            # Add test-specific details
            if "vulnerable_payloads" in test and test["vulnerable_payloads"]:
                content += f"- **Vulnerable payloads:** {', '.join(test['vulnerable_payloads'])}\n"
            
            content += "\n"
        
        # Write to file or return as string
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(content)
            
            return None
        else:
            return content
    
    def test_input_validation(self, target_function: Callable, input_payloads: List[str] = None) -> Dict[str, Any]:
        """
        Test for input validation vulnerabilities.
        
        Args:
            target_function: Function to test
            input_payloads: List of input payloads to try (if None, uses default payloads)
        
        Returns:
            Dictionary with test results
        """
        if input_payloads is None:
            # Default input payloads
            input_payloads = [
                "",
                "a" * 1000,
                "0",
                "-1",
                "3.14",
                "true",
                "null",
                "undefined",
                "[]",
                "{}",
                "function(){}",
                "<script>alert(1)</script>",
                "'; DROP TABLE users; --",
                "../../../etc/passwd",
                "%00",
                "%0A",
                "%0D%0A"
            ]
        
        test = InputValidationTest(target_function, input_payloads)
        test.run()
        
        return test.to_dict()
    
    def test_xss(self, target_function: Callable, xss_payloads: List[str] = None) -> Dict[str, Any]:
        """
        Test for cross-site scripting (XSS) vulnerabilities.
        
        Args:
            target_function: Function to test
            xss_payloads: List of XSS payloads to try (if None, uses default payloads)
        
        Returns:
            Dictionary with test results
        """
        if xss_payloads is None:
            # Default XSS payloads
            xss_payloads = [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<iframe src=javascript:alert(1)>",
                "javascript:alert(1)",
                "';alert(1);//",
                "\";alert(1);//",
                "' onclick=alert(1) '",
                "\" onclick=alert(1) \"",
                "<a href=javascript:alert(1)>click me</a>",
                "<a href='javascript:alert(1)'>click me</a>",
                "<a href=\"javascript:alert(1)\">click me</a>"
            ]
        
        test = XSSTest(target_function, xss_payloads)
        test.run()
        
        return test.to_dict()
