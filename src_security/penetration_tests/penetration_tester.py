"""
Penetration Tester Module

This module provides a framework for penetration testing of the cryptographic system.
"""

import os
import time
import logging
import threading
import multiprocessing
from typing import List, Dict, Any, Optional, Callable

from .crypto_attack_simulator import CryptoAttackSimulator
from .ui_security_tester import UISecurityTester

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("penetration_tester")

class PenetrationTest:
    """Base class for penetration tests."""
    
    def __init__(self, name: str, description: str):
        """
        Initialize a penetration test.
        
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
        Run the penetration test.
        
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

class BruteForceTest(PenetrationTest):
    """Test for brute force attacks."""
    
    def __init__(self, target_function: Callable, input_space: List[Any], correct_input: Any):
        """
        Initialize a brute force test.
        
        Args:
            target_function: Function to brute force
            input_space: List of possible inputs
            correct_input: The correct input
        """
        super().__init__(
            name="brute_force_test",
            description="Test for brute force attacks"
        )
        self.target_function = target_function
        self.input_space = input_space
        self.correct_input = correct_input
        self.attempts = 0
        self.found_input = None
    
    def _run_test(self, *args, **kwargs) -> bool:
        """
        Run the brute force test.
        
        Returns:
            True if the correct input was found, False otherwise
        """
        logger.info(f"Running brute force test with {len(self.input_space)} possible inputs")
        
        for input_value in self.input_space:
            self.attempts += 1
            
            try:
                result = self.target_function(input_value)
                
                # Check if this is the correct input
                if result == self.target_function(self.correct_input):
                    self.found_input = input_value
                    logger.info(f"Found correct input after {self.attempts} attempts")
                    return True
            except Exception:
                # Ignore exceptions and continue
                pass
        
        logger.info(f"Failed to find correct input after {self.attempts} attempts")
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the test to a dictionary.
        
        Returns:
            Dictionary representation of the test
        """
        result = super().to_dict()
        result.update({
            "attempts": self.attempts,
            "found_input": self.found_input
        })
        return result

class InjectionTest(PenetrationTest):
    """Test for injection attacks."""
    
    def __init__(self, target_function: Callable, injection_payloads: List[str]):
        """
        Initialize an injection test.
        
        Args:
            target_function: Function to test for injection
            injection_payloads: List of injection payloads to try
        """
        super().__init__(
            name="injection_test",
            description="Test for injection attacks"
        )
        self.target_function = target_function
        self.injection_payloads = injection_payloads
        self.vulnerable_payloads = []
    
    def _run_test(self, *args, **kwargs) -> bool:
        """
        Run the injection test.
        
        Returns:
            True if no vulnerabilities were found, False otherwise
        """
        logger.info(f"Running injection test with {len(self.injection_payloads)} payloads")
        
        for payload in self.injection_payloads:
            try:
                result = self.target_function(payload)
                
                # Check if the payload was successful
                # This depends on the specific vulnerability being tested
                if self._check_injection_success(result, payload):
                    self.vulnerable_payloads.append(payload)
                    logger.warning(f"Found vulnerable payload: {payload}")
            except Exception as e:
                # Some exceptions might indicate a successful injection
                if self._check_exception_indicates_vulnerability(e):
                    self.vulnerable_payloads.append(payload)
                    logger.warning(f"Found vulnerable payload (exception): {payload}")
        
        return len(self.vulnerable_payloads) == 0
    
    def _check_injection_success(self, result: Any, payload: str) -> bool:
        """
        Check if an injection was successful.
        
        Args:
            result: Result of the target function
            payload: Injection payload
        
        Returns:
            True if the injection was successful, False otherwise
        """
        # This is a simplified check and should be customized for specific vulnerabilities
        # For example, for SQL injection, you might check for database error messages
        # For command injection, you might check for command output
        
        # Check for common indicators of successful injection
        if isinstance(result, str):
            indicators = [
                "error",
                "exception",
                "syntax",
                "command",
                "sql",
                "database",
                "file not found"
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
            "sql",
            "database",
            "command",
            "syntax",
            "permission",
            "access",
            "denied"
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

class PenetrationTester:
    """
    Framework for penetration testing of the cryptographic system.
    
    This class provides methods for:
    - Running various penetration tests
    - Coordinating test execution
    - Generating test reports
    """
    
    def __init__(self):
        """Initialize the penetration tester."""
        self.tests = []
        self.crypto_attack_simulator = CryptoAttackSimulator()
        self.ui_security_tester = UISecurityTester()
    
    def add_test(self, test: PenetrationTest):
        """
        Add a test to the tester.
        
        Args:
            test: Test to add
        """
        self.tests.append(test)
    
    def run_tests(self, parallel: bool = False) -> Dict[str, Any]:
        """
        Run all tests.
        
        Args:
            parallel: Whether to run tests in parallel
        
        Returns:
            Dictionary with test results
        """
        logger.info(f"Running {len(self.tests)} penetration tests")
        
        if parallel:
            self._run_tests_parallel()
        else:
            self._run_tests_sequential()
        
        return self.get_results()
    
    def _run_tests_sequential(self):
        """Run tests sequentially."""
        for test in self.tests:
            logger.info(f"Running test: {test.name}")
            test.run()
    
    def _run_tests_parallel(self):
        """Run tests in parallel."""
        threads = []
        
        for test in self.tests:
            thread = threading.Thread(target=test.run)
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
    
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
        content = "# Penetration Testing Report\n\n"
        
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
            if "attempts" in test:
                content += f"- **Attempts:** {test['attempts']}\n"
            
            if "found_input" in test and test["found_input"] is not None:
                content += f"- **Found input:** {test['found_input']}\n"
            
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
    
    def run_crypto_attacks(self) -> Dict[str, Any]:
        """
        Run cryptographic attacks.
        
        Returns:
            Dictionary with attack results
        """
        return self.crypto_attack_simulator.run_attacks()
    
    def run_ui_security_tests(self) -> Dict[str, Any]:
        """
        Run UI security tests.
        
        Returns:
            Dictionary with test results
        """
        return self.ui_security_tester.run_tests()
