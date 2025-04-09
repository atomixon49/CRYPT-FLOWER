"""
Run Security Tests Script

This script runs all security tests on the cryptographic system.
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

from src.security_tests.static_analysis import StaticAnalyzer
from src.security_tests.penetration_tests import PenetrationTester
from src.security_tests.fuzzing import FuzzingEngine

from src.core.key_management import KeyManager
from src.core.encryption import EncryptionEngine
from src.core.signatures import SignatureEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("security_tests.log")
    ]
)
logger = logging.getLogger("security_tests")

def run_static_analysis(project_root: str, output_dir: str) -> None:
    """
    Run static analysis on the project.
    
    Args:
        project_root: Root directory of the project
        output_dir: Directory to save the results
    """
    logger.info("Running static analysis...")
    
    # Create the static analyzer
    analyzer = StaticAnalyzer(project_root)
    
    # Run the analysis
    report = analyzer.run_analysis()
    
    # Generate the report
    output_file = os.path.join(output_dir, "static_analysis_report.md")
    analyzer.generate_report(report, output_file)
    
    # Save the report as JSON
    json_file = os.path.join(output_dir, "static_analysis_report.json")
    report.save(json_file)
    
    logger.info(f"Static analysis completed. Found {len(report.vulnerabilities)} vulnerabilities.")
    logger.info(f"Report saved to {output_file}")

def run_penetration_tests(output_dir: str) -> None:
    """
    Run penetration tests on the project.
    
    Args:
        output_dir: Directory to save the results
    """
    logger.info("Running penetration tests...")
    
    # Create the penetration tester
    tester = PenetrationTester()
    
    # Initialize core components
    key_manager = KeyManager()
    encryption_engine = EncryptionEngine()
    signature_engine = SignatureEngine()
    
    # Add tests
    
    # Brute force test for password-based encryption
    def encrypt_with_password(password: str) -> bytes:
        data = b"Test data"
        return encryption_engine.encrypt_with_password(data, password)
    
    from src.security_tests.penetration_tests.penetration_tester import BruteForceTest
    
    # Generate a list of common passwords
    common_passwords = [
        "password",
        "123456",
        "qwerty",
        "admin",
        "welcome",
        "password123",
        "abc123",
        "letmein",
        "monkey",
        "1234567890"
    ]
    
    # Add the brute force test
    tester.add_test(BruteForceTest(
        encrypt_with_password,
        common_passwords,
        "password123"
    ))
    
    # Injection test for file paths
    def open_file(file_path: str) -> str:
        try:
            with open(file_path, "r") as f:
                return f.read()
        except Exception as e:
            return str(e)
    
    from src.security_tests.penetration_tests.penetration_tester import InjectionTest
    
    # Generate a list of path injection payloads
    path_injection_payloads = [
        "../../../etc/passwd",
        "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
        "/dev/null",
        "C:\\Windows\\System32\\cmd.exe",
        "file:///etc/passwd",
        "https://example.com",
        "data:text/plain,Hello%20World"
    ]
    
    # Add the injection test
    tester.add_test(InjectionTest(
        open_file,
        path_injection_payloads
    ))
    
    # Run the tests
    tester.run_tests()
    
    # Generate the report
    output_file = os.path.join(output_dir, "penetration_test_report.md")
    tester.generate_report(output_file)
    
    logger.info("Penetration tests completed.")
    logger.info(f"Report saved to {output_file}")
    
    # Run cryptographic attacks
    logger.info("Running cryptographic attacks...")
    
    # Create a simple encryption function for testing
    def simple_encrypt(data: bytes, key: bytes) -> bytes:
        # XOR encryption (insecure, for testing only)
        result = bytearray(data)
        for i in range(len(result)):
            result[i] ^= key[i % len(key)]
        return bytes(result)
    
    # Create a simple decryption function for testing
    def simple_decrypt(data: bytes, key: bytes) -> bytes:
        # XOR decryption (insecure, for testing only)
        return simple_encrypt(data, key)  # XOR is its own inverse
    
    # Generate a random key
    test_key = os.urandom(16)
    
    # Generate test data
    test_data = b"This is a test message for cryptographic attacks."
    
    # Encrypt the test data
    test_ciphertext = simple_encrypt(test_data, test_key)
    
    # Run known plaintext attack
    crypto_attack_simulator = tester.crypto_attack_simulator
    
    # Generate a list of possible keys (including the correct one)
    possible_keys = [os.urandom(16) for _ in range(9)]
    possible_keys.append(test_key)
    
    known_plaintext_result = crypto_attack_simulator.simulate_known_plaintext_attack(
        simple_encrypt,
        simple_decrypt,
        test_data,
        test_ciphertext,
        possible_keys
    )
    
    # Run timing attack
    def password_check(password: str) -> bool:
        correct = "correct_password"
        if len(password) != len(correct):
            return False
        
        # Vulnerable implementation with timing side channel
        for i in range(len(password)):
            if password[i] != correct[i]:
                return False
            time.sleep(0.01)  # Artificial delay to simulate timing side channel
        
        return True
    
    def generate_password() -> str:
        return "".join(random.choice(string.ascii_letters) for _ in range(15))
    
    timing_attack_result = crypto_attack_simulator.simulate_timing_attack(
        password_check,
        generate_password,
        100
    )
    
    # Generate the crypto attack report
    crypto_output_file = os.path.join(output_dir, "crypto_attack_report.md")
    crypto_attack_simulator.generate_report(crypto_output_file)
    
    logger.info("Cryptographic attacks completed.")
    logger.info(f"Report saved to {crypto_output_file}")
    
    # Run UI security tests
    logger.info("Running UI security tests...")
    
    ui_security_tester = tester.ui_security_tester
    
    # Test input validation
    def validate_email(email: str) -> str:
        if "@" not in email:
            return "Invalid email address"
        return "Valid email address"
    
    input_validation_result = ui_security_tester.test_input_validation(validate_email)
    
    # Test XSS
    def process_html(html: str) -> str:
        # Vulnerable implementation that doesn't sanitize HTML
        return f"<div>{html}</div>"
    
    xss_result = ui_security_tester.test_xss(process_html)
    
    # Generate the UI security test report
    ui_output_file = os.path.join(output_dir, "ui_security_test_report.md")
    ui_security_tester.generate_report(ui_output_file)
    
    logger.info("UI security tests completed.")
    logger.info(f"Report saved to {ui_output_file}")

def run_fuzzing(output_dir: str) -> None:
    """
    Run fuzzing on the project.
    
    Args:
        output_dir: Directory to save the results
    """
    logger.info("Running fuzzing...")
    
    # Create the fuzzing engine
    engine = FuzzingEngine()
    
    # Initialize core components
    key_manager = KeyManager()
    encryption_engine = EncryptionEngine()
    signature_engine = SignatureEngine()
    
    # Add fuzzing targets
    
    # Encryption function
    def encrypt_wrapper(data, key, algorithm="AES-GCM"):
        try:
            return encryption_engine.encrypt(data, key, algorithm)
        except Exception as e:
            return str(e)
    
    engine.add_function(
        name="encryption",
        function=encrypt_wrapper,
        input_types=["bytes", "key", "str"],
        iterations=500
    )
    
    # Decryption function
    def decrypt_wrapper(encryption_result, key):
        try:
            return encryption_engine.decrypt(encryption_result, key)
        except Exception as e:
            return str(e)
    
    engine.add_function(
        name="decryption",
        function=decrypt_wrapper,
        input_types=["dict", "key"],
        iterations=500
    )
    
    # Signature function
    def sign_wrapper(data, private_key, algorithm="RSA-PSS"):
        try:
            return signature_engine.sign(data, private_key, algorithm)
        except Exception as e:
            return str(e)
    
    # Generate a key pair for testing
    public_key, private_key = signature_engine.generate_key_pair("RSA-PSS", 2048)
    
    engine.add_function(
        name="signature",
        function=sign_wrapper,
        input_types=["bytes", "key", "str"],
        iterations=500
    )
    
    # Verification function
    def verify_wrapper(data, signature_result, public_key):
        try:
            return signature_engine.verify(data, signature_result, public_key)
        except Exception as e:
            return str(e)
    
    engine.add_function(
        name="verification",
        function=verify_wrapper,
        input_types=["bytes", "dict", "key"],
        iterations=500
    )
    
    # Run fuzzing
    engine.run()
    
    # Generate the report
    output_file = os.path.join(output_dir, "fuzzing_report.md")
    engine.generate_report(output_file)
    
    logger.info("Fuzzing completed.")
    logger.info(f"Report saved to {output_file}")

def main():
    """Main function."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Run security tests on the cryptographic system.")
    parser.add_argument("--project-root", default=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                        help="Root directory of the project")
    parser.add_argument("--output-dir", default="security_test_results",
                        help="Directory to save the results")
    parser.add_argument("--static-analysis", action="store_true",
                        help="Run static analysis")
    parser.add_argument("--penetration-tests", action="store_true",
                        help="Run penetration tests")
    parser.add_argument("--fuzzing", action="store_true",
                        help="Run fuzzing")
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
    if args.all or args.static_analysis:
        run_static_analysis(args.project_root, run_dir)
    
    if args.all or args.penetration_tests:
        run_penetration_tests(run_dir)
    
    if args.all or args.fuzzing:
        run_fuzzing(run_dir)
    
    logger.info(f"All security tests completed. Results saved to {run_dir}")

if __name__ == "__main__":
    import random
    import string
    main()
