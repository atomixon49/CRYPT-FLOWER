"""
API Security Tests Script
Tests security vulnerabilities in the API components.
"""

import os
import sys
import logging
import argparse
import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.security_tests.penetration_tests import PenetrationTester
from src.security_tests.fuzzing import FuzzingEngine

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("api_security_tests")

def run_api_penetration_tests(output_dir):
    """Run API penetration tests."""
    logger.info("Running API penetration tests...")
    
    tester = PenetrationTester()
    
    # Test API authentication
    def authenticate(username, password):
        if username == "admin" and password == "secure_password":
            return {"status": "success", "token": "dummy_token"}
        return {"status": "error", "message": "Invalid credentials"}
    
    # Test API input validation
    def validate_input(data):
        if not isinstance(data, dict):
            return {"status": "error", "message": "Data must be a dictionary"}
        if "action" not in data:
            return {"status": "error", "message": "Action is required"}
        return {"status": "success"}
    
    # Add injection test for API
    from src.security_tests.penetration_tests.penetration_tester import InjectionTest
    
    # API injection payloads
    api_injection_payloads = [
        '{"action": "'; DROP TABLE users; --"}',
        '{"action": "<script>alert(1)</script>"}',
        '{"action": "../../etc/passwd"}',
        '{"action": null}',
        '{"action": [1, 2, 3]}',
        '{"action": {"nested": "value"}}',
        '{"action": true}'
    ]
    
    # Add the test
    tester.add_test(InjectionTest(validate_input, api_injection_payloads))
    
    # Run the tests
    tester.run_tests()
    
    # Generate report
    output_file = os.path.join(output_dir, "api_penetration_test_report.md")
    tester.generate_report(output_file)
    
    logger.info(f"API penetration tests completed. Report saved to {output_file}")

def run_api_fuzzing(output_dir):
    """Run API fuzzing tests."""
    logger.info("Running API fuzzing...")
    
    engine = FuzzingEngine()
    
    # API endpoint handlers
    def handle_encrypt_request(request):
        try:
            if not isinstance(request, dict):
                return {"status": "error", "message": "Invalid request format"}
            
            required_fields = ["data", "key_id", "algorithm"]
            for field in required_fields:
                if field not in request:
                    return {"status": "error", "message": f"Missing required field: {field}"}
            
            return {"status": "success", "result": "encrypted_data_placeholder"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def handle_decrypt_request(request):
        try:
            if not isinstance(request, dict):
                return {"status": "error", "message": "Invalid request format"}
            
            required_fields = ["encrypted_data", "key_id"]
            for field in required_fields:
                if field not in request:
                    return {"status": "error", "message": f"Missing required field: {field}"}
            
            return {"status": "success", "result": "decrypted_data_placeholder"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    # Add fuzzing targets
    engine.add_function(
        name="encrypt_api",
        function=handle_encrypt_request,
        input_types=["dict"],
        iterations=300
    )
    
    engine.add_function(
        name="decrypt_api",
        function=handle_decrypt_request,
        input_types=["dict"],
        iterations=300
    )
    
    # Run fuzzing
    engine.run()
    
    # Generate report
    output_file = os.path.join(output_dir, "api_fuzzing_report.md")
    engine.generate_report(output_file)
    
    logger.info(f"API fuzzing completed. Report saved to {output_file}")

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Run API security tests.")
    parser.add_argument("--output-dir", default="api_security_test_results")
    parser.add_argument("--penetration", action="store_true")
    parser.add_argument("--fuzzing", action="store_true")
    parser.add_argument("--all", action="store_true")
    
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(args.output_dir, f"run_{timestamp}")
    os.makedirs(run_dir, exist_ok=True)
    
    # Run tests
    if args.all or args.penetration:
        run_api_penetration_tests(run_dir)
    
    if args.all or args.fuzzing:
        run_api_fuzzing(run_dir)
    
    logger.info(f"All API security tests completed. Results saved to {run_dir}")

if __name__ == "__main__":
    main()
