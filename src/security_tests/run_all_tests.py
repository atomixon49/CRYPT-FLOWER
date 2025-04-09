"""
Run All Security Tests
Main script to run all security tests for the cryptographic system.
"""

import os
import sys
import logging
import argparse
import datetime
import subprocess
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("security_tests")

def main():
    """Main function to run all security tests."""
    parser = argparse.ArgumentParser(description="Run all security tests.")
    parser.add_argument("--output-dir", default="security_test_results")
    parser.add_argument("--static", action="store_true", help="Run static analysis")
    parser.add_argument("--penetration", action="store_true", help="Run penetration tests")
    parser.add_argument("--fuzzing", action="store_true", help="Run fuzzing tests")
    parser.add_argument("--gui", action="store_true", help="Run GUI security tests")
    parser.add_argument("--api", action="store_true", help="Run API security tests")
    parser.add_argument("--all", action="store_true", help="Run all tests")
    
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(args.output_dir, f"run_{timestamp}")
    os.makedirs(run_dir, exist_ok=True)
    
    # Get the directory of this script
    script_dir = Path(__file__).parent
    
    # Run tests based on arguments
    if args.all or args.static or args.penetration or args.fuzzing:
        cmd = [sys.executable, str(script_dir / "run_security_tests.py"), "--output-dir", run_dir]
        
        if args.static:
            cmd.append("--static-analysis")
        if args.penetration:
            cmd.append("--penetration-tests")
        if args.fuzzing:
            cmd.append("--fuzzing")
        if args.all:
            cmd.append("--all")
        
        logger.info(f"Running command: {' '.join(cmd)}")
        subprocess.run(cmd)
    
    if args.all or args.gui:
        cmd = [sys.executable, str(script_dir / "run_gui_security_tests.py"), "--output-dir", run_dir]
        
        if args.all:
            cmd.append("--all")
        else:
            cmd.append("--ui-tests")
            cmd.append("--fuzzing")
        
        logger.info(f"Running command: {' '.join(cmd)}")
        subprocess.run(cmd)
    
    if args.all or args.api:
        cmd = [sys.executable, str(script_dir / "run_api_security_tests.py"), "--output-dir", run_dir]
        
        if args.all:
            cmd.append("--all")
        else:
            cmd.append("--penetration")
            cmd.append("--fuzzing")
        
        logger.info(f"Running command: {' '.join(cmd)}")
        subprocess.run(cmd)
    
    # Generate summary report
    generate_summary_report(run_dir)
    
    logger.info(f"All security tests completed. Results saved to {run_dir}")

def generate_summary_report(run_dir):
    """Generate a summary report of all test results."""
    logger.info("Generating summary report...")
    
    # Find all report files
    report_files = []
    for root, _, files in os.walk(run_dir):
        for file in files:
            if file.endswith(".md"):
                report_files.append(os.path.join(root, file))
    
    # Create summary report
    summary_file = os.path.join(run_dir, "summary_report.md")
    with open(summary_file, "w") as f:
        f.write("# Security Testing Summary Report\n\n")
        f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("## Test Reports\n\n")
        for report_file in report_files:
            relative_path = os.path.relpath(report_file, run_dir)
            report_name = os.path.splitext(os.path.basename(report_file))[0]
            f.write(f"- [{report_name}]({relative_path})\n")
        
        f.write("\n## Key Findings\n\n")
        
        # Extract key findings from each report
        for report_file in report_files:
            report_name = os.path.splitext(os.path.basename(report_file))[0]
            f.write(f"### {report_name}\n\n")
            
            with open(report_file, "r") as report:
                content = report.read()
                
                # Extract summary section if it exists
                summary_start = content.find("## Summary")
                if summary_start != -1:
                    summary_end = content.find("##", summary_start + 1)
                    if summary_end != -1:
                        summary = content[summary_start:summary_end].strip()
                    else:
                        summary = content[summary_start:].strip()
                    
                    f.write(f"{summary}\n\n")
                else:
                    f.write("No summary found in this report.\n\n")
        
        f.write("\n## Recommendations\n\n")
        f.write("Based on the security testing results, the following recommendations are made:\n\n")
        f.write("1. Address all critical and high severity vulnerabilities immediately.\n")
        f.write("2. Review and fix medium severity vulnerabilities in the next development cycle.\n")
        f.write("3. Consider implementing additional security controls for areas with multiple findings.\n")
        f.write("4. Enhance input validation across all user interfaces.\n")
        f.write("5. Implement proper error handling to prevent information disclosure.\n")
        f.write("6. Regularly update dependencies to address known vulnerabilities.\n")
        f.write("7. Conduct regular security testing as part of the development lifecycle.\n")
    
    logger.info(f"Summary report generated: {summary_file}")

if __name__ == "__main__":
    main()
