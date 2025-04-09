import os
import sys
import json
import time
import subprocess

def run_test(test_script, name):
    """Run a test script and return the results."""
    print(f"\n{'=' * 80}")
    print(f"Running {name} tests...")
    print(f"{'=' * 80}")
    
    # Run the test script
    result = subprocess.run(['python', test_script], capture_output=True, text=True)
    
    # Print the output
    print(result.stdout)
    
    if result.stderr:
        print("Errors:")
        print(result.stderr)
    
    # Check if the test was successful
    success = result.returncode == 0
    
    # Try to load the results file
    results_file = f"{os.path.splitext(test_script)[0]}_results.json"
    results = {}
    
    if os.path.exists(results_file):
        try:
            with open(results_file, 'r') as f:
                results = json.load(f)
        except Exception as e:
            print(f"Error loading results file: {e}")
    
    return {
        'name': name,
        'success': success,
        'return_code': result.returncode,
        'results': results
    }

def main():
    """Run all advanced feature tests."""
    print("Running all advanced feature tests...")
    
    # List of test scripts to run
    test_scripts = [
        ('test_hybrid_crypto_functionality.py', 'Hybrid Cryptography'),
        ('test_multi_recipient_encryption.py', 'Multi-Recipient Encryption'),
        ('test_cosignature.py', 'Co-Signatures'),
        ('test_timestamp.py', 'Timestamps'),
        ('test_cert_revocation.py', 'Certificate Revocation')
    ]
    
    # Run each test script
    results = []
    for script, name in test_scripts:
        result = run_test(script, name)
        results.append(result)
    
    # Generate a summary report
    print("\n\n")
    print("=" * 80)
    print("Advanced Features Test Summary")
    print("=" * 80)
    
    all_success = True
    for result in results:
        status = "✅ Success" if result['success'] else "❌ Failed"
        print(f"{result['name']}: {status}")
        all_success = all_success and result['success']
    
    print("\nDetailed Results:")
    for result in results:
        print(f"\n{result['name']}:")
        
        # Print the results for each category
        for category, tests in result['results'].items():
            print(f"  {category.upper()}:")
            for test_name, test_result in tests.items():
                print(f"    {test_name}: {test_result}")
    
    # Save the summary report
    summary = {
        'timestamp': time.time(),
        'timestamp_str': time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime()),
        'all_success': all_success,
        'results': results
    }
    
    with open('advanced_features_test_summary.json', 'w') as f:
        json.dump(summary, f, indent=2)
    
    print("\nSummary report saved to advanced_features_test_summary.json")
    
    # Update the test_final_results.md file
    update_final_results(results)
    
    return 0 if all_success else 1

def update_final_results(results):
    """Update the test_final_results.md file with the advanced feature test results."""
    try:
        # Read the current file
        with open('test_final_results.md', 'r') as f:
            content = f.read()
        
        # Update the hybrid cryptography section
        hybrid_result = next((r for r in results if r['name'] == 'Hybrid Cryptography'), None)
        if hybrid_result:
            content = update_section(content, 
                                    "### 2. Encryption/Decryption Tests", 
                                    "| Hybrid encryption/decryption | Pending |", 
                                    f"| Hybrid encryption/decryption | {'✅ Success' if hybrid_result['success'] else '❌ Failed'} | {get_result_note(hybrid_result)} |")
        
        # Update the multi-recipient encryption section
        multi_result = next((r for r in results if r['name'] == 'Multi-Recipient Encryption'), None)
        if multi_result:
            content = update_section(content, 
                                    "### 5. Multi-recipient Encryption Tests", 
                                    "| Encrypt for multiple recipients | Pending |", 
                                    f"| Encrypt for multiple recipients | {'✅ Success' if multi_result['success'] else '❌ Failed'} | {get_result_note(multi_result, 'encryption', 'multi_recipient')} |")
            
            content = update_section(content, 
                                    "### 5. Multi-recipient Encryption Tests", 
                                    "| Decrypt as one of multiple recipients | Pending |", 
                                    f"| Decrypt as one of multiple recipients | {'✅ Success' if multi_result['success'] else '❌ Failed'} | {get_result_note(multi_result, 'decryption', 'recipient1')} |")
        
        # Update the co-signature section
        cosign_result = next((r for r in results if r['name'] == 'Co-Signatures'), None)
        if cosign_result:
            content = update_section(content, 
                                    "### 6. Co-signature Tests", 
                                    "| Create co-signatures | Pending |", 
                                    f"| Create co-signatures | {'✅ Success' if cosign_result['success'] else '❌ Failed'} | {get_result_note(cosign_result, 'signature_chain', 'creation')} |")
            
            content = update_section(content, 
                                    "### 6. Co-signature Tests", 
                                    "| Verify co-signatures | Pending |", 
                                    f"| Verify co-signatures | {'✅ Success' if cosign_result['success'] else '❌ Failed'} | {get_result_note(cosign_result, 'verification', 'final')} |")
        
        # Update the timestamp section
        timestamp_result = next((r for r in results if r['name'] == 'Timestamps'), None)
        if timestamp_result:
            content = update_section(content, 
                                    "### 7. Timestamp Tests", 
                                    "| Create timestamps | Pending |", 
                                    f"| Create timestamps | {'✅ Success' if timestamp_result['success'] else '❌ Failed'} | {get_result_note(timestamp_result, 'timestamp_data', 'local')} |")
            
            content = update_section(content, 
                                    "### 7. Timestamp Tests", 
                                    "| Verify timestamps | Pending |", 
                                    f"| Verify timestamps | {'✅ Success' if timestamp_result['success'] else '❌ Failed'} | {get_result_note(timestamp_result, 'verification', 'local')} |")
        
        # Update the certificate revocation section
        revocation_result = next((r for r in results if r['name'] == 'Certificate Revocation'), None)
        if revocation_result:
            content = update_section(content, 
                                    "### 8. Certificate Revocation Tests", 
                                    "| CRL verification | Pending |", 
                                    f"| CRL verification | {'✅ Success' if revocation_result['success'] else '❌ Failed'} | {get_result_note(revocation_result, 'crl_checking', 'valid_cert')} |")
            
            content = update_section(content, 
                                    "### 8. Certificate Revocation Tests", 
                                    "| OCSP verification | Pending |", 
                                    f"| OCSP verification | {'✅ Success' if revocation_result['success'] else '❌ Failed'} | {get_result_note(revocation_result, 'ocsp_checking', 'valid_cert')} |")
        
        # Update the summary
        passed_count = sum(1 for r in results if r['success'])
        failed_count = len(results) - passed_count
        
        # Count the existing passed tests
        import re
        existing_passed = len(re.findall(r'✅ Success', content)) - passed_count
        existing_failed = len(re.findall(r'❌ Failed', content)) - failed_count
        existing_not_available = len(re.findall(r'⚠️ Not Available', content))
        
        # Count the remaining pending tests
        total_tests = 29  # Total number of tests in the file
        pending_count = total_tests - (existing_passed + passed_count + existing_failed + failed_count + existing_not_available)
        
        # Update the summary line
        summary_pattern = r"Total tests: \d+ passed, \d+ failed, \d+ not available, \d+ pending"
        new_summary = f"Total tests: {existing_passed + passed_count} passed, {existing_failed + failed_count} failed, {existing_not_available} not available, {pending_count} pending"
        content = re.sub(summary_pattern, new_summary, content)
        
        # Write the updated file
        with open('test_final_results.md', 'w') as f:
            f.write(content)
        
        print("\nUpdated test_final_results.md with advanced feature test results")
    
    except Exception as e:
        print(f"Error updating test_final_results.md: {e}")

def update_section(content, section_header, old_line_pattern, new_line):
    """Update a specific line in a section of the markdown file."""
    import re
    
    # Find the section
    section_start = content.find(section_header)
    if section_start == -1:
        return content
    
    # Find the next section or the end of the file
    next_section_match = re.search(r"^###", content[section_start + len(section_header):], re.MULTILINE)
    if next_section_match:
        section_end = section_start + len(section_header) + next_section_match.start()
    else:
        section_end = len(content)
    
    # Extract the section
    section = content[section_start:section_end]
    
    # Replace the line
    updated_section = section.replace(old_line_pattern, new_line)
    
    # Replace the section in the content
    return content[:section_start] + updated_section + content[section_end:]

def get_result_note(result, category=None, test_name=None):
    """Get a note about the test result."""
    if not result['success']:
        return "Test failed to run"
    
    if category and test_name and category in result['results'] and test_name in result['results'][category]:
        test_result = result['results'][category][test_name]
        if test_result.startswith("Success"):
            return "Test completed successfully"
        elif test_result.startswith("Failed"):
            return test_result
    
    return "Test completed"

if __name__ == "__main__":
    sys.exit(main())
