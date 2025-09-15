#!/usr/bin/env python3
"""
Test script to demonstrate secure site scanning
"""

import logging
from pathlib import Path
from auto_scanner import SecurityScanner

def setup_logging():
    """Setup basic logging"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('secure_site_test.log')
        ]
    )

def test_secure_site_scan(site_url):
    """Test scanning a well-known secure site"""
    print(f"\n{'='*50}")
    print(f"Testing secure site: {site_url}")
    print(f"{'='*50}")
    
    # Initialize scanner
    scanner = SecurityScanner(
        site_url,
        output_dir=f"scan_results/{site_url.replace('://', '_').replace('/', '_')}",
        verbose=True
    )
    
    # Run the scan
    scanner.run_scan()
    
    # Print summary
    print("\nScan complete!")
    print(f"Secure site detected: {scanner.is_secure_site}")
    
    # List generated files
    output_dir = Path(f"scan_results/{site_url.replace('://', '_').replace('/', '_')}")
    if output_dir.exists():
        print("\nGenerated files:")
        for f in output_dir.glob('*'):
            print(f"- {f.name}")

if __name__ == "__main__":
    setup_logging()
    
    # Test with Google (should be detected as secure)
    test_secure_site_scan("https://google.com")
    
    # For comparison, test with a non-secure site
    # test_secure_site_scan("http://testphp.vulnweb.com")
