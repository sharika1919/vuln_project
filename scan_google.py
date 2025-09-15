#!/usr/bin/env python3
"""
Simple script to test scanning google.com
"""
import logging
from auto_scanner import SecurityScanner

def setup_logging():
    """Setup basic logging"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def main():
    """Main function to test google.com scanning"""
    setup_logging()
    
    target = "https://www.google.com"
    print(f"\n{'='*50}")
    print(f"Testing secure site scanning for: {target}")
    print(f"{'='*50}")
    
    # Initialize scanner
    scanner = SecurityScanner(
        target=target,
        output_dir=f"scan_results/google_scan",
        verbose=True
    )
    
    # Run the scan
    scanner.run_scan()
    
    # Print results
    print("\nScan complete!")
    print(f"Target: {target}")
    print(f"Detected as secure site: {scanner.is_secure_site}")
    print(f"Results saved to: {scanner.output_dir}")

if __name__ == "__main__":
    main()
