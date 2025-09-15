#!/usr/bin/env python3
"""
Test script to verify secure site detection
"""

from auto_scanner import SecurityScanner

def test_secure_site(url):
    """Test if a URL is detected as a secure site"""
    scanner = SecurityScanner(url, verbose=True)
    is_secure = scanner._is_well_known_secure_site(url)
    print(f"\nTesting: {url}")
    print(f"Is secure site: {is_secure}")
    print(f"Scanner's secure site flag: {scanner.is_secure_site}")
    return is_secure

if __name__ == "__main__":
    # Test with various URLs
    test_urls = [
        "https://www.google.com",
        "https://youtube.com",
        "www.facebook.com",
        "example.com",
        "https://www.microsoft.com"
    ]
    
    for url in test_urls:
        test_secure_site(url)
