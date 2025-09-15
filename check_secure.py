#!/usr/bin/env python3
"""Simple script to check secure site detection"""

from urllib.parse import urlparse

# List of well-known secure domains
SECURE_DOMAINS = [
    # Google services
    'google.com', 'youtube.com', 'gmail.com', 'googleapis.com', 'gstatic.com',
    # Social media
    'facebook.com', 'instagram.com', 'twitter.com', 'linkedin.com', 'pinterest.com',
    # E-commerce
    'amazon.com', 'ebay.com', 'walmart.com', 'alibaba.com', 'etsy.com',
    # Cloud providers
    'aws.amazon.com', 'cloud.google.com', 'microsoft.com', 'digitalocean.com',
    # Major tech
    'apple.com', 'adobe.com', 'oracle.com', 'intel.com',
    # Streaming
    'netflix.com', 'spotify.com', 'disneyplus.com', 'hulu.com', 'twitch.tv'
]

def is_secure_site(url):
    """Check if a URL belongs to a well-known secure site"""
    try:
        # Add scheme if missing
        if not (url.startswith('http://') or url.startswith('https://')):
            url = 'https://' + url
            
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        if not domain:
            domain = url.lower()
        
        # Remove port if present
        domain = domain.split(':')[0]
        
        # Remove www. if present
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Check against secure domains
        for secure_domain in SECURE_DOMAINS:
            if (domain == secure_domain or 
                domain.endswith('.' + secure_domain) or
                secure_domain in domain and any(domain.endswith('.' + tld) for tld in ['.com', '.net', '.org', '.io', '.gov', '.edu'])):
                return True, domain
        
        return False, domain
    except Exception as e:
        return False, str(e)

# Test cases
test_urls = [
    "https://www.google.com",
    "youtube.com",
    "www.facebook.com",
    "example.com",
    "https://www.microsoft.com",
    "subdomain.google.com"
]

print("Secure Site Detection Test\n" + "="*40)
for url in test_urls:
    is_secure, domain = is_secure_site(url)
    print(f"URL: {url}")
    print(f"Domain: {domain}")
    print(f"Is Secure: {'✅' if is_secure else '❌'}\n")
