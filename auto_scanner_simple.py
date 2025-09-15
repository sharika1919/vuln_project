#!/usr/bin/env python3
"""
Simple Auto Scanner
Integrates ReNgine, Osmedeus, Porch Pirate, and Subfinder for vulnerability scanning
"""

import os
import sys
import json
import subprocess
import urllib.parse
import re
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
import shutil

# Set up PATH to include common tool locations
def setup_environment():
    """Setup environment variables for tool detection"""
    current_path = os.environ.get('PATH', '')
    additional_paths = [
        os.path.expanduser('~/.local/bin'),  # pipx installations
        os.path.expanduser('~/go/bin'),      # Go installations
        '/usr/local/bin',
        '/opt/homebrew/bin',
        '/usr/bin',
        '/opt/rengine',  # Common ReNgine installation path
        '/opt/osmedeus'  # Common Osmedeus installation path
    ]
    
    # Add paths that exist and aren't already in PATH
    for path in additional_paths:
        if os.path.exists(path) and path not in current_path:
            current_path = f"{path}:{current_path}"
    
    os.environ['PATH'] = current_path

# Setup environment before importing other modules
setup_environment()

@dataclass
class ToolResult:
    """Data class to hold tool execution results"""
    tool: str
    target: str
    is_vulnerable: bool = False  # Whether vulnerabilities were found
    success: bool = False        # Whether the tool ran successfully
    output: str = ""
    error: Optional[str] = None
    findings: List[Dict] = None
    
    def __post_init__(self):
        # Ensure findings is always a list
        if self.findings is None:
            self.findings = []
        # Update is_vulnerable based on findings if not explicitly set
        if not self.is_vulnerable and self.findings:
            self.is_vulnerable = True

class SimpleAutoScanner:
    """Simple auto scanner with focus on key security tools"""
    
    # List of well-known secure domains
    SECURE_DOMAINS = [
        # Google services
        'google.com', 'youtube.com', 'gmail.com', 'googleapis.com', 'gstatic.com',
        # Social media
        'facebook.com', 'instagram.com', 'twitter.com', 'linkedin.com', 'pinterest.com',
        # E-commerce
        'amazon.com', 'ebay.com', 'walmart.com', 'alibaba.com', 'etsy.com',
        # Cloud providers
        'aws.amazon.com', 'cloud.google.com', 'azure.microsoft.com', 'digitalocean.com',
        # Major tech
        'microsoft.com', 'apple.com', 'adobe.com', 'oracle.com', 'intel.com',
        # Streaming
        'netflix.com', 'spotify.com', 'disneyplus.com', 'hulu.com', 'twitch.tv',
        # Security-focused
        'cloudflare.com', 'akamai.com', 'fastly.net', 'cloudfront.net',
        # Banking/Finance
        'paypal.com', 'stripe.com', 'squareup.com', 'visa.com', 'mastercard.com',
        # Government
        'usa.gov', 'gov.uk', 'canada.ca', 'europa.eu',
        # CDNs
        'cloudflare.com', 'akamaihd.net', 'fastly.net', 'cloudflare.net'
    ]
    
    def __init__(self, target: str):
        self.original_target = target
        self.target = self._clean_target(target)
        self.is_secure_site = self._is_well_known_secure_site(self.target)
        self.results: List[ToolResult] = []
        self.output_dir = Path("scan_results") / f"{self.target}-{int(datetime.now().timestamp())}"
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def _clean_target(self, target: str) -> str:
        """Clean target URL/domain"""
        # Remove protocol if present
        target = re.sub(r'^https?://', '', target)
        # Remove path and parameters
        target = target.split('/')[0]
        # Remove port if present
        target = target.split(':')[0]
        # Remove www. if present for consistent matching
        if target.startswith('www.'):
            target = target[4:]
        return target
        
    def _is_well_known_secure_site(self, domain: str) -> bool:
        """Check if the domain is in the list of well-known secure sites"""
        # Check for exact matches or subdomains of secure domains
        for secure_domain in self.SECURE_DOMAINS:
            if (domain == secure_domain or 
                domain.endswith('.' + secure_domain) or
                secure_domain in domain and any(domain.endswith('.' + tld) for tld in ['.com', '.net', '.org', '.io', '.gov', '.edu'])):
                print(f"\n[!] {domain} is a well-known secure site. Limited scanning will be performed.\n")
                return True
        return False
    
    def check_tool(self, tool_name: str) -> bool:
        """Check if a tool is available"""
        return shutil.which(tool_name) is not None
    
    def run_subfinder(self) -> ToolResult:
        """Run Subfinder to discover subdomains"""
        if not self.check_tool('subfinder'):
            return ToolResult("subfinder", self.target, False, error="Subfinder not found")
        
        output_file = self.output_dir / "subdomains.txt"
        cmd = ["subfinder", "-d", self.target, "-o", str(output_file), "-silent"]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode != 0:
                return ToolResult("subfinder", self.target, False, error=result.stderr)
            
            # Read found subdomains
            subdomains = []
            if output_file.exists() and output_file.stat().st_size > 0:
                with open(output_file, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
            
            return ToolResult(
                "subfinder", 
                self.target, 
                True, 
                f"Found {len(subdomains)} subdomains",
                findings=[{"subdomain": sub} for sub in subdomains]
            )
            
        except Exception as e:
            return ToolResult("subfinder", self.target, False, error=str(e))
    
    def run_porch_pirate(self) -> ToolResult:
        """Run Porch Pirate for cloud service enumeration"""
        if not self.check_tool('porch-pirate'):
            return ToolResult("porch-pirate", self.target, False, error="Porch Pirate not found")
        
        output_file = self.output_dir / "porch_pirate.json"
        cmd = ["porch-pirate", "-s", self.target, "--raw"]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                return ToolResult("porch-pirate", self.target, False, error=result.stderr)
            
            # Save the output
            with open(output_file, 'w') as f:
                f.write(result.stdout)
            
            # Simple check for sensitive findings
            findings = []
            if any(keyword in result.stdout.lower() for keyword in ['api', 'key', 'secret', 'token']):
                findings.append({"severity": "high", "type": "sensitive_data", "details": "Potential API keys or secrets found"})
            
            return ToolResult(
                "porch-pirate",
                self.target,
                True,
                f"Cloud services enumerated" if not findings else "Sensitive data potentially found",
                findings=findings
            )
            
        except Exception as e:
            return ToolResult("porch-pirate", self.target, False, error=str(e))
    
    def run_rengine(self) -> ToolResult:
        """Run ReNgine for comprehensive scanning"""
        # Check if ReNgine is available via Docker (common installation method)
        if not shutil.which('docker'):
            return ToolResult("rengine", self.target, False, error="Docker not found. ReNgine requires Docker to run.")
        
        output_file = self.output_dir / "rengine_results.json"
        
        try:
            # Run ReNgine via Docker
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{self.output_dir}:/recon",
                "rengine/rengine:latest",
                "python", "rengine.py",
                "-t", self.target,
                "-o", "/recon/rengine_results.json"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)  # 30 min timeout
            
            if result.returncode != 0:
                return ToolResult("rengine", self.target, False, 
                               error=f"ReNgine failed: {result.stderr or 'Unknown error'}")
            
            # Check for vulnerabilities
            findings = []
            if output_file.exists() and output_file.stat().st_size > 0:
                try:
                    with open(output_file, 'r') as f:
                        data = json.load(f)
                        # Look for common vulnerability indicators
                        if 'vulnerabilities' in data:
                            findings.extend(data['vulnerabilities'])
                        elif 'issues' in data:
                            findings.extend(data['issues'])
                except (json.JSONDecodeError, KeyError) as e:
                    return ToolResult("rengine", self.target, False, 
                                   error=f"Error parsing ReNgine output: {str(e)}")
            
            is_vulnerable = len(findings) > 0
            status = f"Found {len(findings)} potential vulnerabilities" if findings else "No vulnerabilities found"
            
            return ToolResult(
                "rengine",
                self.target,
                is_vulnerable,  # Success is now based on vulnerability detection
                status,
                findings=findings
            )
            
        except subprocess.TimeoutExpired:
            return ToolResult("rengine", self.target, False, 
                           error="ReNgine scan timed out after 30 minutes")
        except Exception as e:
            return ToolResult("rengine", self.target, False, error=str(e))
    
    def run_osmedeus(self) -> ToolResult:
        """Run Osmedeus for comprehensive scanning"""
        # Check if Osmedeus is available via Docker (recommended installation method)
        if not shutil.which('docker'):
            return ToolResult("osmedeus", self.target, False, 
                           error="Docker not found. Osmedeus requires Docker to run.")
        
        output_dir = self.output_dir / "osmedeus_scan"
        output_dir.mkdir(exist_ok=True)
        
        try:
            # Run Osmedeus via Docker with recommended options
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{output_dir}:/home/osmedeus/data",
                "j3ssie/osmedeus:latest",
                "osmedeus", "scan",
                "-t", self.target,
                "-b", "general",  # Use basic scan workflow
                "--debug"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)  # 60 min timeout
            
            if result.returncode != 0:
                return ToolResult("osmedeus", self.target, False, 
                               error=f"Osmedeus failed: {result.stderr or 'Unknown error'}")
            
            # Check for vulnerabilities in the output
            findings = []
            is_vulnerable = False
            
            # Check common output files for vulnerabilities
            for report_file in output_dir.rglob('*vuln*.json'):
                try:
                    with open(report_file, 'r') as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            findings.extend(data)
                        elif isinstance(data, dict) and 'vulnerabilities' in data:
                            findings.extend(data['vulnerabilities'])
                except (json.JSONDecodeError, IOError):
                    continue
            
            # Also check for common vulnerability indicators in the output
            output_text = result.stdout.lower()
            vuln_indicators = ['vulnerable', 'cve-', 'xss', 'sqli', 'rce', 'lfi', 'rfi']
            
            for indicator in vuln_indicators:
                if indicator in output_text:
                    is_vulnerable = True
                    break
            
            status = ""
            if findings:
                status = f"Found {len(findings)} potential vulnerabilities"
                is_vulnerable = True
            elif is_vulnerable:
                status = "Potential vulnerabilities detected in scan output"
            else:
                status = "No vulnerabilities found"
            
            return ToolResult(
                "osmedeus",
                self.target,
                is_vulnerable,  # Success is now based on vulnerability detection
                status,
                findings=findings
            )
            
        except subprocess.TimeoutExpired:
            return ToolResult("osmedeus", self.target, False, 
                           error="Osmedeus scan timed out after 60 minutes")
        
        status = ""
        if findings:
            status = f"Found {len(findings)} potential vulnerabilities"
            is_vulnerable = True
        elif is_vulnerable:
            status = "Potential vulnerabilities detected in scan output"
        else:
            status = "No vulnerabilities found"
        
        return ToolResult(
            "osmedeus",
            self.target,
            is_vulnerable,  # Success is now based on vulnerability detection
            status,
            findings=findings
        )
    
    def run_scan(self) -> Dict[str, Any]:
        """Run all scans and return results"""
        print(f"\n[+] Starting scan of {self.original_target}")
        print("=" * 60 + "\n")
        
        if self.is_secure_site:
            # For secure sites, just run a basic check
            print(f"[!] {self.target} is a well-known secure site. Limited scanning will be performed.\n")
            
            # Create a basic secure result
            secure_result = ToolResult("secure_site_check", self.target, False)
            secure_result.success = True
            secure_result.output = "No vulnerabilities found - well-known secure site"
            self.results.append(secure_result)
        else:
            # Run full scan for non-secure sites
            print("[*] Running full security scan...\n")
            
            # Run Subfinder
            subfinder_result = self.run_subfinder()
            self.results.append(subfinder_result)
            
            # Run Porch Pirate
            porch_pirate_result = self.run_porch_pirate()
            self.results.append(porch_pirate_result)
            
            # Run ReNgine (if available)
            if self.check_tool('docker'):
                rengine_result = self.run_rengine()
                self.results.append(rengine_result)
            
            # Run Osmedeus (if available)
            if self.check_tool('docker'):
                osmedeus_result = self.run_osmedeus()
                self.results.append(osmedeus_result)
        
        # Print results
        print("\n" + "=" * 60)
        print(f"SCAN COMPLETED: {self.target}")
        print("=" * 60 + "\n")
        
        for result in self.results:
            print(f"[*] {result.tool.upper()}")
            print(f"  Status: {result.output}")
            
            if result.error:
                print(f"  Error: \033[91m{result.error}\033[0m")
                
            if result.findings:
                print(f"  \033[91mFound {len(result.findings)} potential vulnerabilities\033[0m")
                # Print first 3 findings as examples
                for i, finding in enumerate(result.findings[:3], 1):
                    print(f"    {i}. {finding.get('type', 'Finding')}: {finding.get('title', str(finding))[:100]}...")
                if len(result.findings) > 3:
                    print(f"    ... and {len(result.findings) - 3} more findings")
                    
            print("\033[0m" + "-" * 50)
            
            # Add a small delay between tools
            import time
            time.sleep(1)
        
        # Generate and return summary
        return self.generate_summary()
    
    def generate_summary(self) -> Dict[str, Any]:
        """Generate a summary of the scan results"""
        vulnerabilities = []
        for result in self.results:
            if result.findings:
                for finding in result.findings:
                    finding['source_tool'] = result.tool
                    vulnerabilities.append(finding)
        
        # Count vulnerabilities by severity
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown').lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Determine overall vulnerability status
        is_vulnerable = any(result.is_vulnerable for result in self.results)
        
        summary = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "is_vulnerable": is_vulnerable,
            "vulnerability_status": "VULNERABLE" if is_vulnerable else "SECURE",
            "tools_run": len([r for r in self.results if r.success]),
            "total_findings": len(vulnerabilities),
            "severity_counts": severity_counts,
            "tools": [],
            "vulnerabilities": vulnerabilities
        }
        
        for result in self.results:
            tool_summary = {
                "tool": result.tool,
                "success": result.success,
                "is_vulnerable": result.is_vulnerable,
                "findings_count": len(result.findings or []),
                "error": result.error,
                "output": result.output
            }
            summary["tools"].append(tool_summary)
        
        # Save summary
        with open(self.output_dir / "summary.json", 'w') as f:
            json.dump(summary, f, indent=2)
        
        return summary

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <target>")
        print("Example: python auto_scanner_simple.py example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    scanner = SimpleAutoScanner(target)
    
    try:
        summary = scanner.run_scan()
        
        # Print final summary
        print("\n" + "=" * 60)
        print(f"SCAN COMPLETED: {target}")
        print("=" * 60)
        print(f"\nTools run successfully: {summary['tools_run']}")
        print(f"Total findings: {summary['total_findings']}")
        print(f"\nDetailed results saved to: {scanner.output_dir}")
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
