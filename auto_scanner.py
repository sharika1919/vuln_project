#!/usr/bin/env python3
"""
AI-Powered Reconnaissance Tool - Professional Implementation
Integrates Subfinder, Amass, HTTPX, and other tools for comprehensive reconnaissance
"""

import os
import subprocess
import json
import logging
import argparse
import sys
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict, Any
import shutil
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from ai_engine import AISecurityEngine, SmartTemplateSelection

# Set up PATH to include common tool locations
def setup_environment():
    """Setup environment variables for tool detection"""
    current_path = os.environ.get('PATH', '')
    additional_paths = [
        os.path.expanduser('~/.local/bin'),  # pipx installations
        os.path.expanduser('~/go/bin'),      # Go installations
        '/usr/local/bin',
        '/opt/homebrew/bin',
        '/usr/bin'
    ]
    
    # Add paths that exist and aren't already in PATH
    for path in additional_paths:
        if os.path.exists(path) and path not in current_path:
            current_path = f"{path}:{current_path}"
    
    os.environ['PATH'] = current_path

# Setup environment before importing other modules
setup_environment()


@dataclass
class ScanResult:
    """Data class to hold scan results"""
    tool: str
    target: str
    success: bool
    output_file: Optional[str] = None
    error: Optional[str] = None
    findings_count: int = 0


class ToolManager:
    """Manages security tool detection and execution"""
    
    def __init__(self, logger: logging.Logger = None):
        self.logger = logger
        self.tools = {
            'subfinder': self._check_subfinder,
            'amass': self._check_amass,
            'httpx': self._check_httpx,
            'waybackurls': self._check_waybackurls,
            'gau': self._check_gau,
            'jq': self._check_jq,
            'rengine': self._check_rengine,
            'osmedeus': self._check_osmedeus,
            'porch-pirate': self._check_porch_pirate
        }
        self.tool_paths = {}
        self._detect_tools()
    
    def _detect_tools(self):
        """Detect available security tools"""
        for tool, checker in self.tools.items():
            self.tool_paths[tool] = checker()
    
    def _check_subfinder(self) -> Optional[str]:
        """Check if subfinder is available"""
        return shutil.which('subfinder')
    
    def _check_amass(self) -> Optional[str]:
        """Check if amass is available"""
        return shutil.which('amass')
    
    def _check_httpx(self) -> Optional[str]:
        """Check if httpx is available"""
        return shutil.which('httpx')
    
    def _check_waybackurls(self) -> Optional[str]:
        """Check if waybackurls is available"""
        return shutil.which('waybackurls')
    
    def _check_gau(self) -> Optional[str]:
        """Check if gau is available"""
        return shutil.which('gau')
        
        # Check if docker is available and running
        docker_path = shutil.which('docker')
        if docker_path:
            try:
                # Check if docker daemon is running
                result = subprocess.run(['docker', 'info'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    # Check if rengine image exists or can be pulled
                    result = subprocess.run(['docker', 'images', 'yogeshojha/rengine'], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0 and 'yogeshojha/rengine' in result.stdout:
                        return 'docker'
                    else:
                        # Try to pull the image
                        self.logger.info("Pulling ReNgine Docker image...")
                        pull_result = subprocess.run(['docker', 'pull', 'yogeshojha/rengine'], 
                                                   capture_output=True, text=True, timeout=300)
                        if pull_result.returncode == 0:
                            return 'docker'
            except Exception as e:
                if self.logger:
                    self.logger.debug(f"Docker check failed: {e}")
        
        # Alternative: Use ReNgine API or standalone installation
        return self._check_rengine_alternative()
    
    def _check_rengine_alternative(self) -> Optional[str]:
        """Check for alternative ReNgine installations"""
        # Check for ReNgine standalone binary
        rengine_paths = [
            '/usr/local/bin/rengine',
            '/opt/rengine/rengine',
            os.path.expanduser('~/rengine/rengine'),
            os.path.expanduser('~/.local/bin/rengine')
        ]
        
        for path in rengine_paths:
            if os.path.exists(path) and os.access(path, os.X_OK):
                return path
        
        # Check if we can use ReNgine via API (if running locally)
        try:
            import requests
            response = requests.get('http://localhost:8000/api/health', timeout=2)
            if response.status_code == 200:
                return 'api'
        except:
            pass
        
        # Use built-in reconnaissance as fallback
        return 'builtin'
    
    def _check_jq(self) -> Optional[str]:
        """Check if jq is available"""
        return shutil.which('jq')
        
    def _check_rengine(self) -> Optional[str]:
        """Check if rengine is available"""
        # First check if rengine CLI is available
        rengine_path = shutil.which('rengine')
        if rengine_path:
            return rengine_path
            
        # Check if docker is available and rengine container is running
        docker_path = shutil.which('docker')
        if docker_path:
            try:
                result = subprocess.run(
                    ['docker', 'ps', '--format', '{{.Names}}'],
                    capture_output=True,
                    text=True
                )
                if 'rengine' in result.stdout:
                    return 'docker-compose -f /path/to/rengine/docker-compose.yml exec rengine rengine'
            except Exception:
                pass
        return None
        
    def _check_osmedeus(self) -> Optional[str]:
        """Check if osmedeus is available"""
        # Check if osmedeus binary is in PATH
        osmedeus_path = shutil.which('osmedeus')
        if osmedeus_path:
            return osmedeus_path
            
        # Check for docker installation
        docker_path = shutil.which('docker')
        if docker_path:
            try:
                result = subprocess.run(
                    ['docker', 'ps', '--format', '{{.Names}}'],
                    capture_output=True,
                    text=True
                )
                if 'osmedeus' in result.stdout:
                    return 'docker exec -it osmedeus ./osmedeus.py'
            except Exception:
                pass
        return None
        
    def _check_porch_pirate(self) -> Optional[str]:
        """Check if porch-pirate is available"""
        return shutil.which('porch-pirate')
    
    def is_available(self, tool: str) -> bool:
        """Check if a tool is available"""
        return self.tool_paths.get(tool) is not None
    
    def get_missing_tools(self) -> List[str]:
        """Get list of missing tools"""
        return [tool for tool, path in self.tool_paths.items() if path is None]


class SecurityScanner:
    """Main security scanner class with AI integration"""
    
    # List of well-known secure domains (top 1000 alexa + major services)
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
    
    def __init__(self, target: str, output_dir: Optional[Path] = None, fast_mode: bool = False, verbose: bool = False):
        self.target = self._clean_target(target)
        self.fast_mode = fast_mode
        self.verbose = verbose
        self.demo_mode = False
        
        # Setup output directory
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            self.output_dir = Path("scan_results") / f"{self.target}-{timestamp}"
        
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup logging
        self.logger = self._setup_logging()
        self.logger.info(f"Initialized scanner for target: {self.target}")
        
        # Initialize tool manager and AI engine
        self.tool_manager = ToolManager(self.logger)
        self.ai_engine = AISecurityEngine(self.logger)
        self.results: List[ScanResult] = []
        
        # Check if target is a well-known secure site
        self.is_secure_site = self._is_well_known_secure_site(self.target)
    
    def _clean_target(self, target: str) -> str:
        """Clean target URL/domain for safe file naming"""
        # Store original target with path for scanning
        self.original_target = target
        
        # Remove protocol for domain extraction
        domain_only = re.sub(r'https?://', '', target)
        # Remove path and port for file naming
        domain_only = re.sub(r'/.*', '', domain_only)
        domain_only = re.sub(r':.*', '', domain_only)
        return domain_only
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('AutoScanner')
        logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_format = logging.Formatter('%(levelname)s: %(message)s')
        console_handler.setFormatter(console_format)
        
        # File handler
        log_file = self.output_dir / 'scan.log'
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_format)
        
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)
        
        return logger
    
    def _is_well_known_secure_site(self, url: str) -> bool:
        """
        Check if the URL belongs to a well-known secure site.
        Returns:
            bool: True if the site is a well-known secure site, False otherwise
        """
        try:
            # Handle case where URL might already be a domain without scheme
            if not (url.startswith('http://') or url.startswith('https://')):
                url = 'https://' + url
                
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            if not domain:  # If parsing failed, use the original URL
                domain = url.lower()
            
            # Remove port if present
            domain = domain.split(':')[0]
            
            # Remove www. if present for better matching
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Check for exact matches or subdomains of secure domains
            for secure_domain in self.SECURE_DOMAINS:
                if (domain == secure_domain or 
                    domain.endswith('.' + secure_domain) or
                    secure_domain in domain and any(domain.endswith('.' + tld) for tld in ['.com', '.net', '.org', '.io', '.gov', '.edu'])):
                    self.logger.info(f"Identified as well-known secure site: {domain}")
                    return True
            
            return False
            
        except Exception as e:
            self.logger.warning(f"Error checking secure site status for {url}: {str(e)}")
            return False
    
    def run_porch_pirate(self) -> ScanResult:
        """Run porch-pirate reconnaissance"""
        self.logger.info(f"[1/5] Starting Porch-pirate reconnaissance on {self.target}...")
        
        if not self.tool_manager.is_available('porch-pirate'):
            error_msg = "Porch-pirate not found. Install with: pipx install porch-pirate"
            self.logger.warning(error_msg)
            return ScanResult('porch-pirate', self.target, False, error=error_msg)
        
        try:
            output_file = self.output_dir / 'porch_pirate.json'
            cmd = [self.tool_manager.tool_paths['porch-pirate'], '-s', self.target, '--raw']
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0 and result.stdout.strip():
                with open(output_file, 'w') as f:
                    f.write(result.stdout)
            else:
                # Create empty JSON if no results
                with open(output_file, 'w') as f:
                    json.dump({}, f)
            
            self.logger.info("Porch-pirate scan completed")
            return ScanResult('porch-pirate', self.target, True, str(output_file))
            
        except subprocess.TimeoutExpired:
            error_msg = "Porch-pirate scan timed out"
            self.logger.error(error_msg)
            return ScanResult('porch-pirate', self.target, False, error=error_msg)
        except Exception as e:
            error_msg = f"Porch-pirate scan failed: {str(e)}"
            self.logger.error(error_msg)
            return ScanResult('porch-pirate', self.target, False, error=error_msg)
    
    def run_subfinder(self) -> Tuple[ScanResult, List[str]]:
        """Run subfinder subdomain discovery"""
        self.logger.info(f"[2/5] Starting Subfinder subdomain discovery on {self.target}...")
        
        if not self.tool_manager.is_available('subfinder'):
            error_msg = "Subfinder not found. Install with: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
            self.logger.warning(error_msg)
            return ScanResult('subfinder', self.target, False, error=error_msg), [self.target]
        
        try:
            output_file = self.output_dir / 'subdomains.txt'
            cmd = [self.tool_manager.tool_paths['subfinder'], '-d', self.target, '-o', str(output_file), '-silent']
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            subdomains = [self.target]  # Default to main domain
            
            if output_file.exists() and output_file.stat().st_size > 0:
                with open(output_file, 'r') as f:
                    found_subdomains = [line.strip() for line in f if line.strip()]
                    if found_subdomains:
                        subdomains = found_subdomains[:20]  # Limit to 20 subdomains
                        self.logger.info(f"Found subdomains: {len(found_subdomains)} domains")
                    else:
                        self.logger.info("No subdomains found, scanning target domain only")
            else:
                self.logger.info("No subdomains found, scanning target domain only")
            
            self.logger.info("Subfinder scan completed")
            return ScanResult('subfinder', self.target, True, str(output_file), findings_count=len(subdomains)), subdomains
            
        except subprocess.TimeoutExpired:
            error_msg = "Subfinder scan timed out"
            self.logger.error(error_msg)
            return ScanResult('subfinder', self.target, False, error=error_msg), [self.target]
        except Exception as e:
            error_msg = f"Subfinder scan failed: {str(e)}"
            self.logger.error(error_msg)
            return ScanResult('subfinder', self.target, False, error=error_msg), [self.target]
    
    def run_rengine(self) -> Tuple[ScanResult, List[str]]:
        """Run ReNgine for comprehensive reconnaissance"""
        if not self.tool_manager.tool_paths.get('rengine'):
            return ScanResult(
                tool='rengine',
                target=self.target,
                success=False,
                error="ReNgine not found. Install from: https://github.com/yogeshojha/rengine"
            ), [self.target]
        
        output_dir = self.output_dir / 'rengine'
        output_dir.mkdir(exist_ok=True)
        output_file = output_dir / 'scan_results.json'
        
        cmd = [
            self.tool_manager.tool_paths['rengine'],
            '--target', self.target,
            '--output', str(output_file),
            '--threads', '10',
            '--timeout', '1800'  # 30 minutes
        ]
        
        try:
            self.logger.info(f"Running ReNgine on {self.target}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=2700  # 45 minutes
            )
            
            if result.returncode != 0:
                return ScanResult(
                    tool='rengine',
                    target=self.target,
                    success=False,
                    error=result.stderr or "ReNgine scan failed"
                ), [self.target]
            
            # Parse results and extract subdomains
            subdomains = set([self.target])
            if output_file.exists():
                with open(output_file, 'r') as f:
                    try:
                        data = json.load(f)
                        if 'subdomains' in data:
                            subdomains.update(data['subdomains'])
                    except json.JSONDecodeError:
                        self.logger.warning("Failed to parse ReNgine JSON output")
            
            return ScanResult(
                tool='rengine',
                target=self.target,
                success=True,
                output_file=str(output_file),
                findings_count=len(subdomains)
            ), list(subdomains)
            
        except subprocess.TimeoutExpired:
            return ScanResult(
                tool='rengine',
                target=self.target,
                success=False,
                error="ReNgine scan timed out after 45 minutes"
            ), [self.target]
        except Exception as e:
            return ScanResult(
                tool='rengine',
                target=self.target,
                success=False,
                error=str(e)
            ), [self.target]
    
    def run_osmedeus(self) -> ScanResult:
        """Run Osmedeus for comprehensive scanning"""
        if not self.tool_manager.tool_paths.get('osmedeus'):
            return ScanResult(
                tool='osmedeus',
                target=self.target,
                success=False,
                error="Osmedeus not found. Install from: https://github.com/j3ssie/osmedeus"
            )
        
        output_dir = self.output_dir / 'osmedeus'
        output_dir.mkdir(exist_ok=True)
        
        cmd = [
            self.tool_manager.tool_paths['osmedeus'],
            '-t', self.target,
            '-o', str(output_dir),
            '-m', 'recon,scan,vuln',
            '-timeout', '3600'  # 1 hour
        ]
        
        try:
            self.logger.info(f"Running Osmedeus on {self.target}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=7200  # 2 hours
            )
            
            if result.returncode != 0:
                return ScanResult(
                    tool='osmedeus',
                    target=self.target,
                    success=False,
                    error=result.stderr or "Osmedeus scan failed"
                )
            
            # Count findings
            findings_count = 0
            report_file = output_dir / 'final_report.json'
            if report_file.exists():
                with open(report_file, 'r') as f:
                    try:
                        data = json.load(f)
                        findings_count = len(data.get('findings', []))
                    except json.JSONDecodeError:
                        self.logger.warning("Failed to parse Osmedeus JSON report")
            
            return ScanResult(
                tool='osmedeus',
                target=self.target,
                success=True,
                output_file=str(report_file) if report_file.exists() else None,
                findings_count=findings_count
            )
            
        except subprocess.TimeoutExpired:
            return ScanResult(
                tool='osmedeus',
                target=self.target,
                success=False,
                error="Osmedeus scan timed out after 2 hours"
            )
        except Exception as e:
            return ScanResult(
                tool='osmedeus',
                target=self.target,
                success=False,
                error=str(e)
            )
    
    def run_porch_pirate(self) -> ScanResult:
        """Run Porch-pirate for cloud service enumeration"""
        if not self.tool_manager.tool_paths.get('porch-pirate'):
            return ScanResult(
                tool='porch-pirate',
                target=self.target,
                success=False,
                error="Porch-pirate not found. Install with: pipx install porch-pirate"
            )
        
        output_dir = self.output_dir / 'porch_pirate'
        output_dir.mkdir(exist_ok=True)
        output_file = output_dir / 'results.json'
        
        cmd = [
            self.tool_manager.tool_paths['porch-pirate'],
            '--target', self.target,
            '--output', str(output_file),
            '--threads', '5',
            '--timeout', '900'  # 15 minutes
        ]
        
        try:
            self.logger.info(f"Running Porch-pirate on {self.target}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1200  # 20 minutes
            )
            
            if result.returncode != 0:
                return ScanResult(
                    tool='porch-pirate',
                    target=self.target,
                    success=False,
                    error=result.stderr or "Porch-pirate scan failed"
                )
            
            # Count findings
            findings_count = 0
            if output_file.exists():
                with open(output_file, 'r') as f:
                    try:
                        data = json.load(f)
                        findings_count = len(data) if isinstance(data, list) else 1
                    except json.JSONDecodeError:
                        findings_count = 1
            
            return ScanResult(
                tool='porch-pirate',
                target=self.target,
                success=True,
                output_file=str(output_file) if output_file.exists() else None,
                findings_count=findings_count
            )
            
        except subprocess.TimeoutExpired:
            return ScanResult(
                tool='porch-pirate',
                target=self.target,
                success=False,
                error="Porch-pirate scan timed out after 20 minutes"
            )
        except Exception as e:
            return ScanResult(
                tool='porch-pirate',
                target=self.target,
                success=False,
                error=str(e)
            )
    
    def run_amass(self) -> ScanResult:
        """Run Amass for comprehensive subdomain enumeration"""
        if not self.tool_manager.tool_paths.get('amass'):
            return ScanResult(
                tool='amass',
                target=self.target,
                success=False,
                error="Amass not found. Install with: brew install amass or apt-get install amass"
            )
        
        output_file = self.output_dir / f"amass-{self.target}.json"
        cmd = [
            self.tool_manager.tool_paths['amass'],
            'enum',
            '-d', self.target,
            '-json', str(output_file),
            '-oA', str(self.output_dir / 'amass'),
            '-active',  # Active reconnaissance
            '-brute',   # Enable subdomain bruteforcing
            '-w', '/usr/share/wordlists/amass/subdomains-top1mil-5000.txt',  # Default wordlist
            '-config', str(Path.home() / '.config/amass/config.ini'),  # Use config file if exists
            '-timeout', '30',  # 30 minutes timeout
            '-max-dns-queries', '1000'  # Rate limiting
        ]
        
        try:
            self.logger.info(f"Running Amass on {self.target}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800  # 30 minutes timeout
            )
            
            if result.returncode != 0:
                return ScanResult(
                    tool='amass',
                    target=self.target,
                    success=False,
                    error=result.stderr
                )
            
            # Count unique subdomains found
            subdomains = set()
            if output_file.exists() and output_file.stat().st_size > 0:
                with open(output_file, 'r') as f:
                    for line in f:
                        try:
                            data = json.loads(line)
                            if 'name' in data:
                                subdomains.add(data['name'].lower())
                        except json.JSONDecodeError:
                            continue
            
            return ScanResult(
                tool='amass',
                target=self.target,
                success=True,
                output_file=str(output_file),
                findings_count=len(subdomains)
            )
            
        except subprocess.TimeoutExpired:
            return ScanResult(
                tool='amass',
                target=self.target,
                success=False,
                error="Command timed out after 30 minutes"
            )
        except Exception as e:
            return ScanResult(
                tool='amass',
                target=self.target,
                success=False,
                error=str(e)
            )
    
    def run_endpoint_discovery(self, domains: List[str]) -> List[ScanResult]:
        """Run endpoint discovery on a list of domains"""
        if not domains:
            return []
            
        results = []
        
        # Create a temporary file with domains
        domains_file = self.output_dir / 'domains.txt'
        with open(domains_file, 'w') as f:
            f.write('\n'.join(domains))
        
        # Run waybackurls
        if self.tool_manager.tool_paths.get('waybackurls'):
            wayback_output = self.output_dir / 'waybackurls.txt'
            cmd = [
                self.tool_manager.tool_paths['waybackurls'],
                '-no-subs',
                '-get-targets',
                '-i', str(domains_file)
            ]
            
            try:
                self.logger.info("Running waybackurls for endpoint discovery")
                with open(wayback_output, 'w') as outfile:
                    result = subprocess.run(
                        cmd,
                        stdout=outfile,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=300  # 5 minutes
                    )
                
                if result.returncode == 0 and wayback_output.exists():
                    with open(wayback_output, 'r') as f:
                        url_count = len(f.readlines())
                    
                    results.append(ScanResult(
                        tool='waybackurls',
                        target=','.join(domains[:3]) + (f" and {len(domains)-3} more" if len(domains) > 3 else ''),
                        success=True,
                        output_file=str(wayback_output),
                        findings_count=url_count
                    ))
                
            except Exception as e:
                self.logger.error(f"Error running waybackurls: {str(e)}")
        
        # Run gau
        if self.tool_manager.tool_paths.get('gau'):
            gau_output = self.output_dir / 'gau.txt'
            cmd = [
                self.tool_manager.tool_paths['gau'],
                '--subs',
                '--from', '202201',  # Get URLs from 2022 onwards
                '--threads', '10',
                '--o', str(gau_output)
            ]
            
            try:
                self.logger.info("Running gau for endpoint discovery")
                result = subprocess.run(
                    cmd,
                    input='\n'.join(domains),
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minutes
                )
                
                if result.returncode == 0 and gau_output.exists():
                    with open(gau_output, 'r') as f:
                        url_count = len(f.readlines())
                    
                    results.append(ScanResult(
                        tool='gau',
                        target=','.join(domains[:3]) + (f" and {len(domains)-3} more" if len(domains) > 3 else ''),
                        success=True,
                        output_file=str(gau_output),
                        findings_count=url_count
                    ))
                
            except Exception as e:
                self.logger.error(f"Error running gau: {str(e)}")
        
        # Run httpx on discovered endpoints
        if self.tool_manager.tool_paths.get('httpx') and (wayback_output.exists() or gau_output.exists()):
            httpx_output = self.output_dir / 'httpx.json'
            input_files = [str(f) for f in [wayback_output, gau_output] if f.exists()]
            
            cmd = [
                self.tool_manager.tool_paths['httpx'],
                '-l', ','.join(input_files),
                '-json',
                '-o', str(httpx_output),
                '-status-code',
                '-title',
                '-tech-detect',
                '-follow-redirects',
                '-timeout', '10',
                '-threads', '20',
                '-retries', '2'
            ]
            
            try:
                self.logger.info("Running httpx for endpoint validation")
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=600  # 10 minutes
                )
                
                if result.returncode == 0 and httpx_output.exists():
                    with open(httpx_output, 'r') as f:
                        url_count = len(f.readlines())
                    
                    results.append(ScanResult(
                        tool='httpx',
                        target=','.join(domains[:3]) + (f" and {len(domains)-3} more" if len(domains) > 3 else ''),
                        success=True,
                        output_file=str(httpx_output),
                        findings_count=url_count
                    ))
                
            except Exception as e:
                self.logger.error(f"Error running httpx: {str(e)}")
        
        return results
    
    def run_scan(self):
        """Run AI-powered reconnaissance scan"""
        start_time = datetime.now()
        
        if self.is_secure_site:
            self.logger.warning(f"Target {self.target} is a well-known secure site. Running in safe mode with limited scanning.")
            self._run_secure_site_scan(start_time)
        elif self.fast_mode:
            self.logger.info(f"Starting fast scan of {self.target}")
            self._run_fast_scan(start_time)
        else:
            self.logger.info(f"Starting comprehensive scan of {self.target}")
            self._run_normal_scan(start_time)
    
    def _run_secure_site_scan(self, start_time: datetime):
        """Run a lightweight scan for well-known secure sites"""
        self.logger.info(f"Running safe scan for well-known secure site: {self.target}")
        
        # Only run basic subdomain discovery
        try:
            result = self.run_subfinder()
            if result:
                self.results.append(result)
        except Exception as e:
            self.logger.error(f"Error running subdomain discovery: {str(e)}")
        
        # Generate summary with secure site notice
        summary = self.generate_summary()
        summary['is_secure_site'] = True
        summary['secure_site_notice'] = "Limited scan performed - target is a well-known secure site"
        self.print_summary(summary)
        
    def _run_fast_scan(self, start_time: datetime):
        """Run fast parallel reconnaissance"""
        with ThreadPoolExecutor(max_workers=4) as executor:
            # Submit all tools for parallel execution
            future_to_tool = {
                executor.submit(self.run_subfinder): 'subfinder',
                executor.submit(self.run_amass): 'amass',
                executor.submit(self.run_porch_pirate): 'porch_pirate'
            }
            
            # Process completed scans
            for future in as_completed(future_to_tool):
                tool_name = future_to_tool[future]
                try:
                    result = future.result()
                    if result:
                        self.results.append(result)
                except Exception as e:
                    self.logger.error(f"Error running {tool_name}: {str(e)}")
        
        # Generate summary
        self.generate_summary()
    
    def _run_normal_scan(self, start_time: datetime):
        # XSS test payloads
        xss_payloads = [
            '"><script>alert(1)</script>',
            '" onmouseover="alert(1)"',
            '"><img src=x onerror=alert(1)>'
        ]
        
        # Test for LFI/RFI
        lfi_payloads = [
            "/etc/passwd",
            "../../../../etc/passwd",
            "C:\\Windows\\System32\\drivers\\etc\\hosts"
        ]
        
        # SQL Injection test
        sql_payloads = [
            "1' OR '1'='1",
            "1' OR '1'='1' -- ",
            "1' OR 1=1 -- "
        ]
        
        # 2. Test for SQL Injection
        try:
            for payload in sql_payloads:
                test_url = f"{self.target}?id={payload}" if '?' in self.target else f"{self.target}?id={payload}"
                response = requests.get(test_url, timeout=10, verify=False)
                
                # Simple check for SQL error messages
                sql_errors = [
                    "SQL syntax", "MySQL server", "syntax error", "unexpected end",
                    "quoted string", "mysql_fetch", "num_rows", "not a valid MySQL"
                ]
                
                if any(error.lower() in response.text.lower() for error in sql_errors):
                    vulnerabilities.append({
                        'type': 'SQL Injection',
                        'url': test_url,
                        'severity': 'high',
                        'payload': payload,
                        'description': 'Possible SQL injection vulnerability detected'
                    })
        except Exception as e:
            self.logger.error(f"Error testing SQLi: {str(e)}")
        
        # 3. Test for XSS
        try:
            for payload in xss_payloads:
                test_url = f"{target_url}?search={requests.utils.quote(payload)}"
                response = requests.get(test_url, timeout=10, verify=False)
                
                if payload in response.text:
                    vulnerabilities.append({
                        'type': 'Cross-Site Scripting (XSS)',
                        'url': test_url,
                        'severity': 'medium',
                        'payload': payload,
                        'description': 'Possible XSS vulnerability detected (reflected)'
                    })
        except Exception as e:
            self.logger.error(f"Error testing XSS: {str(e)}")
        
        # 4. Test for LFI/RFI
        try:
            for payload in lfi_payloads:
                test_url = f"{target_url}?page={requests.utils.quote(payload)}"
                response = requests.get(test_url, timeout=10, verify=False)
                
                lfi_indicators = ["root:", "nobody:", "/bin/", "Microsoft Windows ["]
                if any(indicator in response.text for indicator in lfi_indicators):
                    vulnerabilities.append({
                        'type': 'Local File Inclusion (LFI)',
                        'url': test_url,
                        'severity': 'high',
                        'payload': payload,
                        'description': 'Possible LFI vulnerability detected'
                    })
        except Exception as e:
            self.logger.error(f"Error testing LFI: {str(e)}")
        
        return vulnerabilities

    def _run_normal_scan(self, start_time: datetime) -> Dict:
        """Run normal sequential scan with comprehensive vulnerability checks"""
        self.logger.info("Running in NORMAL mode (sequential execution with vulnerability scanning)")
        
        # Run tools sequentially
        self.run_subfinder()
        self.run_amass()
        
        # Get all discovered subdomains
        subdomains = self._get_subdomains_from_results()
        
        # Add main target if not already in subdomains
        if self.target not in subdomains:
            subdomains.append(self.target)
        
        # Run vulnerability scan on all discovered domains
        vulnerabilities = []
        for domain in subdomains:
            # Add http:// if no scheme is present
            target_url = f"http://{domain}" if not domain.startswith(('http://', 'https://')) else domain
            
            # Run vulnerability checks
            try:
                # Test for SQL Injection
                sql_payloads = [
                    "' OR '1'='1",
                    '\" OR \"\"=\"',
                    "' OR '1'='1' --",
                    "' OR 1=1 --"
                ]
                
                # Test for XSS
                xss_payloads = [
                    "<script>alert('XSS')</script>",
                    '\"><script>alert(1)</script>',
                    '\" onmouseover=\"alert(1)\"',
                    '\"><img src=x onerror=alert(1)>'
                ]
                
                # Test for LFI/RFI
                lfi_payloads = [
                    "/etc/passwd",
                    "../../../../etc/passwd",
                    "C:\\Windows\\System32\\drivers\\etc\\hosts"
                ]
                
                # Test for SQL Injection
                for payload in sql_payloads:
                    test_url = f"{target_url}?id={payload}" if '?' in target_url else f"{target_url}?id={payload}"
                    try:
                        response = requests.get(test_url, timeout=10, verify=False)
                        
                        # Simple check for SQL error messages
                        sql_errors = [
                            "SQL syntax", "MySQL server", "syntax error", "unexpected end",
                            "quoted string", "mysql_fetch", "num_rows", "not a valid MySQL"
                        ]
                        
                        if any(error.lower() in response.text.lower() for error in sql_errors):
                            vulnerabilities.append({
                                'type': 'SQL Injection',
                                'url': test_url,
                                'severity': 'high',
                                'payload': payload,
                                'description': 'Possible SQL injection vulnerability detected',
                                'domain': domain
                            })
                    except Exception as e:
                        self.logger.error(f"Error testing SQLi on {test_url}: {str(e)}")
                
                # Test for XSS
                for payload in xss_payloads:
                    test_url = f"{target_url}?search={requests.utils.quote(payload)}"
                    try:
                        response = requests.get(test_url, timeout=10, verify=False)
                        
                        if payload in response.text:
                            vulnerabilities.append({
                                'type': 'Cross-Site Scripting (XSS)',
                                'url': test_url,
                                'severity': 'medium',
                                'payload': payload,
                                'description': 'Possible XSS vulnerability detected (reflected)',
                                'domain': domain
                            })
                    except Exception as e:
                        self.logger.error(f"Error testing XSS on {test_url}: {str(e)}")
                
                # Test for LFI/RFI
                for payload in lfi_payloads:
                    test_url = f"{target_url}?page={requests.utils.quote(payload)}"
                    try:
                        response = requests.get(test_url, timeout=10, verify=False)
                        
                        lfi_indicators = ["root:", "nobody:", "/bin/", "Microsoft Windows ["]
                        if any(indicator in response.text for indicator in lfi_indicators):
                            vulnerabilities.append({
                                'type': 'Local File Inclusion (LFI)',
                                'url': test_url,
                                'severity': 'high',
                                'payload': payload,
                                'description': 'Possible LFI vulnerability detected',
                                'domain': domain
                            })
                    except Exception as e:
                        self.logger.error(f"Error testing LFI on {test_url}: {str(e)}")
                
            except Exception as e:
                self.logger.error(f"Error scanning {domain}: {str(e)}")
        
        # Save vulnerabilities to results
        if vulnerabilities:
            self.results.append(ScanResult(
                tool='vuln_scan',
                target=self.target,
                success=True,
                output_file=str(self.output_dir / 'vulnerabilities.json'),
                findings_count=len(vulnerabilities)
            ))
            
            # Save vulnerabilities to file
            with open(self.output_dir / 'vulnerabilities.json', 'w') as f:
                json.dump(vulnerabilities, f, indent=2)
        
        # Run endpoint discovery on discovered subdomains
        if subdomains:
            self.run_endpoint_discovery(subdomains)
        
        # Generate and return summary
        summary = self.generate_summary()
        
        # Add vulnerabilities to summary
        if vulnerabilities:
            summary['vulnerabilities'] = vulnerabilities
            
            # Count vulnerabilities by severity
            severity_counts = {'high': 0, 'medium': 0, 'low': 0}
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'low').lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            summary['vulnerability_summary'] = severity_counts
        
        return summary
    
    def _get_subdomains_from_results(self) -> List[str]:
        """Get subdomains from previous scan results"""
        subdomains = set()
        
        for result in self.results:
            if result.tool in ['subfinder', 'amass']:
                if result.output_file:
                    with open(result.output_file, 'r') as f:
                        for line in f:
                            subdomain = line.strip()
                            if subdomain:
                                subdomains.add(subdomain)
        
        return list(subdomains)
    
    def generate_summary(self) -> Dict:
        """Generate comprehensive scan summary"""
        end_time = datetime.now()
        start_time = datetime.strptime(self.timestamp, '%Y-%m-%d_%H-%M-%S')
        runtime = end_time - start_time
        
        summary = {
            'target': self.target,
            'timestamp': self.timestamp,
            'output_directory': str(self.output_dir),
            'total_runtime': str(runtime).split('.')[0],  # Remove microseconds
            'scan_results': {},
            'files_generated': [],
            'results': []
        }
        
        # Process results by tool
        for result in self.results:
            if result.tool not in summary['scan_results']:
                summary['scan_results'][result.tool] = {
                    'success': 0,
                    'failed': 0,
                    'total_findings': 0
                }
            
            if result.success:
                summary['scan_results'][result.tool]['success'] += 1
                summary['scan_results'][result.tool]['total_findings'] += result.findings_count
            else:
                summary['scan_results'][result.tool]['failed'] += 1
        
        # List generated files
        for file_path in self.output_dir.iterdir():
            if file_path.is_file():
                summary['files_generated'].append({
                    'name': file_path.name,
                    'size': file_path.stat().st_size
                })
        
        # Add results for compatibility
        summary['results'] = [
            {
                'tool': result.tool,
                'target': result.target,
                'success': result.success,
                'findings_count': result.findings_count
            } for result in self.results
        ]
        
        # Save summary to JSON file
        summary_file = self.output_dir / 'scan_summary.json'
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        return summary
    def print_summary(self, summary: Dict):
        """Print formatted summary to console"""
        try:
            print("\n" + "="*70)
            print(f"{' RECONNAISSANCE SUMMARY ':=^70}")
            print("="*70)
            print(f"Target: {summary['target']}")
            print(f"Scan started at: {summary['start_time']}")
            print(f"Total runtime: {summary['total_runtime']}")
            print("\n[+] Tools executed:")
            
            # Track total findings
            total_subdomains = 0
            total_endpoints = 0
            
            for tool, stats in summary['scan_results'].items():
                status = "✓" if stats['success'] > 0 else "✗"
                if tool in ['subfinder', 'amass']:
                    total_subdomains += stats['total_findings']
                    print(f"  {status} {tool.upper()}: Found {stats['total_findings']} subdomains")
                elif tool in ['waybackurls', 'gau']:
                    total_endpoints += stats['total_findings']
                    print(f"  {status} {tool.upper()}: Found {stats['total_findings']} endpoints")
                else:
                    print(f"  {status} {tool.upper()}: {stats['success']} successful, {stats['failed']} failed")
            
            print("\n[+] Summary of findings:")
            print(f"  - Total unique subdomains discovered: {total_subdomains}")
            print(f"  - Total endpoints discovered: {total_endpoints}")
            
            if 'files_generated' in summary and summary['files_generated']:
                print("\n[+] Files generated:")
                for file in summary['files_generated']:
                    size_kb = file['size'] / 1024
                    print(f"  - {file['name']} ({size_kb:.1f} KB)")
            
            # Print vulnerability summary if available
            if 'vulnerabilities' in summary and summary['vulnerabilities']:
                print("\n[+] Vulnerability Summary:")
                for vuln in summary['vulnerabilities']:
                    print(f"  - {vuln['severity'].upper()}: {vuln['name']} ({vuln['description']})")
            else:
                print("\n[+] No vulnerabilities found")
                
            print("\n[+] Next steps:")
            print("  1. Review the discovered subdomains in the output files")
            print("  2. Check for sensitive information in the endpoint discovery results")
            print("  3. Manually verify any interesting findings")
            
            # Print files generated
            if 'files_generated' in summary and summary['files_generated']:
                print("\n[+] Files generated:")
                for file_info in summary['files_generated']:
                    size_mb = file_info['size'] / (1024 * 1024)
                    print(f"  - {file_info['name']} ({size_mb:.2f} MB)")
            
            print("\n" + "="*70)
                
        except KeyError as e:
            self.logger.error(f"Error generating summary: {e}")
            print("\n[!] Error generating complete summary. Some information may be missing.")
        
        print()
        print("="*50)
        print("Scan completed successfully!")
        print(f"Review the detailed results in: {summary['output_directory']}")
        print("="*50)
    
    def run_scan(self) -> Dict[str, Any]:
        """Run AI-powered security scan"""
        start_time = datetime.now()
        
        self.logger.info("=" * 50)
        mode_text = "AI-POWERED FAST MODE" if self.fast_mode else "AI-POWERED COMPREHENSIVE MODE"
        self.logger.info(f"Auto Security Scanner Started - {mode_text}")
        self.logger.info(f"Target: {self.target}")
        self.logger.info(f"Timestamp: {start_time.strftime('%Y-%m-%d_%H-%M-%S')}")
        self.logger.info(f"Output Directory: {self.output_dir}")
        self.logger.info("=" * 50)
        
        # Check for missing tools
        missing_tools = self.tool_manager.get_missing_tools()
        if missing_tools:
            self.logger.warning(f"Missing tools: {', '.join(missing_tools)}")
        
        # Import AI methods
        from ai_methods import (
            _run_ai_comprehensive_scan, _run_ai_fast_scan, _run_ai_nuclei_scan,
            _run_ai_nuclei_fast, _run_ai_nuclei_single, _run_ai_nuclei_single_ultra_fast,
            _generate_ai_summary, _save_ai_results, _create_scan_result, _create_failed_result
        )
        
        # Bind methods to self
        self._run_ai_comprehensive_scan = _run_ai_comprehensive_scan.__get__(self, SecurityScanner)
        self._run_ai_fast_scan = _run_ai_fast_scan.__get__(self, SecurityScanner)
        self._run_ai_nuclei_scan = _run_ai_nuclei_scan.__get__(self, SecurityScanner)
        self._run_ai_nuclei_fast = _run_ai_nuclei_fast.__get__(self, SecurityScanner)
        self._run_ai_nuclei_single = _run_ai_nuclei_single.__get__(self, SecurityScanner)
        self._run_ai_nuclei_single_ultra_fast = _run_ai_nuclei_single_ultra_fast.__get__(self, SecurityScanner)
        self._generate_ai_summary = _generate_ai_summary.__get__(self, SecurityScanner)
        self._save_ai_results = _save_ai_results.__get__(self, SecurityScanner)
        self._create_scan_result = _create_scan_result.__get__(self, SecurityScanner)
        self._create_failed_result = _create_failed_result.__get__(self, SecurityScanner)
        
        if self.fast_mode:
            return self._run_ai_fast_scan(start_time)
        else:
            return self._run_ai_comprehensive_scan(start_time)
        
        if missing_tools:
            self.logger.warning(f"Missing tools: {', '.join(missing_tools)}")
        
        if self.fast_mode:
            # Fast mode: run essential tools in parallel
            self.logger.info("Running in FAST MODE - parallel execution")
    """Main entry point"""
    parser = argparse.ArgumentParser(description='AI-Powered Reconnaissance Tool')
    parser.add_argument('target', help='Target domain to perform reconnaissance on')
    parser.add_argument('-o', '--output', help='Output directory for results (default: scan_results/<target>-<timestamp>)')
    parser.add_argument('-f', '--fast', action='store_true', help='Enable fast mode (parallel execution)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--no-http', action='store_true', help='Skip HTTP endpoint discovery')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('recon.log'),
            logging.StreamHandler()
        ]
    )
    
    try:
        # Check if target is a valid domain
        if not re.match(r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$', args.target.lower()):
            logging.error("Invalid domain format. Please provide a valid domain (e.g., example.com)")
            sys.exit(1)
            
        scanner = SecurityScanner(
            target=args.target,
            output_dir=args.output,
            fast_mode=args.fast,
            verbose=args.verbose
        )
        
        # Run the reconnaissance
        print(f"\n[+] Starting reconnaissance on {args.target}")
        print("[*] This may take some time depending on the target's size...\n")
        
        summary = scanner.run_scan()
        
        # Print summary
        scanner.print_summary(summary)
        print()
        print("Vulnerabilities by Severity:")
        vuln_by_severity = summary.get('vulnerabilities_by_severity', {})
        for severity in ['critical', 'high', 'medium', 'low']:
            count = vuln_by_severity.get(severity, 0)
            print(f"  {severity.title()}: {count}")
        print()
        print(f"Detailed results saved to: {scanner.output_dir}")
        print("="*50)
        
        # Display AI Executive Summary
        exec_summary = summary.get('executive_summary', '')
        if exec_summary:
            print("\n" + exec_summary)
            print("\n" + "="*50)
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
