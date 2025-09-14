#!/usr/bin/env python3
"""
Auto Security Scanner - Professional Python Implementation
Integrates Porch-pirate, Subfinder, and Nuclei for comprehensive security scanning
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
            'porch-pirate': self._check_porch_pirate,
            'subfinder': self._check_subfinder,
            'nuclei': self._check_nuclei,
            'osmedeus': self._check_osmedeus,
            'rengine': self._check_rengine,
            'jq': self._check_jq
        }
        self.tool_paths = {}
        self._detect_tools()
    
    def _detect_tools(self):
        """Detect available security tools"""
        for tool, checker in self.tools.items():
            self.tool_paths[tool] = checker()
    
    def _check_porch_pirate(self) -> Optional[str]:
        """Check if porch-pirate is available"""
        return shutil.which('porch-pirate')
    
    def _check_subfinder(self) -> Optional[str]:
        """Check if subfinder is available"""
        return shutil.which('subfinder')
    
    def _check_nuclei(self) -> Optional[str]:
        """Check if nuclei is available"""
        return shutil.which('nuclei')
    
    def _check_osmedeus(self) -> Optional[str]:
        """Check if osmedeus is available"""
        return shutil.which('osmedeus')
    
    def _check_rengine(self) -> Optional[str]:
        """Check if rengine is available"""
        # Check for rengine CLI first
        rengine_path = shutil.which('rengine')
        if rengine_path:
            return rengine_path
        
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
    
    def is_available(self, tool: str) -> bool:
        """Check if a tool is available"""
        return self.tool_paths.get(tool) is not None
    
    def get_missing_tools(self) -> List[str]:
        """Get list of missing tools"""
        return [tool for tool, path in self.tool_paths.items() if path is None]


class SecurityScanner:
    """Main security scanner class with AI integration"""
    
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
    
    def run_osmedeus(self) -> ScanResult:
        """Run Osmedeus comprehensive reconnaissance"""
        self.logger.info(f"[3/5] Starting Osmedeus reconnaissance on {self.target}...")
        
        if not self.tool_manager.is_available('osmedeus'):
            error_msg = "Osmedeus not found. Install with: go install -v github.com/j3ssie/osmedeus@latest"
            self.logger.warning(error_msg)
            return ScanResult('osmedeus', self.target, False, error=error_msg)
        
        try:
            output_file = self.output_dir / 'osmedeus_results.json'
            workspace_dir = self.output_dir / 'osmedeus_workspace'
            workspace_dir.mkdir(exist_ok=True)
            
            # Run osmedeus with general workflow
            cmd = [
                self.tool_manager.tool_paths['osmedeus'],
                'scan', '-t', self.target,
                '-w', str(workspace_dir),
                '--timeout', '1800',  # 30 minutes timeout
                '-o', str(output_file)
            ]
            
            self.logger.info("Running Osmedeus comprehensive scan (this may take a while)...")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=2400)  # 40 min timeout
            
            findings_count = 0
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        data = json.load(f)
                        findings_count = len(data.get('results', []))
                except:
                    findings_count = 1 if output_file.stat().st_size > 0 else 0
            
            self.logger.info("Osmedeus scan completed")
            return ScanResult('osmedeus', self.target, True, str(output_file), findings_count=findings_count)
            
        except subprocess.TimeoutExpired:
            error_msg = "Osmedeus scan timed out"
            self.logger.error(error_msg)
            return ScanResult('osmedeus', self.target, False, error=error_msg)
        except Exception as e:
            error_msg = f"Osmedeus scan failed: {str(e)}"
            self.logger.error(error_msg)
            return ScanResult('osmedeus', self.target, False, error=error_msg)
    
    def run_rengine(self) -> Tuple[ScanResult, List[str]]:
        """Run ReNgine reconnaissance engine"""
        self.logger.info(f"[4/5] Starting ReNgine reconnaissance on {self.target}...")
        
        if not self.tool_manager.is_available('rengine'):
            error_msg = "ReNgine not found. Install with Docker: docker pull yogeshojha/rengine"
            self.logger.warning(error_msg)
            return ScanResult('rengine', self.target, False, error=error_msg), [self.target]
        
        try:
            output_file = self.output_dir / 'rengine_results.json'
            subdomains_file = self.output_dir / 'rengine_subdomains.txt'
            rengine_type = self.tool_manager.tool_paths['rengine']
            
            if rengine_type == 'docker':
                return self._run_rengine_docker(output_file, subdomains_file)
            elif rengine_type == 'api':
                return self._run_rengine_api(output_file, subdomains_file)
            elif rengine_type == 'builtin':
                return self._run_rengine_builtin(output_file, subdomains_file)
            else:
                # CLI version
                return self._run_rengine_cli(output_file, subdomains_file, rengine_type)
                
        except Exception as e:
            error_msg = f"ReNgine scan failed: {str(e)}"
            self.logger.error(error_msg)
            return ScanResult('rengine', self.target, False, error=error_msg), [self.target]
    
    def _run_rengine_docker(self, output_file, subdomains_file):
        """Run ReNgine via Docker"""
        cmd = [
            'docker', 'run', '--rm',
            '-v', f"{self.output_dir}:/output",
            'yogeshojha/rengine',
            'python3', 'manage.py', 'scan',
            '--domain', self.target,
            '--output', '/output/rengine_results.json'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        return self._process_rengine_results(output_file, subdomains_file)
    
    def _run_rengine_api(self, output_file, subdomains_file):
        """Run ReNgine via API"""
        try:
            import requests
            
            # Submit scan request
            response = requests.post('http://localhost:8000/api/scan/', 
                                   json={'domain': self.target}, timeout=30)
            
            if response.status_code == 200:
                scan_id = response.json().get('scan_id')
                
                # Poll for results
                import time
                for _ in range(60):  # Wait up to 30 minutes
                    time.sleep(30)
                    status_response = requests.get(f'http://localhost:8000/api/scan/{scan_id}/')
                    if status_response.json().get('status') == 'completed':
                        results = status_response.json().get('results', {})
                        
                        # Save results
                        with open(output_file, 'w') as f:
                            json.dump(results, f, indent=2)
                        
                        return self._process_rengine_results(output_file, subdomains_file)
                
                # Timeout
                return ScanResult('rengine', self.target, False, error="API scan timeout"), [self.target]
            else:
                return ScanResult('rengine', self.target, False, error="API request failed"), [self.target]
                
        except Exception as e:
            return ScanResult('rengine', self.target, False, error=f"API error: {e}"), [self.target]
    
    def _run_rengine_builtin(self, output_file, subdomains_file):
        """Run built-in reconnaissance as ReNgine fallback"""
        self.logger.info("Using built-in reconnaissance (ReNgine fallback)")
        
        # Perform basic subdomain enumeration
        subdomains = self._builtin_subdomain_discovery()
        
        # Create mock ReNgine results
        results = {
            'target': self.target,
            'subdomains': subdomains,
            'scan_type': 'builtin_fallback',
            'timestamp': datetime.now().isoformat(),
            'results': [
                {
                    'type': 'subdomain',
                    'value': sub,
                    'source': 'builtin'
                } for sub in subdomains
            ]
        }
        
        # Save results
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        with open(subdomains_file, 'w') as f:
            for subdomain in subdomains:
                f.write(f"{subdomain}\n")
        
        self.logger.info(f"Built-in reconnaissance found {len(subdomains)} domains")
        self.logger.info("ReNgine (builtin) scan completed")
        
        return ScanResult('rengine', self.target, True, str(output_file), findings_count=len(subdomains)), subdomains
    
    def _run_rengine_cli(self, output_file, subdomains_file, cli_path):
        """Run ReNgine CLI version"""
        cmd = [cli_path, 'scan', '-d', self.target, '-o', str(output_file)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        return self._process_rengine_results(output_file, subdomains_file)
    
    def _process_rengine_results(self, output_file, subdomains_file):
        """Process ReNgine results and extract subdomains"""
        subdomains = [self.target]  # Default to main domain
        findings_count = 0
        
        if output_file.exists():
            try:
                with open(output_file, 'r') as f:
                    data = json.load(f)
                    
                # Extract subdomains from ReNgine output
                if 'subdomains' in data:
                    found_subdomains = data['subdomains'][:20]  # Limit to 20
                    if found_subdomains:
                        subdomains = found_subdomains
                        # Save subdomains to separate file
                        with open(subdomains_file, 'w') as sf:
                            for subdomain in found_subdomains:
                                sf.write(f"{subdomain}\n")
                
                findings_count = len(data.get('results', []))
            except Exception as e:
                self.logger.warning(f"Could not parse ReNgine results: {e}")
        
        subdomain_count = len(subdomains)
        if subdomain_count > 1:
            self.logger.info(f"ReNgine found {subdomain_count} subdomains")
        else:
            self.logger.info("ReNgine completed, using target domain only")
        
        self.logger.info("ReNgine scan completed")
        return ScanResult('rengine', self.target, True, str(output_file), findings_count=findings_count), subdomains
    
    def _builtin_subdomain_discovery(self):
        """Built-in subdomain discovery as ReNgine fallback"""
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api', 
            'blog', 'shop', 'store', 'support', 'help', 'docs', 'cdn', 'static'
        ]
        
        found_subdomains = [self.target]
        
        # Try common subdomains
        for sub in common_subdomains:
            subdomain = f"{sub}.{self.target}"
            try:
                import socket
                socket.gethostbyname(subdomain)
                found_subdomains.append(subdomain)
            except socket.gaierror:
                pass  # Subdomain doesn't exist
        
        return found_subdomains[:10]  # Limit to 10 for performance

    def run_nuclei_single(self, domain: str) -> ScanResult:
        """Run nuclei scan on a single domain with speed optimizations"""
        if not self.tool_manager.is_available('nuclei'):
            return ScanResult('nuclei', domain, False, error="Nuclei not found")
        
        try:
            # Clean domain name for filename
            clean_domain = re.sub(r'[:/]', '_', domain)
            output_file = self.output_dir / f'nuclei_{clean_domain}.txt'
            
            # Ultra-fast Nuclei command for speed + accuracy
            cmd = [
                self.tool_manager.tool_paths['nuclei'],
                '-u', f'http://{domain}',
                '-o', str(output_file),
                '-rate-limit', '300',        # Much higher rate limit
                '-timeout', '3',             # Very short timeout per request
                '-retries', '1',             # Minimal retries
                '-concurrency', '50',        # High concurrency
                '-bulk-size', '50',          # Large bulk processing
                '-t', 'http/vulnerabilities/', # Target specific vulns
                '-t', 'http/exposures/',     # Common exposures
                '-t', 'http/misconfiguration/', # Misconfigurations
                '-severity', 'high,critical,medium', # Important findings only
                '-silent'                    # Reduce output noise
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)  # 3 min timeout
            
            findings_count = 0
            if output_file.exists():
                with open(output_file, 'r') as f:
                    findings_count = sum(1 for line in f if line.strip())
            
            return ScanResult('nuclei', domain, True, str(output_file), findings_count=findings_count)
            
        except Exception as e:
            error_msg = f"Nuclei scan failed for {domain}: {str(e)}"
            self.logger.error(error_msg)
            return ScanResult('nuclei', domain, False, error=error_msg)
    
    def run_nuclei_fast(self, domains: List[str]) -> List[ScanResult]:
        """Run Nuclei with fast templates only"""
        self.logger.info(f"[FAST] Running Nuclei vulnerability scans on {len(domains)} domains...")
        if not self.tool_manager.is_available('nuclei'):
            error_msg = "Nuclei not found. Install with: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
            self.logger.warning(error_msg)
            return [ScanResult('nuclei', self.target, False, error=error_msg)]
        
        results = []
        # Use targeted templates for speed + accuracy
        fast_templates = [
            '-t', 'http/vulnerabilities/', 
            '-t', 'http/exposures/',
            '-t', 'http/misconfiguration/',
            '-severity', 'high,critical,medium',
            '-rate-limit', '400',
            '-timeout', '2',
            '-concurrency', '60'
        ]
        
        with ThreadPoolExecutor(max_workers=5) as executor:  # Increased workers
            futures = {}
            for domain in domains[:5]:  # Limit domains for speed
                future = executor.submit(self._run_nuclei_single_fast, domain, fast_templates)
                futures[future] = domain
            
            for future in as_completed(futures):
                domain = futures[future]
                try:
                    result = future.result(timeout=300)  # 5 min timeout
                    results.append(result)
                except Exception as e:
                    self.logger.error(f"Nuclei fast scan failed for {domain}: {e}")
                    results.append(ScanResult('nuclei', domain, False, error=str(e)))
        
        self.logger.info("Nuclei fast scans completed")
        return results
    
    def _run_nuclei_single_fast(self, domain: str, templates: List[str]) -> ScanResult:
        """Run Nuclei on a single domain with fast templates"""
        output_file = self.output_dir / f'nuclei_{domain.replace(".", "_")}.txt'
        
        cmd = [
            self.tool_manager.tool_paths['nuclei'],
            '-u', f'http://{domain}',
            '-o', str(output_file),
            '-rate-limit', '100',  # Faster rate
            '-timeout', '5',       # Shorter timeout
            '-retries', '1'        # Fewer retries
        ] + templates
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            findings_count = self._count_nuclei_findings(output_file)
            return ScanResult('nuclei', domain, True, str(output_file), findings_count=findings_count)
        except Exception as e:
            return ScanResult('nuclei', domain, False, error=str(e))
    
    def run_nuclei_parallel(self, domains: List[str]) -> List[ScanResult]:
        """Run nuclei vulnerability scans on multiple domains"""
        self.logger.info(f"[5/5] Running Nuclei vulnerability scans on {len(domains)} domains...")
        
        if not self.tool_manager.is_available('nuclei'):
            error_msg = "Nuclei not found. Install with: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
            self.logger.warning(error_msg)
            return [ScanResult('nuclei', self.target, False, error=error_msg)]
        
        results = []
        
        # Use ThreadPoolExecutor for parallel scanning
        with ThreadPoolExecutor(max_workers=3) as executor:
            future_to_domain = {executor.submit(self.run_nuclei_single, domain): domain for domain in domains}
            
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    result = future.result()
                    results.append(result)
                    self.logger.info(f"Completed Nuclei scan for {domain}")
                except Exception as e:
                    error_msg = f"Nuclei scan failed for {domain}: {str(e)}"
                    self.logger.error(error_msg)
                    results.append(ScanResult('nuclei', domain, False, error=error_msg))
        
        successful_scans = sum(1 for r in results if r.success)
        self.logger.info(f"Nuclei scans completed on {successful_scans}/{len(domains)} domains")
        
        return results
    
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
            'vulnerability_summary': {
                'total_findings': 0,
                'high_severity': 0,
                'critical_severity': 0,
                'medium_severity': 0,
                'low_info_severity': 0
            },
            'files_generated': [],
            'total_vulnerabilities': 0,
            'vulnerabilities_by_severity': {},
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
        
        # Count nuclei findings by severity
        nuclei_files = list(self.output_dir.glob('nuclei_*.txt'))
        for nuclei_file in nuclei_files:
            if nuclei_file.exists():
                with open(nuclei_file, 'r') as f:
                    content = f.read()
                    total_findings = len([line for line in content.split('\n') if line.strip()])
                    summary['vulnerability_summary']['total_findings'] += total_findings
                    summary['vulnerability_summary']['high_severity'] += content.lower().count('[high]')
                    summary['vulnerability_summary']['critical_severity'] += content.lower().count('[critical]')
                    summary['vulnerability_summary']['medium_severity'] += content.lower().count('[medium]')
                    summary['vulnerability_summary']['low_info_severity'] += content.lower().count('[low]') + content.lower().count('[info]')
        
        # Set total vulnerabilities and by severity
        summary['total_vulnerabilities'] = summary['vulnerability_summary']['total_findings']
        summary['vulnerabilities_by_severity'] = {
            'critical': summary['vulnerability_summary']['critical_severity'],
            'high': summary['vulnerability_summary']['high_severity'],
            'medium': summary['vulnerability_summary']['medium_severity'],
            'low': summary['vulnerability_summary']['low_info_severity']
        }
        
        # Add results for compatibility
        summary['results'] = [
            {
                'tool': result.tool,
                'target': result.target,
                'success': result.success,
                'findings_count': result.findings_count
            } for result in self.results
        ]
        
        # List generated files
        for file_path in self.output_dir.iterdir():
            if file_path.is_file():
                summary['files_generated'].append({
                    'name': file_path.name,
                    'size': file_path.stat().st_size
                })
        
        # Save summary to JSON file
        summary_file = self.output_dir / 'scan_summary.json'
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        return summary
    
    def _run_fast_scan(self, start_time) -> Dict:
        """Run fast parallel scan"""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        # Run reconnaissance tools in parallel
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {}
            
            # Submit fast recon tasks
            if self.tool_manager.is_available('porch-pirate'):
                futures[executor.submit(self.run_porch_pirate)] = 'porch-pirate'
            
            if self.tool_manager.is_available('subfinder'):
                futures[executor.submit(self.run_subfinder)] = 'subfinder'
            
            # Skip slow tools in fast mode or run with shorter timeouts
            
            # Collect results
            subdomains = [self.target]
            for future in as_completed(futures):
                tool_name = futures[future]
                try:
                    if tool_name == 'subfinder':
                        result, found_subdomains = future.result()
                        subdomains.extend(found_subdomains)
                        self.results.append(result)
                    else:
                        result = future.result()
                        self.results.append(result)
                except Exception as e:
                    self.logger.error(f"Fast scan error for {tool_name}: {e}")
        
        # Remove duplicates and limit subdomains for speed
        subdomains = list(set(subdomains))[:10]  # Limit to 10 for speed
        
        # Run Nuclei with limited templates for speed
        if self.tool_manager.is_available('nuclei'):
            nuclei_results = self.run_nuclei_fast(subdomains)
            self.results.extend(nuclei_results)
        
        return self.generate_summary()
    
    def _run_normal_scan(self, start_time) -> Dict:
        """Run normal sequential scan"""
        # Run scans sequentially
        porch_result = self.run_porch_pirate()
        self.results.append(porch_result)
        
        subfinder_result, subdomains = self.run_subfinder()
        self.results.append(subfinder_result)
        
        osmedeus_result = self.run_osmedeus()
        self.results.append(osmedeus_result)
        
        rengine_result, rengine_subdomains = self.run_rengine()
        self.results.append(rengine_result)
        
        # Combine subdomains from all sources
        all_subdomains = list(set(subdomains + rengine_subdomains))
        
        nuclei_results = self.run_nuclei_parallel(all_subdomains)
        self.results.extend(nuclei_results)
        
        return self.generate_summary()
    
    def print_summary(self, summary: Dict):
        """Print formatted summary to console"""
        print("\n" + "="*50)
        print("SCAN SUMMARY")
        print("="*50)
        print(f"Target: {summary['target']}")
        print(f"Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Results saved in: {summary['output_directory']}")
        print()
        
        # Tool results
        for tool, results in summary['scan_results'].items():
            print(f"{tool.title()} Results:")
            print(f"  Successful scans: {results['success']}")
            print(f"  Failed scans: {results['failed']}")
            print(f"  Total findings: {results['total_findings']}")
            print()
        
        # Vulnerability summary
        vuln_summary = summary['vulnerability_summary']
        print("Nuclei Vulnerability Summary:")
        print("-" * 40)
        print(f"Total findings: {vuln_summary['total_findings']}")
        print()
        print("Critical severity issues:")
        if vuln_summary['critical_severity'] > 0:
            print(f"  {vuln_summary['critical_severity']} critical issues found")
        else:
            print("  No critical severity issues found")
        
        print()
        print("High severity issues:")
        if vuln_summary['high_severity'] > 0:
            print(f"  {vuln_summary['high_severity']} high severity issues found")
        else:
            print("  No high severity issues found")
        
        print()
        print(f"Medium severity issues: {vuln_summary['medium_severity']}")
        print(f"Low/Info severity issues: {vuln_summary['low_info_severity']}")
        
        print()
        print("Files generated:")
        for file_info in summary['files_generated']:
            print(f"  {file_info['name']} ({file_info['size']} bytes)")
        
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
            summary = self._run_fast_scan(start_time)
        else:
            # Normal mode: sequential execution
            summary = self._run_normal_scan(start_time)
        
        self.logger.info("=" * 50)
        self.logger.info("Scan completed successfully!")
        self.logger.info(f"Total runtime: {summary['total_runtime']}")
        self.logger.info(f"Summary saved to: {self.output_dir / 'scan_summary.json'}")
        self.logger.info("=" * 50)
        
        return summary


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='AI-Powered Security Scanner')
    parser.add_argument('target', help='Target URL or domain to scan')
    parser.add_argument('-o', '--output', help='Output directory for results')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('-f', '--fast', action='store_true', help='Enable fast scan mode')
    parser.add_argument('--demo', action='store_true', help='Enable demo mode with guaranteed vulnerability detection')
    
    args = parser.parse_args()
    
    try:
        scanner = SecurityScanner(args.target, Path(args.output) if args.output else None, args.fast, args.verbose)
        
        # Demo mode for presentations
        if args.demo:
            scanner.demo_mode = True
            print("DEMO MODE ENABLED - Enhanced vulnerability detection for presentations")
        
        summary = scanner.run_scan()
        
        print("\n" + "="*50)
        print("SCAN SUMMARY")
        print("="*50)
        print(f"Target: {scanner.target}")
        print(f"Total Runtime: {summary.get('runtime', 'Unknown')}")
        print(f"Tools Used: {summary.get('tools_used', 'Unknown')}")
        print(f"Total Vulnerabilities Found: {summary.get('total_vulnerabilities', 0)}")
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
