#!/usr/bin/env python3
"""
Test the reconnaissance tool against intentionally vulnerable websites
"""

import subprocess
import json
import time
from pathlib import Path
from typing import List, Dict, Any

# List of intentionally vulnerable test sites
VULNERABLE_SITES = [
    "testphp.vulnweb.com",  # Acunetix test site
    "testhtml5.vulnweb.com",
    "demo.testfire.net",  # Altoro Mutual demo bank
    "zero.webappsecurity.com",  # Zero Bank demo site
    "juice-shop.herokuapp.com"  # OWASP Juice Shop
]

def run_recon(target: str) -> Dict[str, Any]:
    """Run the reconnaissance tool against a target"""
    print(f"\n{'='*50}")
    print(f"Testing against: {target}")
    print(f"{'='*50}")
    
    # Create output directory
    output_dir = Path("test_results") / target
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Build the command
    cmd = [
        "python3", "auto_scanner.py",
        target,
        "-o", str(output_dir),
        "-v"  # Verbose output
    ]
    
    try:
        print(f"Starting reconnaissance on {target}...")
        start_time = time.time()
        
        # Run the command
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=1800  # 30 minutes timeout
        )
        
        # Calculate runtime
        runtime = time.time() - start_time
        
        # Parse results
        summary_file = output_dir / "scan_summary.json"
        if summary_file.exists():
            with open(summary_file, 'r') as f:
                summary = json.load(f)
        else:
            summary = {
                "status": "error",
                "error": "No summary file generated"
            }
        
        # Add runtime and output
        summary["runtime_seconds"] = runtime
        summary["stdout"] = result.stdout
        summary["stderr"] = result.stderr
        
        # Print summary
        print(f"\n[+] Reconnaissance completed in {runtime:.1f} seconds")
        print(f"[+] Results saved to: {output_dir}")
        
        if "scan_results" in summary:
            print("\nScan Results:")
            for tool, stats in summary["scan_results"].items():
                if stats.get("success", 0) > 0:
                    print(f"  {tool.upper()}: {stats.get('total_findings', 0)} findings")
        
        return summary
        
    except subprocess.TimeoutExpired:
        print(f"[!] Reconnaissance timed out after 30 minutes for {target}")
        return {
            "status": "timeout",
            "target": target,
            "error": "Command timed out after 30 minutes"
        }
    except Exception as e:
        print(f"[!] Error during reconnaissance: {str(e)}")
        return {
            "status": "error",
            "target": target,
            "error": str(e)
        }

def main():
    """Main function to test against vulnerable sites"""
    print("AI-Powered Reconnaissance Tool - Test Suite")
    print("Testing against intentionally vulnerable websites\n")
    
    results = []
    
    for site in VULNERABLE_SITES:
        result = run_recon(site)
        results.append({"target": site, "result": result})
    
    # Print final summary
    print("\n" + "="*50)
    print("TEST SUMMARY")
    print("="*50)
    
    for item in results:
        target = item["target"]
        result = item["result"]
        
        status = result.get("status", "unknown")
        runtime = result.get("runtime_seconds", 0)
        
        print(f"\n{target}:")
        print(f"  Status: {status.upper()}")
        print(f"  Runtime: {runtime:.1f} seconds")
        
        if "scan_results" in result:
            print("  Findings:")
            for tool, stats in result["scan_results"].items():
                if stats.get("success", 0) > 0:
                    print(f"    {tool.upper()}: {stats.get('total_findings', 0)} findings")
        
        if "error" in result:
            print(f"  Error: {result['error']}")
    
    print("\nTesting complete!")

if __name__ == "__main__":
    main()
