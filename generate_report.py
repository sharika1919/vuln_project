#!/usr/bin/env python3
"""
Generate HTML report from scan results
"""

import json
import sys
from pathlib import Path
from datetime import datetime

def generate_html_report(scan_dir: Path):
    """Generate HTML report from scan results"""
    # Read summary
    summary_path = scan_dir / "summary.json"
    if not summary_path.exists():
        print(f"Error: {summary_path} not found")
        return False
    
    with open(summary_path, 'r') as f:
        summary = json.load(f)
    
    # Read subdomains if available
    subdomains = []
    subdomains_path = scan_dir / "subdomains.txt"
    if subdomains_path.exists():
        with open(subdomains_path, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
    
    # Generate HTML
    is_vulnerable = summary.get('is_vulnerable', False)
    vuln_status = summary.get('vulnerability_status', 'UNKNOWN')
    severity_counts = summary.get('severity_counts', {})
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Scan Report - {summary['target']}</title>
    <style>
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            line-height: 1.6; 
            margin: 0; 
            padding: 0;
            color: #333;
        }}
        .container {{ 
            max-width: 1200px; 
            margin: 0 auto; 
            padding: 20px;
        }}
        .header {{ 
            background: #f8f9fa; 
            padding: 25px; 
            border-radius: 8px; 
            margin-bottom: 25px;
            border-left: 5px solid {'#e74c3c' if is_vulnerable else '#2ecc71'};
        }}
        .vuln-status {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            background: {'#ffebee' if is_vulnerable else '#e8f5e9'};
            color: {'#c62828' if is_vulnerable else '#2e7d32'};
            margin-left: 10px;
        }}
        .severity-badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 12px;
            font-weight: bold;
            margin-right: 5px;
            color: white;
        }}
        .critical {{ background: #d32f2f; }}
        .high {{ background: #f57c00; }}
        .medium {{ background: #fbc02d; color: #333; }}
        .low {{ background: #8bc34a; }}
        .info {{ background: #2196f3; }}
        .unknown {{ background: #9e9e9e; }}
        
        .section {{ 
            margin-bottom: 30px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .section-header {{
            background: #f1f3f4;
            padding: 15px 20px;
            border-bottom: 1px solid #ddd;
            font-size: 18px;
            font-weight: 600;
        }}
        .section-content {{ padding: 20px; }}
        
        .tool-result {{ 
            border-left: 4px solid #3498db;
            margin-bottom: 15px;
            background: #fff;
            border-radius: 0 4px 4px 0;
            overflow: hidden;
        }}
        .tool-result.vulnerable {{ border-left-color: #e74c3c; }}
        .tool-result-header {{
            padding: 12px 15px;
            background: #f8f9fa;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
        }}
        .tool-result-header:hover {{ background: #f1f3f4; }}
        .tool-result-title {{
            font-weight: 600;
            margin: 0;
        }}
        .tool-result-status {{
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .status-success {{ background: #e8f5e9; color: #2e7d32; }}
        .status-failed {{ background: #ffebee; color: #c62828; }}
        .status-vulnerable {{ background: #fff3e0; color: #e65100; }}
        
        .tool-result-content {{ 
            padding: 15px;
            border-top: 1px solid #eee;
            display: none;
        }}
        .tool-result.expanded .tool-result-content {{ display: block; }}
        
        .vulnerability {{
            margin-bottom: 15px;
            padding: 15px;
            background: #fff9c4;
            border-left: 3px solid #ffd600;
            border-radius: 0 4px 4px 0;
        }}
        .vulnerability.critical {{ 
            background: #ffebee; 
            border-left-color: #c62828;
        }}
        .vulnerability.high {{ 
            background: #fff3e0; 
            border-left-color: #e65100;
        }}
        .vulnerability.medium {{ 
            background: #fff8e1; 
            border-left-color: #ff8f00;
        }}
        .vulnerability.low {{ 
            background: #f1f8e9; 
            border-left-color: #558b2f;
        }}
        .vulnerability-header {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
            font-weight: 600;
        }}
        .vulnerability-desc {{
            margin: 8px 0;
            line-height: 1.5;
        }}
        
        .subdomain {{ 
            padding: 8px 12px; 
            margin: 5px 0; 
            background: #f0f8ff;
            border-left: 4px solid #3498db;
            border-radius: 0 4px 4px 0;
            display: flex;
            justify-content: space-between;
        }}
        .subdomain:hover {{ background: #e3f2fd; }}
        
        .severity-summary {{
            display: flex;
            gap: 10px;
            margin: 15px 0;
            flex-wrap: wrap;
        }}
        .severity-item {{
            padding: 8px 15px;
            border-radius: 4px;
            font-weight: 600;
            color: white;
            display: flex;
            align-items: center;
        }}
        .severity-item i {{ margin-right: 5px; }}
    </style>
    <script>
        function toggleToolResult(element) {{
            element.parentElement.classList.toggle('expanded');
        }}
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <h1 style="margin: 0;">Security Scan Report</h1>
                <span class="vuln-status">
                    {vuln_status}
                </span>
            </div>
            <p><strong>Target:</strong> {summary['target']}</p>
            <p><strong>Scan Time:</strong> {datetime.fromisoformat(summary['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}</p>
            
            <div class="severity-summary">
                {''.join(f'<div class="severity-item {severity}"><i class="fas fa-bug"></i> {severity.title()}: {count}</div>' 
                        for severity, count in severity_counts.items())}
            </div>
            
            <p><strong>Tools Run Successfully:</strong> {summary['tools_run']} of {len(summary['tools'])}</p>
            <p><strong>Total Findings:</strong> {summary['total_findings']}</p>
        </div>
        
        <!-- Subdomains Section -->
        <div class="section">
            <div class="section-header">
                Subdomains Found
                <span class="badge">{len(subdomains)}</span>
            </div>
            <div class="section-content">
                {"".join(f'<div class="subdomain">\n'
                         f'    <span>{sub}</span>\n'
                         f'    <a href="http://{sub}" target="_blank" style="color: #1976d2; text-decoration: none;">\n'
                         f'        Open <span style="font-size: 0.9em;">↗</span>\n'
                         f'    </a>\n'
                         f'</div>' for sub in subdomains) or '<p>No subdomains found</p>'}
            </div>
        </div>
        
        <!-- Tool Results Section -->
        <div class="section">
            <div class="section-header">Scan Results</div>
            <div class="section-content">
    """
    
    # Add tool results
    for tool in summary.get('tools', []):
        is_vuln = tool.get('is_vulnerable', False)
        status_class = 'status-success' if tool['success'] and not is_vuln else 'status-vulnerable' if is_vuln else 'status-failed'
        status_text = 'VULNERABLE' if is_vuln else ('SUCCESS' if tool['success'] else 'FAILED')
        
        html += f"""
        <div class="tool-result{' vulnerable' if is_vuln else ''}">
            <div class="tool-result-header" onclick="toggleToolResult(this)">
                <h3 class="tool-result-title">{tool['tool']}</h3>
                <span class="tool-result-status {status_class}">{status_text}</span>
            </div>
            <div class="tool-result-content">
                <p><strong>Status:</strong> {tool.get('output', 'No output')}</p>
        """
        
        if 'error' in tool and tool['error']:
            html += f"<p style='color: #c62828;'><strong>Error:</strong> {tool['error']}</p>"
        
        findings = [v for v in summary.get('vulnerabilities', []) 
                   if v.get('source_tool', '').lower() == tool['tool'].lower()]
        
        if findings:
            html += f"<p><strong>Findings:</strong> {len(findings)}</p>"
            for finding in findings:
                severity = finding.get('severity', 'unknown').lower()
                html += f"""
                <div class="vulnerability {severity}">
                    <div class="vulnerability-header">
                        <span>{finding.get('title', 'Vulnerability Found')}</span>
                        <span class="severity-badge {severity}">{severity.upper()}</span>
                    </div>
                    <div class="vulnerability-desc">
                        {finding.get('description', 'No description provided')}
                    </div>
                    {"<div><strong>URL:</strong> " + finding['url'] + "</div>" if 'url' in finding else ''}
                    {"<div><strong>Remediation:</strong> " + finding['remediation'] + "</div>" if 'remediation' in finding else ''}
                </div>
                """
        
        html += "</div></div>"
    
    # Close HTML
    html += """
        </div>
    </div>
</body>
</html>
"""
    
    # Save report
    report_path = scan_dir / "report.html"
    with open(report_path, 'w') as f:
        f.write(html)
    
    return report_path

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <scan_directory>")
        sys.exit(1)
    
    scan_dir = Path(sys.argv[1])
    if not scan_dir.exists():
        print(f"Error: Directory {scan_dir} not found")
        sys.exit(1)
    
    report_path = generate_html_report(scan_dir)
    if report_path:
        print(f"Report generated: {report_path}")
        print(f"Open this in your browser: file://{report_path.absolute()}")
    else:
        print("Failed to generate report")
        sys.exit(1)

if __name__ == "__main__":
    main()
