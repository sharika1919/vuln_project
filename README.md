# AI-Powered Security Scanner

A next-generation, AI-enhanced security scanning solution that combines multiple security tools with artificial intelligence to provide comprehensive vulnerability assessment and security posture analysis.

## 🔍 Overview

This AI-powered security scanner is designed to automate and enhance the process of vulnerability assessment by integrating multiple security tools with machine learning capabilities. It provides a unified interface for comprehensive security testing, from reconnaissance to vulnerability detection and risk assessment.

## 🚀 Key Features

- **AI-Powered Vulnerability Detection**: Uses machine learning to identify and prioritize security risks
- **Comprehensive Scanning**: Combines multiple security tools for thorough assessment
- **Smart Template Selection**: AI selects optimal scanning templates based on target analysis
- **False Positive Reduction**: Advanced filtering to minimize false positives
- **Detailed Reporting**: Generates comprehensive security reports with AI-generated insights
- **Demo Mode**: Special mode for presentations and testing with simulated vulnerabilities

## 🛠️ Integrated Security Tools

### 1. **Nuclei**
- **Purpose**: Fast and customizable vulnerability scanner
- **Why we use it**: Provides extensive template-based scanning for known vulnerabilities
- **AI Enhancement**: AI selects and prioritizes templates based on target analysis

### 2. **Subfinder**
- **Purpose**: Subdomain discovery tool
- **Why we use it**: Identifies all possible subdomains to expand the attack surface
- **AI Enhancement**: Analyzes subdomain patterns to identify high-value targets

### 3. **Porch-pirate**
- **Purpose**: OSINT and reconnaissance tool
- **Why we use it**: Gathers intelligence about the target from public sources
- **AI Enhancement**: Processes and correlates OSINT data for better context

### 4. **ReNgine (built-in fallback)**
- **Purpose**: Automated reconnaissance framework
- **Why we use it**: Provides additional enumeration capabilities
- **AI Enhancement**: Prioritizes findings based on potential impact

## 🤖 AI/ML Components

### 1. **Target Intelligence Analysis**
- Analyzes target characteristics (tech stack, services, etc.)
- Identifies high-risk areas and potential attack vectors
- Selects optimal scanning templates based on target profile

### 2. **Vulnerability Risk Assessment**
- Uses machine learning models to assess vulnerability severity
- Reduces false positives through contextual analysis
- Provides AI-generated risk scores and recommendations

### 3. **Smart Template Selection**
- Dynamically selects and prioritizes scanning templates
- Adapts scanning strategy based on initial findings
- Optimizes scan time while maintaining thorough coverage

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Go 1.17+ (for Nuclei and Subfinder)
- jq (for JSON processing)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/sharika1919/hack_proj.git
cd hack_proj
```

2. **Install Python dependencies**
```bash
pip install -r requirements.txt
```

3. **Install required tools**
```bash
# Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Install Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install Porch-pirate
pip install porch-pirate

# Install jq (macOS)
brew install jq
# Or on Ubuntu/Debian: sudo apt-get install jq
```

### Basic Usage

```bash
# Run a comprehensive security scan
python3 auto_scanner.py example.com

# Run in fast mode (limited templates)
python3 auto_scanner.py example.com --fast

# Enable verbose output
python3 auto_scanner.py example.com --verbose

# Run in demo mode (for presentations)
python3 auto_scanner.py example.com --demo
```

## 🏗️ System Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                    AI Security Scanner                        │
├───────────────┬───────────────────────┬──────────────────────┤
│  Recon Phase  │  Vulnerability Phase  │   Analysis Phase     │
│  • Subfinder  │   • Nuclei Scanning   │  • AI Risk Scoring   │
│  • OSINT      │   • Template Selection│  • False +ve Filter  │
│  • Enumeration│   • Custom Templates  │  • Report Generation │
└───────┬───────┴───────────┬───────────┴──────────┬───────────┘
        │                   │                       │
        ▼                   ▼                       ▼
┌───────────────────────────────────────────────────────────────┐
│                     AI Engine & Analysis                      │
│  • Target Profiling  • Vulnerability Correlation             │
│  • Risk Assessment  • Report Generation                      │
└───────────────────────────────────────────────────────────────┘
```

## 🔍 Real-World Applications

### 1. **Enterprise Security**
- Continuous security monitoring of web applications
- Pre-production security testing
- Third-party vendor risk assessment

### 2. **Bug Bounty Programs**
- Automated initial reconnaissance
- Vulnerability discovery and validation
- Attack surface mapping

### 3. **Compliance & Auditing**
- Automated compliance checking
- Security posture assessment
- Risk management and reporting

### 4. **Security Research**
- New vulnerability discovery
- Security tool testing
- Attack pattern analysis

## 🎯 Why AI in Security Scanning?

1. **Reduced False Positives**
   - AI helps distinguish between actual vulnerabilities and false positives
   - Context-aware analysis reduces noise in scan results

2. **Intelligent Scanning**
   - Adapts scanning strategy based on target characteristics
   - Focuses on high-risk areas first

3. **Automated Triage**
   - Prioritizes findings based on potential impact
   - Provides actionable insights and remediation guidance

4. **Efficiency**
   - Reduces manual effort in vulnerability assessment
   - Speeds up the security review process

## 📊 Output & Reporting

The scanner generates comprehensive reports in the `scan_results/` directory, including:

- **AI Scan Summary**: Executive overview with risk assessment
- **Vulnerability Analysis**: Detailed findings with risk scores
- **Template Selection**: AI's reasoning for template choices
- **Executive Summary**: Business-level security assessment

### Example Report Structure
```
scan_results/
└── example.com-2025-09-14_11-23-10/
    ├── ai_scan_summary.json        # Complete scan results
    ├── ai_vulnerability_analysis.json  # AI-analyzed vulnerabilities
    ├── ai_template_selection.json  # AI template selection reasoning
    ├── executive_summary.txt       # Business-friendly report
    └── scan.log                   # Detailed scan log
```

## 🛡️ Security Considerations

- **Ethical Use**: Only scan systems you own or have permission to test
- **Rate Limiting**: Built-in rate limiting to avoid overwhelming targets
- **Sensitive Data**: Be cautious when scanning production environments
- **Legal Compliance**: Ensure compliance with local laws and regulations

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) for details on how to submit pull requests.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Project Discovery for Nuclei and Subfinder
- The open-source security community
- All contributors and testers

## Output Structure

The script creates a timestamped directory under `scan_results/` with the following structure:

```
scan_results/
└── example.com-2025-09-13_14-30-15/
    ├── porch_pirate.json          # Porch-pirate reconnaissance results
    ├── subdomains.txt             # Subfinder subdomain discovery results
    ├── nuclei_example.com.txt     # Nuclei vulnerability scan for main domain
    ├── nuclei_api.example.com.txt # Nuclei scan for discovered subdomains
    ├── nuclei_www.example.com.txt # Additional subdomain scans
    ├── scan_summary.json          # Comprehensive scan summary
    └── scan.log                   # Detailed execution log
```

## Features

- **Cross-platform compatibility**: Works on Windows, macOS, and Linux
- **Professional logging**: Separate console and file logs with configurable levels
- **Parallel processing**: Concurrent Nuclei scans for faster execution
- **Intelligent subdomain handling**: Extracts subdomains from Subfinder and scans each with Nuclei
- **Comprehensive reporting**: JSON summary with vulnerability breakdown by severity
- **Error handling**: Graceful degradation when tools are missing
- **Configurable settings**: JSON-based configuration system
- **Type safety**: Full Python type hints for better code quality

## Summary Report

The script provides a detailed summary including:
- Total vulnerability findings
- High and critical severity issues (highlighted)
- Medium and low severity issue counts
- File sizes and locations

## Troubleshooting

### Common Issues

1. **Tool not found errors**: Install the missing tools using the instructions above
2. **Permission denied**: Make sure the script is executable with `chmod +x auto_scan.sh`
3. **No subdomains found**: Subfinder might not find subdomains for some domains - the script will scan the main domain only
4. **JSON parsing errors**: Ensure `jq` is installed for proper output parsing

### Verification

Test if tools are properly installed:
```bash
# Check if tools are available
which porch-pirate
which subfinder
which nuclei
which jq
```

## Security Note

This tool is intended for authorized security testing only. Always ensure you have proper permission before scanning any domain or system.

## License

This script is provided as-is for educational and authorized security testing purposes.
