# Vulnerability Scanner and Auto Scanner

A powerful security scanning solution that combines automated vulnerability detection with intelligent scanning capabilities. This project includes two main components:

1. **Vulnerability Scanner** (`vuln_scanner.py`): A focused tool for detecting security vulnerabilities in web applications.
2. **Auto Scanner** (`auto_scanner_simple.py`): An automated scanner that integrates multiple security tools for comprehensive vulnerability assessment.

## 🔍 Overview

This project provides a comprehensive security scanning solution that combines automated vulnerability detection with intelligent scanning capabilities. The `vuln_scanner.py` focuses on detecting specific web vulnerabilities, while `auto_scanner_simple.py` provides a more comprehensive scanning solution by integrating multiple open-source security tools.

## 🚀 Key Features

### Vulnerability Scanner
- **SQL Injection Detection**: Advanced detection of SQL injection vulnerabilities with reduced false positives
- **XSS Detection**: Identifies potential Cross-Site Scripting vulnerabilities
- **Directory Traversal**: Checks for path traversal vulnerabilities
- **Sensitive Data Exposure**: Identifies potential information leaks
- **HTML Reporting**: Generates detailed HTML reports of findings

### Auto Scanner
- **Subdomain Discovery**: Finds subdomains using Subfinder
- **Cloud Service Enumeration**: Identifies cloud services and configurations
- **Containerized Scanning**: Supports Docker-based tool execution
- **Smart Target Analysis**: Identifies well-known secure sites to reduce false positives
- **Comprehensive Reporting**: Saves detailed scan results for analysis

## 🛠️ Integrated Open Source Tools (auto_scanner_simple.py)

### 1. **Subfinder**
- **Purpose**: Fast and efficient subdomain discovery
- **Usage**: Used to enumerate subdomains of the target domain
- **Installation**: `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
- **Integration**: Automatically discovers subdomains as part of the scanning process

### 2. **Porch Pirate**
- **Purpose**: Cloud service enumeration and reconnaissance
- **Usage**: Identifies cloud services and potentially sensitive configurations
- **Installation**: `pip install porch-pirate`
- **Integration**: Scans for cloud service configurations and potential leaks

### 3. **Docker**
- **Purpose**: Containerization for security tools
- **Usage**: Runs security tools in isolated containers
- **Installation**: [Docker Installation Guide](https://docs.docker.com/get-docker/)
- **Integration**: Used to run tools like ReNgine and Osmedeus in containers

### 4. **ReNgine** (via Docker)
- **Purpose**: Comprehensive web application scanner
- **Usage**: Performs in-depth security scanning of web applications
- **Installation**: Requires Docker
- **Integration**: Called automatically for comprehensive scanning when available

### 5. **Osmedeus** (via Docker)
- **Purpose**: Automated security tool for reconnaissance and vulnerability scanning
- **Usage**: Performs automated security scanning
- **Installation**: Requires Docker
- **Integration**: Used for additional scanning capabilities when available

## 🔧 Installation

### Prerequisites
- Python 3.8+
- Go 1.17+ (for Subfinder)
- Docker (optional, for containerized tools)
- jq (for JSON processing)

### Setup

1. **Clone the repository**
```bash
git clone https://github.com/sharika1919/vuln_project.git
cd vuln_project
```

2. **Install Python dependencies**
```bash
pip install -r requirements.txt
```

3. **Install required tools**
```bash
# Install Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install Porch-pirate
pip install porch-pirate

# Install jq (macOS)
brew install jq
# Or on Ubuntu/Debian: sudo apt-get install jq
```

## 🚀 Usage

### Vulnerability Scanner
```bash
# Run vulnerability scan on a target URL
python3 vuln_scanner.py http://example.com

# Save results to a specific directory
python3 vuln_scanner.py http://example.com --output custom_output_dir
```

### Auto Scanner
```bash
# Basic scan
python3 auto_scanner_simple.py example.com

# Scan with specific output directory
python3 auto_scanner_simple.py example.com --output custom_scan_results
```

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
│                  Vulnerability Scanner                        │
├───────────────────────┬───────────────────────────────────────┤
│  Vulnerability Tests  │  Auto Scanner Integration            │
│  • SQL Injection     │  • Subdomain Discovery (Subfinder)    │
│  • XSS Detection     │  • Cloud Service Enumeration          │
│  • Directory Traversal│  • Containerized Tool Execution      │
│  • Sensitive Data    │  • Comprehensive Reporting            │
└───────────┬──────────┴───────────────────────────┬───────────┘
            │                                       │
            ▼                                       ▼
┌─────────────────────────┐           ┌─────────────────────────┐
│  HTML Report Generator  │           │  Scan Results Analysis  │
│  • Detailed Findings    │           │  • Results Correlation  │
│  • Vulnerability Details│           │  • False Positive Check │
│  • Remediation Guidance │           └───────────────┬─────────┘
└─────────────────────────┘                           │
            │                                       │
            └───────────────────────────────────────┘
```

## 📊 Output & Reporting

### Vulnerability Scanner
Generates detailed HTML reports in the `reports` directory with:
- Vulnerability details and severity levels
- Affected URLs and parameters
- Proof of concept for identified issues
- Remediation recommendations

### Auto Scanner
Saves comprehensive scan results in the `scan_results` directory, including:
- Subdomain enumeration results
- Cloud service configurations
- Security scan findings
- Tool-specific output files

## 🔒 Security Considerations

- **Ethical Use**: Only scan systems you own or have permission to test
- **Rate Limiting**: Be mindful of target server load
- **Sensitive Data**: Review scan results carefully for sensitive information
- **Legal Compliance**: Ensure compliance with all applicable laws and regulations

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Thanks to all the open-source tools that make this project possible
- Special thanks to the security community for their contributions and support

## 📝 License

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
