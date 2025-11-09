
# 🔍 Advanced SQL Injection Scanner

<p align="center">
  <img src="https://github.com/nasifh4s4n/W-SCAN/blob/main/Screenshot_20251109-195108.jpg" alt="SQL Scanner Dashboard" width="800"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20MacOS-green.svg" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen.svg" alt="Status">
</p>

## 🚀 Features

### 🛡️ **Security Testing Capabilities**
- **Multiple SQLi Techniques**: Union-based, Error-based, Boolean-based, Time-based attacks
- **🎯 WAF Bypass**: Advanced payload encoding and header manipulation
- **🔍 Database Extraction**: Automatic extraction of databases, tables, and columns
- **📊 Data Sampling**: Extract sample data from sensitive tables

### ⚡ **Technical Features**
- **🚀 Concurrent Scanning**: Multi-threaded parameter testing
- **📁 External Payload Support**: Load custom payloads from files
- **🎨 Professional UI**: Rich console interface with real-time progress
- **📝 Comprehensive Logging**: Detailed reports in multiple formats

### 🎯 **Advanced Detection**
- **Smart Vulnerability Detection**: Error-based, boolean-based, and time-based analysis
- **WAF Detection**: Automatic Web Application Firewall detection
- **Encoding Variations**: Multiple encoding techniques for bypassing filters

## 📦 Installation

### Prerequisites
- **Python 3.8** or higher
- **pip** package manager

### Quick Setup
```bash
# Clone the repository
git clone https://github.com/nasifh4s4n/W-SCAN.git
cd W-SCAN

# Install dependencies
pip install -r requirements.txt

# Run the scanner
python Wscan.py
```


🎮 Usage

Basic Usage

```bash
python Wscan.py
```

Interactive Workflow

1. 🎯 Enter Target URL
   ```
   Enter the target URL (e.g., http://example.com/page.php?id=1):
   http://testphp.vulnweb.com/artists.php?artist=1
   ```
2. ⚙️ Select Scan Mode
   ```
   Select scan mode:
   1. Quick Scan (Fast, basic tests)
   2. Comprehensive Scan (Slow, thorough tests with DB extraction)
   ```
3. 📁 Optional: External Payloads
   ```
   Load external payloads? (y/n): y
   Enter path to payload file: custom_payloads.txt
   ```
4. 🚀 Start Scanning
   ```
   Press Enter to start scanning...
   ```

Example Output

```
[*] Scanning parameter: artist
[+] VULNERABLE: artist
    Payload: ' UNION SELECT 1,2,3 --
    Technique: url_encode
    URL: http://testphp.vulnweb.com/artists.php?artist=1'%20UNION%20SELECT%201,2,3%20--

[*] Starting advanced database extraction...
[+] Found 3 databases using mixed_case technique
[+] Found 5 tables in database: acuart
[+] Extracted sample data from users table
```

📁 Project Structure

```
sql-scanner/
├── 📄 Wscan.py          # Main scanner script
├── 📄 requirements.txt        # Python dependencies
├── 📄 README.md              # This file
├── 📁 payloads/              # Custom payload directory
│   ├── basic_payloads.txt    # Basic SQL injection payloads
│   └── waf_bypass.txt        # WAF bypass payloads
├── 📁 logs/                  # Scan logs directory
│   ├── scan_1701234567.txt   # Timestamped scan logs
│   └── extracted_data.json   # Extracted database info
└── 📁 examples/              # Usage examples
```

🛠️ Configuration

Scan Modes

Mode Speed Tests DB Extraction Recommended Use
Quick 🚀 Fast Basic payloads ❌ No Initial reconnaissance
Comprehensive 🐢 Thorough All payloads + WAF bypass ✅ Yes Deep penetration testing

Custom Payload Files

Create your own payload files with one payload per line:

```txt
# custom_payloads.txt
# Basic authentication bypass
' OR '1'='1' --
admin'--

# Union-based injections  
' UNION SELECT 1,2,3 --

# Time-based blind
' AND SLEEP(5)--

# WAF bypass
'/**/OR/**/'1'='1'--
```

Log Files

Scan results are saved in multiple formats:

· 📄 Text logs: Human-readable scan results
· 📊 JSON files: Structured extracted data
· 📋 Summary reports: Vulnerability overview

Sample Log Entry

```log
[2024-01-01 12:00:00] VULNERABLE PARAMETER: id
    Payload: ' UNION SELECT 1,@@version,3 --
    Technique: url_encode
    URL: http://example.com/page.php?id=1'%20UNION%20SELECT%201,@@version,3%20--
```

🛡️ WAF Bypass Techniques

The scanner employs multiple WAF bypass methods:

🔄 Encoding Techniques

· URL Encoding: Standard percent encoding
· Double URL Encoding: Double-encoded payloads
· Unicode Encoding: Unicode character representation
· HTML Entities: HTML entity encoding

🎭 Obfuscation Methods

· Case Variation: Random upper/lower case
· Comment Injection: SQL comment obfuscation
· White Space: Tab and newline injection
· Null Bytes: Null byte injection

🌐 Header Manipulation

· IP Spoofing: X-Forwarded-For header rotation
· User-Agent Rotation: Random user agent strings
· Custom Headers: Additional random headers

⚠️ Legal Disclaimer

🚨 IMPORTANT: LEGAL NOTICE

This tool is designed for:

· ✅ Authorized penetration testing
· ✅ Educational purposes
· ✅ Security research
· ✅ Vulnerability assessment on systems you own

❌ PROHIBITED USES:

· Unauthorized testing on systems you don't own
· Malicious attacks
· Illegal activities

Developers are not responsible for misuse. Always obtain proper authorization before scanning.

🐛 Troubleshooting

Common Issues

Issue Solution
ModuleNotFoundError Run pip install -r requirements.txt
SSL Certificate Errors Use --verify-ssl=false (not recommended)
Connection Timeouts Check target availability and firewall settings
No Vulnerabilities Found Try comprehensive scan mode with WAF bypass

Performance Tips

· Use quick scan for initial testing
· Limit threads for sensitive targets
· Use custom payloads for specific applications
· Monitor logs for false positives/negatives

🤝 Contributing

We welcome contributions! Please:

1. 🍴 Fork the repository
2. 🌿 Create a feature branch
3. 💻 Make your changes
4. 📝 Add tests if applicable
5. 🔧 Submit a pull request

Development Setup

```bash
git clone https://github.com/nasifh4s4n/W-SCAN.git
cd sql-scanner
python -m venv venv
source venv/bin/activate  # Linux/Mac
# OR
venv\Scripts\activate    # Windows
pip install -r requirements.txt
```

📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

🙏 Acknowledgments

· Security Researchers for SQL injection techniques
· Python Community for excellent libraries
· Open Source Tools that inspired this project

---

<p align="center">
  <strong>Made with ❤️ for the newcomers</strong>
</p>

<p align="center">
  <sub>If you find this tool helpful, please give it a ⭐!</sub>
</p>

