# Bug Scan Pro 🔍

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-orange.svg)](https://github.com/lonefaisal7/bug-scan-Pro)
[![Made with ❤️](https://img.shields.io/badge/Made%20with-%E2%9D%A4%EF%B8%8F-red.svg)](https://github.com/lonefaisal7)

**Professional async-based bug host discovery and network reconnaissance toolkit for cybersecurity professionals.**

Created by **@lonefaisal** | Made with ❤️ by **@lonefaisal**

---

## 🚀 Features

### Core Capabilities
- **Async Architecture**: High-performance concurrent scanning with asyncio
- **Cross-Platform**: Supports Linux, macOS, Windows, and Android Termux
- **Multiple Output Formats**: TXT, JSON, CSV with append mode support
- **Proxy Support**: HTTP and SOCKS5 proxy integration
- **Professional CLI**: Modern command-line interface with progress bars
- **Wildcard DNS Detection**: Intelligent filtering of wildcard responses
- **Rich Console Output**: Beautiful terminal output with progress indicators

### Scanning Modules

#### 🔍 **Main Scanner** (`scan`)
- Passive subdomain discovery from Certificate Transparency and OTX
- DNS brute-force enumeration with wordlists
- Concurrent DNS resolution with wildcard detection
- Optional HTTP/HTTPS reachability testing
- Multiple output formats with append support

#### 🌐 **Advanced HTTP Scanner** (`scan-pro`)
- Multiple HTTP method support (GET, HEAD, OPTIONS, POST, etc.)
- Status code filtering (include/exclude specific codes)
- Header and response body content filtering
- Custom User-Agent support
- Rate limiting and retry logic

#### 🔍 **Pure Subdomain Finder** (`subfinder`)
- Fast subdomain enumeration without HTTP checking
- Certificate Transparency integration
- Brute-force with custom wordlists
- Clean hostname extraction

#### 🔒 **SSL/TLS Certificate Inspector** (`ssl`)
- SNI-based TLS handshake analysis
- Certificate subject and issuer extraction
- SAN (Subject Alternative Names) parsing
- Certificate chain analysis
- Expiration and validity checking

#### 📡 **Network Tools**
- **ICMP Ping Checker** (`ping`): Host availability testing
- **Port Scanner** (`ports`): TCP port enumeration with banner grabbing
- **CIDR Scanner** (`cidr`): IP range scanning with host discovery
- **DNS Lookup** (`dns`): Multi-record type DNS queries
- **Reverse PTR Lookup** (`ip-lookup`): IP to hostname resolution

#### 🛠️ **File Toolkit** (`file`)
- **Split**: Divide large files into manageable parts
- **Merge**: Combine multiple files with deduplication
- **Clean**: Extract valid hostnames using regex
- **Dedupe**: Remove duplicate entries
- **Filter**: TLD and keyword-based filtering
- **Convert**: CIDR to IP expansion, domain to IP resolution

---

## 📦 Installation

### Quick Install
```bash
# Clone the repository
git clone https://github.com/lonefaisal7/bug-scan-Pro.git
cd bug-scan-Pro

# Install dependencies
pip install -r requirements.txt

# Make executable (Linux/macOS)
chmod +x main.py
```

### Dependencies
- Python 3.8 or higher
- aiohttp >= 3.9.0
- dnspython >= 2.6.1
- rich >= 13.7.1
- icmplib >= 3.0
- tldextract >= 5.1.2
- aiohttp-socks >= 0.8.0
- uvloop >= 0.19.0 (Linux/macOS only)

---

## 🎯 Usage Examples

### Basic Subdomain Enumeration
```bash
# Basic scan with passive discovery
python3 main.py scan -d example.com -o results.txt

# With custom wordlist and more threads
python3 main.py scan -d example.com -w lists/subs-medium.txt -t 200 -o subs.txt

# JSON output with verbose logging
python3 main.py scan -d example.com --json results.json --verbose
```

### Advanced HTTP Scanning
```bash
# Scan with multiple HTTP methods
python3 main.py scan-pro -i hosts.txt --methods GET,HEAD,OPTIONS -o clean.txt

# Filter out redirects and specific status codes
python3 main.py scan-pro -i hosts.txt --non-302 --status-exclude 404,403 -o live.txt

# Header and content filtering
python3 main.py scan-pro -i hosts.txt --header-has "nginx" --contains "admin" -o filtered.txt
```

### SSL Certificate Analysis
```bash
# Single host certificate inspection
python3 main.py ssl -H example.com --json cert_info.json

# Bulk certificate analysis
python3 main.py ssl -i hosts.txt -p 443 -o ssl_results.txt
```

### Network Reconnaissance
```bash
# ICMP ping sweep
python3 main.py ping -i hosts.txt --alive-only -o alive_hosts.txt

# Port scanning
python3 main.py ports -H example.com -p 80,443,8080,8443 --json ports.json

# CIDR range scanning
python3 main.py cidr --cidr 192.168.1.0/24 -p 80,443 --alive-only -o cidr_results.txt
```

### DNS Information Gathering
```bash
# DNS record lookup
python3 main.py dns -H example.com -r A --json dns_records.json

# Reverse PTR lookup
python3 main.py ip-lookup -i ip_list.txt -o ptr_results.txt
```

### File Operations
```bash
# Split large file
python3 main.py file split -i large_list.txt --parts 5 -o split_files

# Merge and deduplicate files
python3 main.py file merge -i "file1.txt,file2.txt,file3.txt" -o merged.txt --dedupe

# Clean and extract valid hostnames
python3 main.py file clean -i raw_data.txt -o clean_hosts.txt

# Filter by TLD
python3 main.py file filter-tld -i domains.txt --tlds "com,net,org" -o filtered.txt
```

### Bulk and Advanced Operations
```bash
# Bulk domain scanning with append mode
python3 main.py scan -l domains.txt --alive-only --append -o all_results.txt

# Proxy usage
python3 main.py scan -d example.com --proxy http://127.0.0.1:8080
python3 main.py scan -d example.com --proxy socks5://127.0.0.1:9050

# Resolve-only mode (no HTTP checking)
python3 main.py scan -d example.com --resolve-only --json resolved.json

# Performance tuning
python3 main.py scan -d example.com -t 500 --timeout 15 -w lists/subs-medium.txt
```

---

## 🔧 Configuration

### Environment Variables
```bash
# AlienVault OTX API Key (optional)
export OTX_API_KEY="your-otx-api-key-here"

# Custom DNS resolvers
export DNS_RESOLVERS="1.1.1.1,8.8.8.8"
```

### Proxy Configuration
```bash
# HTTP Proxy
python3 main.py scan -d example.com --proxy http://proxy.example.com:8080

# SOCKS5 Proxy
python3 main.py scan -d example.com --proxy socks5://127.0.0.1:9050

# Authenticated Proxy
python3 main.py scan -d example.com --proxy http://user:pass@proxy.example.com:8080
```

---

## 📊 Output Formats

### TXT Format
Simple newline-separated hostnames for easy piping:
```
example.com
www.example.com
api.example.com
```

### JSON Format
Structured data with full details:
```json
{
  "root": "example.com",
  "host": "api.example.com",
  "resolved": true,
  "ips": ["93.184.216.34"],
  "http": {
    "reachable": true,
    "status": 200,
    "scheme": "https",
    "server": "nginx"
  }
}
```

### CSV Format
Tabular data for analysis:
```csv
root,host,resolved,ips,http_reachable,http_status
example.com,api.example.com,true,"93.184.216.34",true,200
```

---

## ⚡ Performance Tips

### Optimal Thread Configuration
```bash
# For VPS/dedicated servers
python3 main.py scan -d example.com -t 500

# For home connections
python3 main.py scan -d example.com -t 100

# For mobile/limited bandwidth
python3 main.py scan -d example.com -t 50
```

### Memory Usage Optimization
```bash
# Use append mode for large datasets
python3 main.py scan -l large_domains.txt --append -o results.txt

# Resolve-only mode for DNS-only operations
python3 main.py scan -d example.com --resolve-only
```

### Timeout Configuration
```bash
# Fast scanning (may miss slow hosts)
python3 main.py scan -d example.com --timeout 5

# Thorough scanning (slower but more complete)
python3 main.py scan -d example.com --timeout 30
```

---

## 🛡️ Security Features

- **SSL Certificate Bypass**: Reconnaissance mode ignores certificate errors
- **Proxy Chain Support**: Route traffic through multiple proxies
- **Custom User-Agent**: Avoid basic bot detection
- **Rate Limiting**: Respectful scanning with configurable delays
- **Stealth Options**: Randomized timing and request patterns

---

## 🚀 Advanced Usage

### Scripting and Automation
```bash
#!/bin/bash
# Automated reconnaissance pipeline

# Step 1: Subdomain discovery
python3 main.py scan -d $1 -w lists/subs-medium.txt --json step1.json

# Step 2: HTTP filtering
python3 main.py scan-pro -i step1.txt --alive-only -o step2.txt

# Step 3: SSL analysis
python3 main.py ssl -i step2.txt --json ssl_analysis.json

# Step 4: Port scanning on live hosts
python3 main.py ports -i step2.txt -p 80,443,8080,8443 --json port_scan.json
```

### Integration with Other Tools
```bash
# Pipe to other reconnaissance tools
python3 main.py scan -d example.com --alive-only | httpx -silent -mc 200
python3 main.py subfinder -d example.com | nuclei -t vulnerabilities/
```

---

## 📈 Performance Benchmarks

- **DNS Resolution**: 10,000+ subdomains per minute
- **HTTP Checking**: 1,000+ concurrent connections
- **Memory Usage**: <500MB for typical workloads
- **CIDR Scanning**: /24 networks in under 30 seconds
- **Certificate Analysis**: 100+ certificates per minute

---

## 🔍 Troubleshooting

### Common Issues

**DNS Resolution Timeouts**
```bash
# Use faster DNS servers
python3 main.py scan -d example.com --resolver 1.1.1.1

# Reduce thread count
python3 main.py scan -d example.com -t 50
```

**HTTP Connection Errors**
```bash
# Increase timeout
python3 main.py scan -d example.com --timeout 30

# Use proxy
python3 main.py scan -d example.com --proxy http://proxy:8080
```

**Memory Issues**
```bash
# Use append mode
python3 main.py scan -l domains.txt --append -o results.txt

# Process in smaller batches
python3 main.py file split -i large_list.txt --parts 10
```

### Debug Mode
```bash
# Enable verbose logging
python3 main.py scan -d example.com --verbose

# Silent mode for automated scripts
python3 main.py scan -d example.com --silent
```

---

## 🤝 Contributing

We welcome contributions! Please feel free to submit pull requests, report bugs, or suggest features.

### Development Setup
```bash
# Clone and setup development environment
git clone https://github.com/lonefaisal7/bug-scan-Pro.git
cd bug-scan-Pro
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Code Style
- Follow PEP 8 guidelines
- Use type hints for all functions
- Include comprehensive docstrings
- Maintain async/await throughout

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚖️ Legal Disclaimer

**Bug Scan Pro** is designed for **authorized security testing and educational purposes only**. Users are responsible for ensuring they have proper authorization before scanning any systems or networks.

### Ethical Usage Guidelines
- Only scan systems you own or have explicit written permission to test
- Respect rate limits and avoid overwhelming target systems
- Follow responsible disclosure practices for any vulnerabilities found
- Comply with local laws and regulations regarding network scanning
- Use responsibly and ethically in professional security assessments

---

## 📞 Support & Contact

- **Creator**: LONE FAISAL (@lonefaisal)
- **Telegram**: [@lonefaisal](https://t.me/lonefaisal)
- **GitHub**: [github.com/lonefaisal7](https://github.com/lonefaisal7)
- **Issues**: [GitHub Issues](https://github.com/lonefaisal7/bug-scan-Pro/issues)

---

## 🙏 Acknowledgments

- Certificate Transparency logs (crt.sh)
- AlienVault OTX community
- Python asyncio and aiohttp communities
- All contributors and users of Bug Scan Pro

---

## 📋 Changelog

### v1.0.0 (2025-09-18)
- Initial release
- Async-based architecture
- Multiple scanning modules
- Cross-platform support
- Professional CLI interface
- Comprehensive output formats
- Advanced filtering options
- File toolkit utilities

---

<div align="center">

**Made with ❤️ by [@lonefaisal](https://github.com/lonefaisal7)**

⭐ **Star this repository if you find it useful!** ⭐

</div>