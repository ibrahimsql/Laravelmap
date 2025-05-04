<div align="center">

# 🕸️ LaravelMap

<img src="/laravelmap.png" alt="LaravelMap Logo" width="450">

[![Go](https://img.shields.io/badge/go-v1.18+-blue.svg)](https://golang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/github/workflow/status/ibrahimsql/laravelmap/Go/main)](https://github.com/ibrahimsql/laravelmap/actions)
[![GitHub issues](https://img.shields.io/github/issues/ibrahimsql/laravelmap)](https://github.com/ibrahimsql/laravelmap/issues)

**A high-performance Laravel security scanner built with Go**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Modules](#-modules) • [Configuration](#-configuration) • [Docker](#-docker) • [Contributing](#-contributing) • [License](#-license)

</div>

## 🚀 Features

LaravelMap is a comprehensive security scanning tool specifically designed for Laravel applications. Built with performance and accuracy in mind, it helps security professionals, developers, and DevSecOps teams identify potential vulnerabilities in Laravel-based web applications.

### Core Capabilities

- **Framework Detection:** Identifies the presence of the Laravel framework on a target web application
- **Comprehensive Scanning:** Detects common web vulnerabilities with Laravel-specific context
- **WAF Detection & Bypass:** Identifies and attempts to bypass Web Application Firewalls
- **Modular Architecture:** Easily extendable with new scanning modules
- **Performance Optimized:** Written in Go for high-speed concurrent scanning
- **Detailed Reporting:** Generates reports in multiple formats (JSON, HTML, text)

### Security Scanning

- **Debug Mode Detection:** Identifies if the Laravel application's debug mode is enabled
- **Exposed Development Tools:** Detects Laravel development tools (Debugbar, Telescope, Horizon)
- **Log Injection Testing:** Checks for log injection vulnerabilities
- **Host Header Injection:** Detects if application is vulnerable to Host Header Injection
- **Livewire Detection:** Determines if the application uses Livewire and identifies version
- **PHP Version Check:** Extracts the PHP version from headers
- **WAF Detection:** Identifies presence and type of Web Application Firewalls (Cloudflare, Incapsula, Akamai, etc.)
- **WAF Bypass Techniques:** Implements various bypass methods to test WAF security

### Content Analysis

- **Form Analysis:** Detect and analyze HTML forms for potential input vectors
- **Robots.txt Analysis:** Parse and test restrictions in robots.txt files
- **Subdomain Enumeration:** Attempts to enumerate common subdomains for the target domain
- **Technology Fingerprinting:** Identifies web technologies and frameworks in use

## 📦 Installation

### Prerequisites

- [Go](https://golang.org/doc/install) (version 1.16 or later)

### From Source

```bash
# Clone the repository
git clone https://github.com/ibrahimsql/laravelmap.git

# Navigate to the project directory
cd laravelmap

# Install dependencies
go mod tidy

# Build the project
go build -o laravelmap cmd/main.go

# The binary will be available at ./laravelmap
```

## 🔧 Usage

### Basic Command

```bash
# Using the compiled binary
./laravelmap --url https://example.com
```

### Command Line Options

```
USAGE:
    laravelmap [OPTIONS] --url <URL>

OPTIONS:
    -url <URL>                  Target URL to scan (required)
    -threads <THREADS>          Number of parallel threads [default: 5]
    -timeout <TIMEOUT>          Timeout in seconds for HTTP requests [default: 30]
    -output <FILE>              Output file path for scan results
    -format <FORMAT>            Output format: text, json, html [default: text]
    -mode <MODE>                Scan mode: passive or active [default: active]
    -risk-level <LEVEL>         Risk level: low, medium, or high [default: medium]
    -categories <CATEGORIES>    Scan categories to run (comma-separated): recon,vulnerabilities,waf [default: all]
    -user-agent <AGENT>         Custom User-Agent header [default: LaravelMap Security Scanner]
    -headers <HEADERS>          Custom HTTP headers (format: 'Header1:Value1,Header2:Value2')
    -cookies <COOKIES>          Custom cookies (format: 'name1=value1,name2=value2')
    -max-depth <DEPTH>          Maximum crawling depth [default: 3]
    -exclude <PATHS>            Paths to exclude from scanning (comma-separated)
    -include <PATHS>            Only scan these paths (comma-separated)
    -waf-detection              Enable WAF detection [auto-enabled when categories includes 'waf']
    -waf-bypass                 Attempt to bypass detected WAFs
    -waf-payload <PAYLOAD>      Payload to use for WAF bypass attempts [default: <script>alert(1)</script>]
    -waf-random-ua             Use random User-Agent headers for WAF detection/bypass [default: true]
    -waf-path-mutations        Use path mutations for WAF bypass attempts [default: true]
    -verbose                    Enable verbose output
    -debug                      Enable debug mode
    -version                    Show version information
```

### Examples

```bash
# Basic scan
./laravelmap --url https://example.com

# Advanced scan with custom options
./laravelmap --url https://example.com --threads 10 --categories vulnerabilities --risk-level high --output report.json --format json

# WAF detection and bypass scan
./laravelmap --url https://example.com --categories waf --waf-bypass --waf-payload "<script>document.cookie=1</script>"

# Scan with authentication
./laravelmap --url https://example.com --auth-method form --auth-user admin --auth-pass password

# Exclude specific paths
./laravelmap --url https://example.com --exclude /admin,/api,/assets
```

## 🧩 Modules

LaravelMap includes the following modules that can be enabled or disabled as needed:

| Module Name | Description |
|-------------|-------------|
| `recon` | Reconnaissance and information gathering |
| `vulnerabilities` | Security vulnerability scanning |
| `waf` | WAF detection and bypass testing |
| `debug_mode` | Detects if Laravel debug mode is enabled |
| `log_injection` | Tests for log injection vulnerabilities |
| `authorization_bypass` | Checks for authorization bypass vulnerabilities |
| `csrf_bypass` | Tests for CSRF protection bypass |
| `deserialization` | Detects PHP deserialization vulnerabilities |
| `file_upload` | Identifies insecure file upload configurations |
| `mass_assignment` | Checks for mass assignment vulnerabilities |
| `sql_injection` | Tests for SQL injection vulnerabilities |
| `xss_scanner` | Scans for Cross-Site Scripting (XSS) vulnerabilities |
| `tools_detection` | Finds exposed Laravel development tools |
| `sensitive_files_detection` | Discovers sensitive configuration files |
| `cache_poisoning` | Tests for cache poisoning vulnerabilities |

## ⚙️ Configuration

LaravelMap can be configured using command-line parameters or by specifying options in the code:

```go
scanConfig := scanner.ScanConfig{
    Threads:         10,
    Timeout:         30 * time.Second,
    Mode:            "active",
    RiskLevel:       "medium",
    Categories:      []string{"vulnerabilities"},
    Headers:         customHeaders,
    ExcludePaths:    []string{"/admin", "/assets"},
    IncludePaths:    []string{},
    FollowRedirects: true,
    MaxDepth:        3,
    Verbose:         true,
}
```

## 🐳 Docker

LaravelMap can also be run using Docker, which eliminates the need to install Go or any other dependencies on your local machine.

### Using Docker

1. **Build the Docker image:**

   ```bash
   docker build -t laravelmap .
   ```

2. **Run a scan using Docker:**

   ```bash
   docker run --rm laravelmap -url http://example-laravel-app.com -threads 5
   ```

3. **Save scan results to your local machine:**

   ```bash
   docker run --rm -v $(pwd)/reports:/app/reports laravelmap -url http://example-laravel-app.com -output /app/reports/scan-report.json -format json
   ```

### Using Docker Compose

1. **Edit the docker-compose.yml file to specify your target URL:**

   ```yaml
   # In docker-compose.yml
   command: -url https://your-target-site.com -output /app/reports/scan-report.json -format json
   ```

2. **Run the scan using Docker Compose:**

   ```bash
   docker-compose up
   ```

3. **For interactive use:**

   ```bash
   # Uncomment the stdin_open and tty lines in docker-compose.yml
   docker-compose run --rm laravelmap -url https://your-target-site.com
   ```

### Helper Script

For convenience, you can use the provided helper script:

```bash
./scripts/docker-run.sh --url https://example.com --output report.json --format json
```

## 🤝 Contributing

Contributions are welcome and appreciated! Here's how you can contribute:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add some amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Related Projects

- [Nuclei](https://github.com/projectdiscovery/nuclei) - Fast and customizable vulnerability scanner
- [Sqlmap](https://github.com/sqlmapproject/sqlmap) -  Automatic SQL injection and database takeover tool 
- [OWASP ZAP](https://github.com/zaproxy/zaproxy) - Web application security scanner
- [WPScan](https://github.com/wpscanteam/wpscan) - WordPress security scanner.
- [WAFW00F](https://github.com/EnableSecurity/wafw00f) - Web Application Firewall detection tool
- [CDNCheck](https://github.com/projectdiscovery/cdncheck) - CDN & WAF IP detection library
---

<div align="center">

Made with ❤️ by ibrahimsql

</div>
