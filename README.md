# WebAuthTester Pro v2.2 🛡️

[![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-supported-blue.svg)](https://www.docker.com/)
[![CI/CD](https://github.com/AbasSec/WebAuthTester/actions/workflows/tests.yml/badge.svg)](https://github.com/AbasSec/WebAuthTester/actions)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**WebAuthTester Pro** is a high-concurrency, asynchronous authentication auditing framework. Designed for security researchers and enterprise-level penetration testing, it automates the discovery, security analysis, and credential validation of web authentication gateways using fuzzy-logic differential analysis.

---

## 📸 Interface Preview

```text
 __      __      ___.       _____         __  .__     
/  \    /  \ ____\_ |__    /  _  \  __ ___/  |_|  |__  
\   \/\/   // __ \| __ \  /  /_\  \|  |  \   __\  |  \ 
 \        /\  ___/| \_\ /    |    \  |  /|  | |   Y  \
  \__/\  /  \___  >___  /\____|__  /____/ |__| |___|  /
       \/       \/    \/         \/                 \/ 
                 v2.2 - Enterprise Security Research Suite
```

---

## ✨ Enterprise-Grade Features

- 🏗️ **Modular Architecture:** Clean, decoupled Python package structure for maximum extensibility.
- 🚀 **Asynchronous Core:** Non-blocking I/O engine built on `asyncio` for high-speed concurrent auditing.
- 🔍 **Intelligent Discovery:** Multi-worker BFS crawler that identifies HTML forms and "invisible" API endpoints.
- 🧠 **Fuzzy-Logic Detection:** Uses **Gestalt Pattern Matching** to detect successful logins by analyzing response body similarity ratios.
- 🛡️ **Security Configuration Audit:** Automated checks for HSTS, CSP, X-Frame-Options, CSRF, and SSL/TLS integrity.
- 🐳 **Containerized Deployment:** Full Docker & Docker-Compose support for consistent environment execution.
- 🧪 **Automated QA:** Integrated CI/CD pipeline via GitHub Actions with a comprehensive `pytest` suite.
- 📝 **Professional Reporting:** Generates detailed Markdown and JSON reports for every audit session.

---

## 🚀 Installation & Setup

### Option 1: Docker (Recommended)
Deploy instantly without managing local Python dependencies.
```bash
docker-compose up --build
```

### Option 2: Automated Setup (Linux/macOS)
Creates a virtual environment and installs all dependencies automatically.
```bash
chmod +x setup.sh
./setup.sh
```

### Option 3: Manual Installation
```bash
pip install -r requirements.txt
```

---

## ⚙️ Configuration

The tool supports professional configuration management via `config.yaml`. You can define targets, wordlists, concurrency, and proxy settings in one place.

```yaml
target: "https://example.com"
concurrency: 20
wordlists:
  usernames: "wordlists/usernames.txt"
  passwords: "wordlists/passwords.txt"
```

---

## 📖 Usage Guide

Run the tool using the wrapper or the main entry point:

```bash
# Basic Audit
./WebAuthTester.py https://target.com

# Audit with Proxy (e.g. Burp Suite)
./WebAuthTester.py https://target.com -x http://127.0.0.1:8080

# Audit with custom wordlists
./WebAuthTester.py https://target.com -u users.txt -p pass.txt
```

---

## 📊 Technical Reports & Documentation

This repository includes high-level documentation suitable for academic and professional review:

1.  **[Technical Dissertation (Deep Dive)](RAPTOR-PRO_OFFICIAL_REPORT.md):** A detailed whitepaper covering the system's architecture, fuzzy-logic algorithms, and performance analysis.
2.  **[Comprehensive Usage Guide](MODULES_USAGE_GUIDE.md):** A manual detailing every command-line argument and deployment scenario.
3.  **Session Reports:** Every audit generates a timestamped report in the `reports/` directory (JSON/Markdown) detailing specific vulnerabilities found.

---

## ⚖️ Disclaimer
This tool is for **authorized security testing** and **educational purposes only**. Unauthorized use against targets without prior written consent is illegal. The developer assumes no liability for misuse.
