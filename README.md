# WebAuthTester Pro v2.2 🛡️

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Educational-green.svg)](LICENSE)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/AbasSec/WebAuthTester/graphs/commit-activity)

**WebAuthTester Pro** is a high-performance, asynchronous authentication auditing suite designed for security researchers. It automates the discovery, configuration auditing, and credential testing of web-based authentication gateways.

---

## ✨ Key Features

- 🚀 **Asynchronous Engine:** High-concurrency BFS crawler and brute-force engine built on `asyncio`.
- 🔍 **Intelligent Discovery:** Automatically maps HTML forms and heuristic API endpoints.
- 🧠 **Fuzzy Logic Detection:** Uses `SequenceMatcher` to identify successful logins by analyzing response body similarity.
- 🛡️ **Security Audit:** Performs automated checks for SSL/TLS, Security Headers, and CSRF protection.
- 📊 **Professional UI:** Rich terminal interface with ASCII art, progress bars, and formatted result tables.
- 📝 **Dual Reporting:** Generates comprehensive Markdown and JSON reports for documentation.

---

## 📸 Interface Preview

```text
 __      __      ___.       _____         __  .__     
/  \    /  \ ____\_ |__    /  _  \  __ ___/  |_|  |__  
\   \/\/   // __ \| __ \  /  /_\  \|  |  \   __\  |  \ 
 \        /\  ___/| \_\ \/    |    \  |  /|  | |   Y  \
  \__/\  /  \___  >___  /\____|__  /____/ |__| |___|  /
       \/       \/    \/         \/                 \/ 
                 v2.2 - Advanced Auth Auditing Suite
```

---

## 🚀 Installation & Setup

### 1. Automated Setup
```bash
git clone https://github.com/AbasSec/WebAuthTester.git
cd WebAuthTester
chmod +x setup.sh
./setup.sh
```

### 2. Manual Installation
```bash
pip install aiohttp rich beautifulsoup4
```

---

## 📖 Usage Guide

```bash
usage: WebAuthTester.py [-h] [-u USERLIST] [-p PASSLIST] [-c CONCURRENCY] [-x PROXY] target

WebAuthTester Pro v2.2 - Advanced Authentication Auditing Suite

positional arguments:
  target                Target URL (e.g., https://example.com)

🎯 TARGET CONFIGURATION:
  target                Target URL (e.g., https://example.com)

📂 WORDLISTS:
  -u USERLIST, --userlist USERLIST
                        Path to username wordlist (default: wordlists/usernames.txt)
  -p PASSLIST, --passlist PASSLIST
                        Path to password wordlist (default: wordlists/passwords.txt)

⚡ PERFORMANCE & STEALTH:
  -c CONCURRENCY, --concurrency CONCURRENCY
                        Number of concurrent connections (default: 10)
  -x PROXY, --proxy PROXY
                        HTTP proxy to route traffic through (e.g. http://127.0.0.1:8080)
```

### Examples:
- **Basic Audit:** `./WebAuthTester.py https://target.com`
- **Fast Audit:** `./WebAuthTester.py https://target.com -c 30`
- **Proxy/Burp Integration:** `./WebAuthTester.py https://target.com -x http://127.0.0.1:8080`

---

## ⚖️ Disclaimer
This tool is for **authorized security testing** and **educational purposes only**. The developer assumes no liability for misuse or damage caused by this program.
