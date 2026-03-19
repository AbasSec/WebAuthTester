# WebAuthTester Pro v2.0 🛡️

**WebAuthTester Pro** is an advanced, high-concurrency authentication auditing suite designed for security researchers and academic projects. It automates the discovery, security analysis, and brute-force testing of web-based authentication systems.

Built with a modular asynchronous architecture, it handles everything from deep crawling and API heuristic detection to fuzzy-logic-based success identification.

## 🚀 Features

- **Concurrent Discovery Engine:** High-speed BFS crawler that identifies HTML forms and JSON-based API endpoints.
- **Security Auditor:** Performs real-time checks for missing security headers (HSTS, CSP, XFO), CSRF vulnerabilities, and insecure credential transmission.
- **Fuzzy Success Detection:** Uses `SequenceMatcher` to detect successful logins by comparing response similarity, bypassing dynamic content hurdles.
- **Username Enumeration:** Detects logic flaws (CWE-204) by analyzing response differences between valid and invalid users.
- **Proxy Support:** Seamless integration with Burp Suite and OWASP ZAP for traffic interception and manual analysis.
- **Academic Reporting:** Generates detailed Markdown and JSON reports suitable for academic submissions and technical audits.

## 🛠️ Quick Start

### 1. Automated Setup
```bash
chmod +x setup.sh
./setup.sh
```

### 2. Run an Audit
```bash
./WebAuthTester.py https://target-website.com
```

## 📋 Requirements
- Python 3.8+
- `aiohttp` (Async HTTP)
- `beautifulsoup4` (Advanced Parsing)
- `rich` (Terminal UI)

## ⚖️ License
This project is intended for educational and authorized security testing only. The author is not responsible for any misuse or damage caused by this tool.
