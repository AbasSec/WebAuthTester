```text
 __      __      ___.       _____         __  .__     
/  \    /  \ ____\_ |__    /  _  \  __ ___/  |_|  |__  
\   \/\/   // __ \| __ \  /  /_\  \|  |  \   __\  |  \ 
 \        /\  ___/| \_\ /    |    \  |  /|  | |   Y  \
  \__/\  /  \___  >___  /\____|__  /____/ |__| |___|  /
       \/       \/    \/         \/                 \/ 
                 v2.5 - Enterprise Security Research Suite
```

**WebAuthTester Pro** — Enterprise Automated Web Security Testing Framework
Reconnaissance · Exploitation · Authorization · Intelligence

A high-performance, asynchronous Python security framework for elite bug bounty hunters and red teams.

---

## 📋 Table of Contents
- [Overview](#overview)
- [Enterprise Features](#enterprise-features)
- [Architecture](#architecture)
- [Installation & Setup](#installation--setup)
- [Usage Guide](#usage-guide)
- [Modular Architecture](#modular-architecture)
- [Reporting](#reporting)
- [Docker Security](#docker-security)
- [Legal & Ethics](#legal--ethics)

---

## 🔍 Overview
**WebAuthTester Pro v2.5** is a comprehensive, asynchronous offensive security framework designed for enterprise-scale authentication auditing. It implements a **Plugin-Based Workflow Engine** that automatically identifies authentication gateways, handles stateful CSRF tokens, and executes isolated credential validation.

---

## 🚀 Key Features (v2.5)
- 🧩 **Plugin Architecture:** Decoupled modules for Form, JSON, and OAuth2 detection.
- 🔐 **Stateful CSRF Handling:** Dynamic token extraction and rotation per-request.
- 🍪 **Session Isolation:** Fresh `ClientSession` and `CookieJar` per attempt to prevent tracking.
- 📈 **Credential Stuffing Mode:** Support for 1:1 user-to-password pairing.
- 📊 **CWE/CVSS Tagging:** Vulnerability reporting with industry-standard classification.
- 🐳 **Hardened Docker:** Multi-stage builds and non-root execution for safe deployments.
- 📋 **Structured Logging:** Full audit logs in `webauthtester.log`.

---

## 🛠️ Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/AbasSec/WebAuthTester.git
cd WebAuthTester
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Execute the Tool
```bash
python3 main.py -t https://example.com
```

---

## 📖 Usage Guide

### Basic Brute Force
```bash
python3 main.py -t https://example.com
```

### Credential Stuffing (1:1 Pairing)
```bash
python3 main.py -t https://target.com -u users.txt -p pass.txt --stuffing
```

### Stealth Mode (Randomized Jitter)
```bash
python3 main.py -t https://target.com --stealth
```

### Save Structured Report
```bash
python3 main.py -t https://target.com -o report.json
```

---

## 🧩 Modular Architecture

The framework is built on a provider-based architecture:
- **FormAuthModule:** Handles HTML forms with CSRF and session management.
- **OAuthDetectionModule:** Identifies OAuth2/OIDC/SAML flows (Reported as Out-of-Scope).
- **BaseModule:** Extensible interface for custom auth handlers.

---

## 🐳 Docker Security
Run the tool securely in a hardened container:
```bash
docker build -t webauthtester .
docker run -v $(pwd)/wordlists:/home/auditor/app/wordlists webauthtester -t https://example.com
```

---

## 📊 Reporting
Generates a professional terminal report and structured JSON/Text output with:
- **Valid Credentials:** Successfully identified logins.
- **Vulnerabilities:** Tagged with CWE IDs and CVSS scores (e.g., CWE-307 for weak lockout).

---

## ⚖️ Legal & Ethics
**WebAuthTester Pro is for authorized security testing only.**

**WebAuthTester Pro v2.5 — Built for Elite Security Research**
*AbasSec · Student of Cyber Security*
