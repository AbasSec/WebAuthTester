```text
 __      __      ___.       _____         __  .__     
/  \    /  \ ____\_ |__    /  _  \  __ ___/  |_|  |__  
\   \/\/   // __ \| __ \  /  /_\  \|  |  \   __\  |  \ 
 \        /\  ___/| \_\ /    |    \  |  /|  | |   Y  \
  \__/\  /  \___  >___  /\____|__  /____/ |__| |___|  /
       \/       \/    \/         \/                 \/ 
                 v2.2 - Enterprise Security Research Suite
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
- [Professional Modules](#professional-modules)
- [Reporting](#reporting)
- [Legal & Ethics](#legal--ethics)

---

## 🔍 Overview
**WebAuthTester Pro v2.2** is a comprehensive, Kali Linux-native offensive security framework designed for enterprise-scale authentication auditing. It implements an Intelligent Workflow Engine that automatically identifies authentication gateways, analyzes their behavior using fuzzy-logic, and executes high-concurrency credential validation.

Target → Recon → Gateway Discovery → Baseline Analysis → Fuzzy-Logic Brute Audit → Final Report

---

## 🚀 Enterprise Features
| Feature | Details |
| :--- | :--- |
| **Workflow Engine** | Stateful pipeline that chains discovery findings with active testing phases. |
| **Async Performance** | Massive concurrency via `asyncio` for high-speed auditing with low memory footprint. |
| **Gateway Discovery** | Multi-worker BFS crawler that identifies HTML forms, SPA components, and API endpoints. |
| **Firebase Intelligence** | Built-in support for Google Identity Toolkit and modern serverless auth APIs. |
| **Fuzzy-Logic Detection** | Uses Gestalt Pattern Matching to detect success via response similarity differentials. |
| **WAF Evasion** | Configurable stealth modes with request jitter and randomized headers. |

---

## 🏗️ Architecture
```text
WebAuthTester/
├── WebAuthTester.py          ← Main CLI Entry Point
├── config.yaml               ← Global Scan Configuration
├── main.py                   ← Orchestration Logic
├── webauthtester/
│   ├── core/
│   │   ├── engine.py         ← Discovery & Brute Force Engines
│   │   ├── models.py         ← Data Structures & Baselines
│   │   └── utils.py          ← UI & Terminal Formatting
├── wordlists/
│   ├── usernames.txt         ← Optimized User Wordlist
│   ├── passwords.txt         ← Optimized Password Wordlist
│   └── test_pass.txt         ← Rapid Verification Wordlist
└── tests/                    ← Integrated Pytest Suite
```

---

## 🛠️ Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/AbasSec/WebAuthTester.git
cd WebAuthTester
```

### 2. Automated Environment Setup
The `setup.sh` script creates a virtual environment, installs dependencies, and generates default wordlists.
```bash
chmod +x setup.sh
./setup.sh
```

### 3. Activate Environment (If using venv)
```bash
source venv/bin/activate
```

---

## 📖 Usage Guide

Running the tool without arguments displays the help menu and usage examples.

### Basic Audit
Automatically discover forms and audit with default wordlists:
```bash
python3 WebAuthTester.py -t https://example.com
```

### Targeted API Audit (REST / JSON)
Directly target a specific API endpoint with custom wordlists and intelligent JSON payload mapping:
```bash
python3 WebAuthTester.py -t "https://api.example.com/v1/auth/login" \
  -u wordlists/usernames.txt \
  -p wordlists/passwords.txt
```

### Advanced Usage Examples
- **High Speed Audit:** `python3 WebAuthTester.py -t https://target.com -c 50`
- **Proxy via Burp Suite:** `python3 WebAuthTester.py -t https://target.com -x http://127.0.0.1:8080`
- **Custom Config File:** `python3 WebAuthTester.py -t https://target.com --config my_audit.yaml`

### Advanced Options
- **Concurrency:** Increase speed with `-c` (Default: 10).
- **Proxy:** Route traffic through a proxy with `-x`.
- **Stealth:** Enable `--stealth` to add jitter and bypass behavioral WAFs.

---

## 🧠 Professional Modules

### 1. Discovery Engine
The discovery module uses a recursive crawler to find:
- Standard HTML `<form>` elements.
- Modern SPA login components (React/Vue/Angular).
- "Naked" input fields sitting directly in the DOM.
- Hidden Firebase API configurations in Javascript files.

### 2. Brute Force Engine
Unlike standard tools that look for 302 redirects, our engine:
1. **Captures a Baseline:** Sends a known-invalid request to map the failure response.
2. **Fuzzy Matching:** Compares every attempt against the baseline using a similarity ratio.
3. **Differential Analysis:** Identifies success when the response deviates significantly from the failure signature.

---

## 📊 Reporting
At the end of every session, WebAuthTester Pro generates a professional summary in the terminal. Detailed findings including endpoint URLs, identified usernames, and valid passwords are displayed in a high-fidelity formatted table.

---

## ⚖️ Legal & Ethics
**WebAuthTester Pro is for authorized security testing only.**

Using this tool against systems without explicit written permission is illegal. The developers assume zero liability for unauthorized or malicious use.

**WebAuthTester Pro v2.2 — Built for Elite Security Research**
*AbasSec · Student of Cyber Security*
