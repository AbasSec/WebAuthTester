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

## 🛠️ Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/AbasSec/WebAuthTester.git
cd WebAuthTester
```

### 2. Run the Setup Script
The `setup.sh` script automatically installs dependencies and prepares the environment.
```bash
chmod +x setup.sh
./setup.sh
```

### 3. Run the Tool
On most systems (including Kali/Debian), the setup script installs dependencies directly. You can now execute the tool:
```bash
python3 WebAuthTester.py -t https://example.com
```
*Note: If the setup script successfully created a virtual environment, it will prompt you to activate it with `source venv/bin/activate` before running.*

---

## 📖 Usage Guide

Running the tool without arguments displays the help menu and usage examples.

### Basic Audit
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

### Advanced Options
- **Concurrency:** Increase speed with `-c` (Default: 10).
- **Proxy:** Route traffic through a proxy (e.g. Burp Suite) with `-x`.
- **Stealth:** Enable `--stealth` to add jitter and bypass behavioral WAFs.

---

## 🧠 Professional Modules

### 1. Discovery Engine
Identifies standard HTML forms, modern SPA components, and hidden API configurations (e.g. Firebase) within JavaScript files.

### 2. Brute Force Engine
Uses **Differential Response Modeling (DRM)** and **Gestalt Pattern Matching** to identify successful logins by analyzing structural response changes rather than simple status codes.

---

## 📊 Reporting
Generates a detailed terminal-based report and a comprehensive technical dissertation in `WebAuthTester.md`.

---

## ⚖️ Legal & Ethics
**WebAuthTester Pro is for authorized security testing only.**

**WebAuthTester Pro v2.2 — Built for Elite Security Research**
*AbasSec · Student of Cyber Security*
