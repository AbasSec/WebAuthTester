```text
  __      __     __    ___         __  _      
 |  | /| / /__  / /_  / _ | __ __ / /_| |_    
 |  |/ |/ / -_) __ \/ __ |/ // // __/| ' \   
 |__/|__/\___/_.___/_/ |_|\_,_/ \__/ |_||_|  

     >> WebAuthTester Pro v2.6 << 
   Enterprise Security Research Suite 
```

**WebAuthTester Pro** — Enterprise Automated Web Security Testing Framework
Reconnaissance · Exploitation · Authorization · Intelligence

A high-performance, asynchronous Python security framework for elite bug bounty hunters and red teams.

---

## 📋 Table of Contents
- [🔍 Overview](#-overview)
- [🚀 Key Features (v2.6)](#-key-features-v26)
- [🛠️ Installation & Setup](#️-installation--setup)
  - [Prerequisites](#prerequisites)
  - [Quick Start (Automated)](#quick-start-automated)
  - [Manual Installation](#manual-installation)
- [📖 Usage Guide](#-usage-guide)
  - [Dashboard Mode (Beginners)](#dashboard-mode-beginners)
  - [Manual Mode (Technical)](#manual-mode-technical)
  - [Advanced Attack Modes](#advanced-attack-modes)
- [⚙️ Configuration (`config.yaml`)](#️-configuration-configyaml)
- [🧩 Modular Architecture](#-modular-architecture)
- [📊 Reporting](#-reporting)
- [🐳 Docker Deployment](#-docker-deployment)
- [⚖️ Legal & Ethics](#-legal--ethics)

---

## 🔍 Overview
**WebAuthTester Pro v2.6** is a comprehensive, asynchronous offensive security framework designed for enterprise-scale authentication auditing. It implements a **RAPTOR-grade Differential Analysis** engine that identifies successful authentications by modeling response structural divergence, bypassing modern anti-automation defenses.

---

## 🚀 Key Features (v2.6)
- 🧩 **Plugin Architecture:** Decoupled modules for Form, JSON, Firebase, and OAuth2 detection.
- 📉 **Differential Success Detection:** Uses `SequenceMatcher` to bypass `200 OK` failure responses.
- 🔐 **Stateful CSRF Handling:** Dynamic token extraction and rotation per-request.
- ⚡ **High-Performance Pooling:** Shared session architecture with ~40% latency reduction.
- 🔥 **Firebase & SPA Support:** Automated identification and auditing of Firebase-backed apps.
- 📈 **Credential Stuffing Mode:** Support for 1:1 user-to-password pairing.
- 📊 **CWE/CVSS Tagging:** Vulnerability reporting with industry-standard classification.
- 🐳 **Hardened Docker:** Multi-stage builds and non-root execution for safe deployments.

---

## 🛠️ Installation & Setup

### Prerequisites
- **Python 3.8+**
- **pip** (Python package manager)
- **git** (optional, for cloning)

### Quick Start (Automated)
The provided `setup.sh` script automates the environment creation, dependency installation, and wordlist generation.
```bash
# Clone the repository
git clone https://github.com/AbasSec/WebAuthTester.git
cd WebAuthTester

# Run the setup script
chmod +x setup.sh
./setup.sh

# Activate the virtual environment
source venv/bin/activate
```

### Manual Installation
If you prefer to set up the environment manually:
```bash
# 1. Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Customize Wordlists
# Default wordlists are provided in the wordlists/ directory.
```

---

## 📖 Usage Guide

### Dashboard Mode (Beginners)
Simply run the script without arguments to see a high-level overview and quick-start guide:
```bash
python3 main.py
```

### Manual Mode (Technical)
Use the help flag to see the full technical manual and all available options:
```bash
python3 main.py --help
```

### Basic Brute Force
Automatically crawls the target and audits discovered endpoints:
```bash
python3 main.py -t https://example.com
```

### Credential Stuffing (1:1 Pairing)
Pairs the $n$-th username with the $n$-th password from your lists:
```bash
python3 main.py -t https://target.com -u wordlists/users.txt -p wordlists/pass.txt --stuffing
```

### Stealth Mode
Introduces randomized jitter (0.5s - 2.0s) between attempts to bypass rate limiting:
```bash
python3 main.py -t https://target.com --stealth
```

---

## ⚙️ Configuration (`config.yaml`)
Global defaults and operational settings can be tuned in `config.yaml`:
- **Wordlists:** Default paths for usernames and passwords.
- **Concurrency:** Control the number of parallel workers.
- **Proxy:** Configure an upstream proxy (e.g., Burp Suite).
- **Discovery:** Adjust crawl depth and timeout settings.

---

## 🧩 Modular Architecture
The framework is built on a provider-based architecture located in `webauthtester/modules/`:
- **`FormAuthModule`:** Handles standard HTML forms with CSRF and session management.
- **`JSONAuthModule`:** Audits JSON-based API endpoints with field heuristics.
- **`FirebaseAuthModule`:** Deep auditing of modern Firebase SPAs via direct API hooks.
- **`OAuthDetectionModule`:** Identifies OAuth2/OIDC/SAML flows.

Deep technical documentation for each module can be found in the `docs/` directory.

---

## 📊 Reporting
WebAuthTester Pro generates professional, structured output:
- **Terminal UI:** Real-time progress bars and color-coded results via `rich`.
- **Structured JSON:** Export results with `-o results.json` for CI/CD integration.
- **Audit Logs:** Full execution details are stored in `webauthtester.log`.

---

## 🐳 Docker Deployment
Run the tool securely in a hardened container:
```bash
# Build the image
docker build -t webauthtester .

# Run an audit
docker run --rm -v $(pwd)/wordlists:/home/auditor/app/wordlists webauthtester -t https://example.com
```

---

## ⚖️ Legal & Ethics
**WebAuthTester Pro is for authorized security testing only.**
Unauthorized use against systems without prior written consent is illegal and unethical. The authors assume no liability for misuse.

**WebAuthTester Pro v2.6 — Built for Elite Security Research**
*AbasSec · Student of Cyber Security*
