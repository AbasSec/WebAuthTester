# WebAuthTester Pro: Comprehensive Usage Guide 📘

This guide explains all command-line arguments and scenarios for using **WebAuthTester Pro**.

---

## 🛠️ Basic Command-Line Arguments

The basic syntax is as follows:
`./WebAuthTester.py [TARGET] [OPTIONS]`

### Core Options:
- `target`: The target URL (e.g., `https://example.com`).
- `-u` / `--userlist`: Path to a file containing usernames (Default: `wordlists/usernames.txt`).
- `-p` / `--passlist`: Path to a file containing passwords (Default: `wordlists/passwords.txt`).
- `-c` / `--concurrency`: Number of simultaneous async connections (Default: `10`).
- `-x` / `--proxy`: Route all requests through a proxy (e.g., `http://127.0.0.1:8080`).

---

## 📖 Common Usage Scenarios

### 1. Simple Quick Audit
To perform a standard audit on a website using default wordlists:
```bash
./WebAuthTester.py https://target.com
```

### 2. High-Performance / Massive Brute Force
Increase concurrency for faster testing on stable, high-capacity servers:
```bash
./WebAuthTester.py https://target.com -c 50 -u custom_users.txt -p common_pass.txt
```

### 3. Traffic Interception with Burp Suite
Use this to analyze the tool's behavior or troubleshoot detection issues.
1. Open Burp Suite.
2. Ensure Burp is listening on `127.0.0.1:8080`.
3. Run the tool with the `-x` flag:
```bash
./WebAuthTester.py https://target.com -x http://127.0.0.1:8080
```

### 4. Custom Wordlists
If you have gathered specific usernames for your target:
```bash
./WebAuthTester.py https://target.com -u targets_usernames.txt -p top_1000_pass.txt
```

---

## ⚠️ Understanding the Output

- **[+] Discovered X endpoints:** Shows how many login forms or API endpoints the crawler found.
- **Auditing [URL]:** Indicates the tool is performing a configuration audit (headers, SSL, CSRF).
- **Brute forcing [X/Total]:** A real-time progress bar shows the credential testing phase.
- **[!] Rate limited:** Indicates the target server is blocking requests (HTTP 429). The tool will automatically stop testing that specific endpoint.
- **Audit Complete. Report: [FILE]:** The location of your final Markdown security report.

---

## 💡 Troubleshooting

- **"No endpoints discovered":** The crawler may be blocked, or the site is a single-page app (SPA) that requires JavaScript rendering. Try pointing the tool directly at the `/login` URL.
- **"Wordlists not found":** Run `./setup.sh` first to generate the default directory and files.
- **SSL Verification Errors:** The tool disables SSL verification by default to work with proxies, but ensure your system time is correct for modern HTTPS requests.
