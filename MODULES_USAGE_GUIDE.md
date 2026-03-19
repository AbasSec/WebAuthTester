# WebAuthTester Pro: Comprehensive Usage Guide 📘

This guide explains all command-line arguments and scenarios for using **WebAuthTester Pro v2.3**.

---

## 🛠️ Basic Command-Line Arguments

The basic syntax is as follows:
`./WebAuthTester.py [TARGET] [OPTIONS]`

### Core Options:
- `target`: The target URL (e.g., `https://example.com`).
- `-u` / `--userlist`: Path to a file containing usernames.
- `-p` / `--passlist`: Path to a file containing passwords.
- `-c` / `--concurrency`: Number of simultaneous async connections (Default: `10`).
- `-x` / `--proxy`: Route all requests through a proxy (e.g., `http://127.0.0.1:8080`).
- `--config`: Path to a custom YAML configuration file.

---

## 🚀 Advanced Usage Scenarios

### 1. Auditing modern SPAs (Firebase/React/Vue)
If the tool cannot find a standard form, it automatically initiates **Force-Discovery Mode**. You can also target API endpoints directly using the `config.yaml` mapping feature:

```yaml
target: "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=YOUR_API_KEY"
mapping:
  username: "email"
  password: "password"
  extra:
    returnSecureToken: True
```

### 2. Deep-Crawl JavaScript Parsing
The tool automatically fetches and parses all linked `.js` files on the target to identify hidden Firebase configurations and hardcoded API endpoints. No extra flags are required.

### 3. High-Performance / Massive Brute Force
Increase concurrency for faster testing on stable servers:
```bash
./WebAuthTester.py https://target.com -c 50
```

### 4. Traffic Interception with Burp Suite
1. Open Burp Suite (Default: `127.0.0.1:8080`).
2. Run: `./WebAuthTester.py https://target.com -x http://127.0.0.1:8080`

---

## ⚠️ Understanding the Output

- **[+] Identified X authentication gateway(s):** Success in finding forms, SPA components, or API endpoints.
- **[*] Initiating Force-Discovery Mode:** Fallback logic used when no formal gateways are found.
- **[!] Security mechanism triggered:** The tool detected rate-limiting (429) and is pausing to avoid a ban.

---

## 💡 Troubleshooting

- **"No endpoints discovered":** The site likely uses heavy obfuscation or requires multi-step interactive login. Try pointing the tool directly at the API endpoint.
- **SSL Errors:** Ensure you are using the `-x` flag correctly if running through a proxy.
