#!/bin/bash

# WebAuthTester Pro - Automated Setup Script

echo -e "\033[1;34m[+] Starting WebAuthTester Pro Setup...\033[0m"

# Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo -e "\033[1;31m[-] Python 3 is not installed. Please install Python 3 and try again.\033[0m"
    exit 1
fi

echo -e "\033[1;32m[+] Python 3 detected.\033[0m"

# Try to create a virtual environment, fallback to --break-system-packages if it fails
echo -e "\033[1;34m[+] Setting up environment and installing dependencies...\033[0m"

# Install dependencies
if python3 -m venv venv 2>/dev/null; then
    echo -e "\033[1;32m[+] Virtual environment created successfully.\033[0m"
    source venv/bin/activate
    pip install --upgrade pip > /dev/null 2>&1
    pip install aiohttp rich beautifulsoup4
    VENV_CREATED=true
else
    echo -e "\033[1;33m[!] Virtual environment creation failed (often due to missing python3-venv package on Debian/Kali).\033[0m"
    echo -e "\033[1;33m[!] Falling back to user installation (--break-system-packages)...\033[0m"
    pip install aiohttp rich beautifulsoup4 --break-system-packages --user
    VENV_CREATED=false
fi

# Make the main script executable
chmod +x main.py

# Create default wordlists directory if it doesn't exist
if [ ! -d "wordlists" ]; then
    echo -e "\033[1;34m[+] Creating default wordlists directory...\033[0m"
    mkdir -p wordlists
    
    # Create sample wordlists
    echo -e "admin\nadministrator\nroot\nuser\ntest" > wordlists/usernames.txt
    echo -e "admin\npassword\n123456\nPassword123!\nadmin123" > wordlists/passwords.txt
    echo -e "\033[1;32m[+] Sample wordlists created at wordlists/\033[0m"
fi

echo -e "\033[1;32m[+] Setup Complete!\033[0m"

if [ "$VENV_CREATED" = true ]; then
    echo -e "\033[1;33m[!] To run the tool, first activate the virtual environment:\033[0m"
    echo -e "    source venv/bin/activate"
    echo -e "\033[1;33m[!] Then execute the script:\033[0m"
    echo -e "    ./main.py https://target.com"
else
    echo -e "\033[1;33m[!] To execute the script, simply run:\033[0m"
    echo -e "    ./main.py https://target.com"
fi
