#!/usr/bin/env python3
"""
WebAuthTester - Professional Entry Point.
"""

import asyncio
import aiohttp
import argparse
import os
import sys
import yaml

from webauthtester.core.engine import DiscoveryEngine, BruteEngine
from webauthtester.core.utils import show_banner, print_error, print_status, print_success, display_results, console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

def load_config(config_path="config.yaml"):
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    return {}

def get_args():
    parser = argparse.ArgumentParser(description="WebAuthTester Pro - Enterprise Security Suite")
    parser.add_argument("target", nargs="?", help="Target URL (e.g., https://example.com)")
    parser.add_argument("-u", "--userlist", help="Username wordlist")
    parser.add_argument("-p", "--passlist", help="Password wordlist")
    parser.add_argument("-c", "--concurrency", type=int, help="Concurrency level")
    parser.add_argument("-x", "--proxy", help="HTTP Proxy")
    parser.add_argument("--config", default="config.yaml", help="Path to config file")
    return parser.parse_args()

async def run_audit():
    args = get_args()
    config = load_config(args.config)
    
    # Priority: CLI Args > Config File > Defaults
    target = args.target or config.get('target')
    userlist = args.userlist or config.get('wordlists', {}).get('usernames', 'wordlists/usernames.txt')
    passlist = args.passlist or config.get('wordlists', {}).get('passwords', 'wordlists/passwords.txt')
    concurrency = args.concurrency or config.get('concurrency', 10)
    proxy = args.proxy or config.get('proxy')

    show_banner()
    
    if not target:
        print_error("No target specified. Provide a URL or set it in config.yaml.")
        return

    if not os.path.exists(userlist) or not os.path.exists(passlist):
        print_error(f"Wordlists missing at {userlist} or {passlist}. Run setup.sh first.")
        return

    print_status(f"Initializing audit for: [bold white]{target}[/bold white]")

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        # Discovery Phase
        discovery = DiscoveryEngine(session, target, proxy=proxy)
        with console.status("[bold green]Crawling target for entry points...") as status:
            endpoints = await discovery.run()

        if not endpoints:
            print_error("No standard or SPA-style authentication gateways detected.")
            print_status("Initiating [bold yellow]Force-Discovery Mode[/bold yellow] (using target URL as universal gateway)...")
            # Fallback: add the direct target as a universal JSON endpoint
            discovery._add_ep(target, 'universal_json', 'POST', 'username', 'password', {}, target)
            endpoints = discovery.endpoints

        print_success(f"Proceeding with {len(endpoints)} authentication gateway(s).")

        # Brute Force Phase
        brute = BruteEngine(session, concurrency, proxy)
        for ep in endpoints:
            print_status(f"Targeting: [bold cyan]{ep.url}[/bold cyan] ({ep.auth_type})")
            await brute.capture_baseline(ep)

            users = [l.strip() for l in open(userlist).readlines() if l.strip()][:50]
            passwords = [l.strip() for l in open(passlist).readlines() if l.strip()][:50]

            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TaskProgressColumn(), console=console) as progress:
                task = progress.add_task("[cyan]Auditing credentials...", total=len(users)*len(passwords))
                for u in users:
                    for p in passwords:
                        if brute.rate_limited: break
                        await brute.test(ep, u, p)
                        progress.update(task, advance=1)
            
            if brute.rate_limited:
                print_error("Security mechanism triggered (Rate Limited). Skipping endpoint.")

        display_results(brute.results)

if __name__ == "__main__":
    try:
        asyncio.run(run_audit())
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print_error(f"Fatal error: {e}")
