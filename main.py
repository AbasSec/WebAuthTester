#!/usr/bin/env python3
"""
WebAuthTester Pro - Main Entry Point.

This module orchestrates the entire security auditing process, coordinating 
the DiscoveryEngine and BruteEngine, handling user input, and managing 
asynchronous tasks.
"""

import asyncio
import aiohttp
import argparse
import os
import sys
import yaml
import logging
from typing import Dict, Any
from textwrap import dedent

from webauthtester.core.engine import DiscoveryEngine, BruteEngine
from webauthtester.core.utils import show_banner, print_error, print_status, print_success, display_results, console

# Try to import Rich for professional progress bars
try:
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# Configure root logger to prevent third-party library spam
logging.basicConfig(level=logging.ERROR)

def load_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    """Loads operational configuration from a YAML file."""
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            print_error(f"Failed to parse config.yaml: {e}")
    return {}

def parse_arguments() -> argparse.Namespace:
    """Parses command-line arguments and provides professional usage examples."""
    usage_examples = dedent("""
        [bold yellow]Usage Examples:[/bold yellow]
          python3 WebAuthTester.py -t https://example.com
          python3 WebAuthTester.py -t https://target.com -u users.txt -p pass.txt
          python3 WebAuthTester.py -t https://api.target.com/v1/login -c 20 -x http://127.0.0.1:8080
          python3 WebAuthTester.py --stealth -t https://protected-site.com
    """)

    parser = argparse.ArgumentParser(
        description="WebAuthTester Pro - Enterprise Security Research Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=usage_examples
    )
    
    parser.add_argument("-t", "--target", type=str, help="Target URL (e.g., https://example.com)")
    parser.add_argument("-u", "--userlist", type=str, help="Path to username wordlist")
    parser.add_argument("-p", "--passlist", type=str, help="Path to password wordlist")
    parser.add_argument("-c", "--concurrency", type=int, help="Concurrency level (default: 10)")
    parser.add_argument("-x", "--proxy", type=str, help="HTTP Proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--config", type=str, default="config.yaml", help="Path to configuration file")
    parser.add_argument("--full-scan", action="store_true", help="Enable exhaustive enterprise audit")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode with randomized jitter")
    
    return parser.parse_args()

async def run_audit() -> None:
    """Main orchestration function for the security audit."""
    args = parse_arguments()
    config = load_config(args.config)
    
    # Priority Resolution: CLI arguments override Config File settings
    target = args.target or config.get('target')
    userlist = args.userlist or config.get('wordlists', {}).get('usernames', 'wordlists/usernames.txt')
    passlist = args.passlist or config.get('wordlists', {}).get('passwords', 'wordlists/passwords.txt')
    concurrency = args.concurrency or config.get('concurrency', 10)
    proxy = args.proxy or config.get('proxy')

    show_banner()
    
    if not target:
        # Re-initialize parser just to print help dynamically without exiting
        parse_arguments()._get_kwargs()
        # Hacky but clean way to show help
        print_error("No target specified. Use -t or define a target in config.yaml.")
        print("\nRun `python3 WebAuthTester.py -h` for usage instructions.")
        return

    if not os.path.exists(userlist) or not os.path.exists(passlist):
        print_error(f"Wordlists missing. Checked paths: {userlist}, {passlist}")
        print_status("Please run `./setup.sh` or specify valid paths using -u and -p.")
        return

    print_status(f"Initializing Enterprise Audit for: [bold white]{target}[/bold white]")

    # Create a unified async session for all HTTP requests
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        
        # --- PHASE 1: DISCOVERY ---
        discovery = DiscoveryEngine(session, target, proxy=proxy)
        if HAS_RICH:
            with console.status("[bold green]Crawling target and parsing DOM for entry points...") as status:
                endpoints = await discovery.run()
        else:
            print_status("Crawling target for entry points...")
            endpoints = await discovery.run()

        # Fallback to Universal Discovery if no standard forms are identified
        if not endpoints:
            print_error("No standard HTML forms or SPA routing components detected.")
            print_status("Initiating [bold yellow]Force-Discovery Mode[/bold yellow] (targeting root as universal gateway)...")
            
            # Map custom JSON payload structure if targeting an API
            u_field = config.get('mapping', {}).get('username', 'username')
            p_field = config.get('mapping', {}).get('password', 'password')
            extra = config.get('mapping', {}).get('extra', {})
            
            discovery._add_ep(target, 'universal_json', 'POST', u_field, p_field, extra, target)
            endpoints = discovery.endpoints

        print_success(f"Discovered and mapped {len(endpoints)} authentication gateway(s).")

        # --- PHASE 2: DIFFERENTIAL BRUTE FORCE ---
        brute = BruteEngine(session, concurrency, proxy)
        
        for ep in endpoints:
            print_status(f"Targeting Endpoint: [bold cyan]{ep.url}[/bold cyan] (Type: {ep.auth_type})")
            
            # 1. Establish Failure Baseline
            await brute.capture_baseline(ep)
            if ep.url not in brute.baselines:
                print_error("Failed to capture baseline. Endpoint may be dead or WAF protected. Skipping.")
                continue

            # 2. Load Wordlists
            try:
                with open(userlist, 'r', encoding='utf-8') as fu:
                    users = [line.strip() for line in fu if line.strip()]
                with open(passlist, 'r', encoding='utf-8') as fp:
                    passwords = [line.strip() for line in fp if line.strip()]
            except IOError as e:
                print_error(f"Error reading wordlists: {e}")
                return

            total_attempts = len(users) * len(passwords)
            
            # 3. Execute High-Concurrency Auditing
            if HAS_RICH:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TaskProgressColumn(),
                    console=console
                ) as progress:
                    task = progress.add_task("[cyan]Auditing credentials...", total=total_attempts)
                    for u in users:
                        for p in passwords:
                            if brute.rate_limited:
                                break
                            await brute.test(ep, u, p)
                            progress.update(task, advance=1)
            else:
                print_status(f"Auditing credentials... ({total_attempts} combinations)")
                for u in users:
                    for p in passwords:
                        if brute.rate_limited:
                            break
                        await brute.test(ep, u, p)
            
            if brute.rate_limited:
                print_error("Security Response Triggered: Rate Limit (HTTP 429/403) detected. Aborting endpoint audit.")

        # --- PHASE 3: REPORTING ---
        display_results(brute.results)

if __name__ == "__main__":
    # Ensure Windows compatibility for asyncio if necessary
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
    try:
        asyncio.run(run_audit())
    except KeyboardInterrupt:
        print("\n[!] Audit interrupted by user. Exiting gracefully.")
        sys.exit(0)
    except Exception as e:
        if HAS_RICH:
            console.print(f"[bold red]Fatal Error:[/bold red] {str(e)}")
        else:
            print(f"Fatal Error: {e}")
        sys.exit(1)
