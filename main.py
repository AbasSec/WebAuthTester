#!/usr/bin/env python3
"""
WebAuthTester - Professional Entry Point.
"""

import asyncio
import aiohttp
import argparse
import os
import sys

from webauthtester.core.engine import DiscoveryEngine, BruteEngine
from webauthtester.core.utils import show_banner, print_error, print_status, print_success, display_results, console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

def get_args():
    parser = argparse.ArgumentParser(description="WebAuthTester Pro - Enterprise Security Suite")
    parser.add_argument("target", help="Target URL (e.g., https://example.com)")
    parser.add_argument("-u", "--userlist", default="wordlists/usernames.txt", help="Username wordlist")
    parser.add_argument("-p", "--passlist", default="wordlists/passwords.txt", help="Password wordlist")
    parser.add_argument("-c", "--concurrency", type=int, default=10, help="Concurrency level")
    parser.add_argument("-x", "--proxy", help="HTTP Proxy")
    return parser.parse_args()

async def run_audit(args):
    show_banner()
    
    if not os.path.exists(args.userlist) or not os.path.exists(args.passlist):
        print_error("Wordlists missing. Run setup.sh first.")
        return

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        # Discovery Phase
        discovery = DiscoveryEngine(session, args.target, proxy=args.proxy)
        with console.status("[bold green]Crawling target for entry points...") as status:
            endpoints = await discovery.run()

        if not endpoints:
            print_error("No authentication endpoints identified.")
            return

        print_success(f"Identified {len(endpoints)} authentication gateway(s).")

        # Brute Force Phase
        brute = BruteEngine(session, args.concurrency, args.proxy)
        for ep in endpoints:
            print_status(f"Targeting: {ep.url}")
            await brute.capture_baseline(ep)

            users = [l.strip() for l in open(args.userlist).readlines() if l.strip()][:50]
            passwords = [l.strip() for l in open(args.passlist).readlines() if l.strip()][:50]

            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TaskProgressColumn(), console=console) as progress:
                task = progress.add_task("[cyan]Testing credentials...", total=len(users)*len(passwords))
                for u in users:
                    for p in passwords:
                        if brute.rate_limited: break
                        await brute.test(ep, u, p)
                        progress.update(task, advance=1)
            
            if brute.rate_limited:
                print_error("Rate limit hit. Skipping endpoint.")

        display_results(brute.results)

if __name__ == "__main__":
    args = get_args()
    try:
        asyncio.run(run_audit(args))
    except KeyboardInterrupt:
        sys.exit(0)
