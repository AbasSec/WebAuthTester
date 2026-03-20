"""
WebAuthTester Pro - CLI Interface.
"""

import asyncio
import aiohttp
import argparse
import os
import sys
import yaml
import logging
from typing import Dict, Any, Tuple
from textwrap import dedent
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel

from webauthtester.core.engine import DiscoveryEngine, BruteEngine
from webauthtester.core.utils import (
    show_banner, print_error, print_status, print_success, 
    display_results, display_findings, console
)

# Configure proper logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('webauthtester.log')
    ]
)
logger = logging.getLogger(__name__)

VERSION = "2.6"

def load_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    """Loads operational configuration from a YAML file."""
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            print_error(f"Failed to parse config.yaml: {e}")
    return {}

def parse_arguments() -> Tuple[argparse.ArgumentParser, argparse.Namespace]:
    """Parses command-line arguments and provides professional usage examples."""
    usage_examples = dedent("""
        [bold yellow]Usage Examples:[/bold yellow]
          python3 main.py -t https://example.com
          python3 main.py -t https://target.com -u users.txt -p pass.txt
          python3 main.py --stuffing -t https://target.com
          python3 main.py --stealth -t https://protected-site.com
    """)

    parser = argparse.ArgumentParser(
        description="WebAuthTester Pro - Enterprise Security Research Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=usage_examples,
        add_help=False # We'll add it manually to support -help
    )
    
    # Support both -h, --help AND -help
    parser.add_argument("-h", "--help", "-help", action="help", help="show this help message and exit")
    
    parser.add_argument("-t", "--target", type=str, help="Target URL (e.g., https://example.com)")
    parser.add_argument("-u", "--userlist", type=str, help="Path to username wordlist")
    parser.add_argument("-p", "--passlist", type=str, help="Path to password wordlist")
    parser.add_argument("-c", "--concurrency", type=int, help="Concurrency level (default: 10)")
    parser.add_argument("-x", "--proxy", type=str, help="HTTP Proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-o", "--output", type=str, help="Save findings to JSON/CSV (e.g., results.json)")
    parser.add_argument("--config", type=str, default="config.yaml", help="Path to configuration file")
    parser.add_argument("--full-scan", action="store_true", help="Enable exhaustive enterprise audit")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode with randomized jitter")
    parser.add_argument("--stuffing", action="store_true", help="Pair users and passwords 1:1 (Credential Stuffing)")
    parser.add_argument("--version", action="version", version=f"WebAuthTester Pro v{VERSION}")
    
    return parser, parser.parse_args()

def show_overview():
    """Displays a high-level overview of the tool's capabilities."""
    overview_text = dedent("""
        [bold cyan]WebAuthTester Pro v2.6[/bold cyan] is a high-performance, asynchronous security framework
        designed for enterprise-scale authentication auditing.

        [bold white]Core Capabilities:[/bold white]
        • [green]Aggressive Discovery:[/green] Automated crawling and DOM parsing for auth gateways.
        • [green]Differential Analysis:[/green] RAPTOR-grade success detection using SequenceMatcher.
        • [green]Stateful Auditing:[/green] Real-time CSRF extraction and session isolation.
        • [green]Multi-Protocol:[/green] Support for Form-based, JSON (active), and OAuth2 detection.
        • [green]Stealth & Performance:[/green] Adaptive jitter, connection pooling, and concurrency control.
    """)
    console.print(Panel(overview_text, title="[bold yellow]Tool Overview[/bold yellow]", border_style="blue"))

async def run_audit() -> None:
    """Main orchestration function for the security audit."""
    # If no arguments provided, show overview then help
    if len(sys.argv) == 1:
        show_banner()
        show_overview()
        parser, _ = parse_arguments()
        parser.print_help()
        return

    parser, args = parse_arguments()
    config = load_config(args.config)
    
    target_raw = args.target or config.get('target')
    target = str(target_raw) if target_raw else None
    
    userlist = args.userlist or config.get('wordlists', {}).get('usernames', 'wordlists/usernames.txt')
    passlist = args.passlist or config.get('wordlists', {}).get('passwords', 'wordlists/passwords.txt')
    concurrency = args.concurrency or config.get('concurrency', 10)
    proxy = args.proxy or config.get('proxy')
    stealth = args.stealth or config.get('stealth', False)
    stuffing = args.stuffing or config.get('stuffing', False)
    output_file = args.output or config.get('output')

    show_banner()
    
    if not target:
        parser.print_help()
        print_error("\nNo target specified. Use -t or define a target in config.yaml.")
        return

    logger.info(f"Audit Started - WebAuthTester Pro v{VERSION} targeting {target}")
    
    if not os.path.exists(userlist) or not os.path.exists(passlist):
        print_error(f"Wordlists missing. Checked paths: {userlist}, {passlist}")
        return

    print_status(f"Initializing Enterprise Audit for: [bold white]{target}[/bold white]")

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        
        discovery = DiscoveryEngine(session, target, proxy=proxy)
        with console.status("[bold green]Crawling target and parsing DOM for entry points..."):
            endpoints = await discovery.run()

        print_success(f"Discovered and mapped {len(endpoints)} authentication gateway(s).")

        brute = BruteEngine(session, concurrency, proxy, stealth=stealth)
        
        for ep in endpoints:
            print_status(f"Targeting Endpoint: [bold cyan]{ep.url}[/bold cyan] (Type: {ep.auth_type})")
            
            await brute.capture_baseline(ep)
            if ep.url not in brute.baselines and not ep.is_oauth:
                continue

            try:
                with open(userlist, 'r', encoding='utf-8') as fu:
                    users = [line.strip() for line in fu if line.strip()]
                with open(passlist, 'r', encoding='utf-8') as fp:
                    passwords = [line.strip() for line in fp if line.strip()]
            except IOError as e:
                print_error(f"Error reading wordlists: {e}")
                return

            if stuffing:
                pairs = list(zip(users, passwords))
                print_status(f"Stuffing Mode: [bold yellow]ON[/bold yellow]. Pairs: {len(pairs)}")
            else:
                pairs = [(u, p) for u in users for p in passwords]
                print_status(f"Brute Mode: [bold cyan]ON[/bold cyan]. Combinations: {len(pairs)}")

            total_attempts = len(pairs)
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console
            ) as progress:
                task_p = progress.add_task("[cyan]Auditing credentials...", total=total_attempts)
                
                async def track_task(u, p):
                    if brute.rate_limited:
                        return
                    await brute.test(ep, u, p)
                    progress.update(task_p, advance=1)

                tasks = [track_task(u, p) for u, p in pairs]
                await asyncio.gather(*tasks)
            
            if brute.rate_limited:
                print_error("Security Response Triggered: Rate Limit detected. Aborted endpoint audit.")

        display_findings(brute.findings)
        display_results(brute.results)
        
        if output_file and (brute.results or brute.findings):
            try:
                import json
                with open(output_file, 'w', encoding='utf-8') as f:
                    res = [{"url": r[0], "username": r[1], "password": r[2]} for r in brute.results]
                    finds = [f.__dict__ for f in brute.findings]
                    for fin in finds:
                        if 'timestamp' in fin: fin['timestamp'] = fin['timestamp'].isoformat()
                    out = {"credentials": res, "vulnerabilities": finds}
                    json.dump(out, f, indent=4)
                print_success(f"Full report exported to: [bold white]{output_file}[/bold white]")
            except Exception as e:
                print_error(f"Failed to save output: {e}")

def main():
    """Main entry point for the CLI."""
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(run_audit())
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print(f"Fatal Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
