"""
WebAuth Utils - UI components and terminal formatting.
"""

import random
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

BANNER = r"""[bold red]
 __      __      ___.       _____         __  .__     
/  \    /  \ ____\_ |__    /  _  \  __ ___/  |_|  |__  
\   \/\/   // __ \| __ \  /  /_\  \|  |  \   __\  |  \ 
 \        /\  ___/| \_\ /    |    \  |  /|  | |   Y  \
  \__/\  /  \___  >___  /\____|__  /____/ |__| |___|  /
       \/       \/    \/         \/                 \/ 
                 [italic white]v2.2 - Enterprise Security Research Suite[/italic white]
[/bold red]"""

def show_banner():
    """Displays the stylized application banner."""
    console.print(BANNER)

def print_error(msg: str):
    """Prints a formatted error message."""
    console.print(f"[bold red][!] {msg}[/bold red]")

def print_status(msg: str):
    """Prints a formatted status message."""
    console.print(f"[bold blue][*] {msg}[/bold blue]")

def print_success(msg: str):
    """Prints a formatted success message."""
    console.print(f"[bold green][+] {msg}[/bold green]")

def display_results(results: list):
    """Renders the final results in a professional table."""
    if not results:
        console.print("[yellow][*] Audit complete. No valid credentials found.[/yellow]")
        return

    table = Table(title="[bold green]VALID CREDENTIALS IDENTIFIED[/bold green]", border_style="green")
    table.add_column("Endpoint", style="cyan")
    table.add_column("Username", style="white")
    table.add_column("Password", style="bold red")

    for url, u, p in results:
        table.add_row(url, u, p)
    
    console.print(table)
