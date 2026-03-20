"""
WebAuth Utils - UI components and terminal formatting.

This module leverages the 'rich' library to provide a professional,
colorized, and structured command-line interface for the framework.
"""

from typing import List, Tuple
from rich.console import Console
from rich.table import Table
from .models import SecurityFinding

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

def show_banner() -> None:
    """Displays the stylized application banner."""
    console.print(BANNER)

def print_error(msg: str) -> None:
    """Prints a formatted critical error message."""
    console.print(f"[bold red][!] {msg}[/bold red]")

def print_status(msg: str) -> None:
    """Prints a formatted informational status message."""
    console.print(f"[bold blue][*] {msg}[/bold blue]")

def print_success(msg: str) -> None:
    """Prints a formatted success message."""
    console.print(f"[bold green][+] {msg}[/bold green]")

def display_findings(findings: List[SecurityFinding]) -> None:
    """Renders discovered security vulnerabilities in a professional table."""
    if not findings:
        return

    table = Table(title="[bold yellow]SECURITY VULNERABILITIES IDENTIFIED[/bold yellow]", border_style="yellow", expand=True)
    table.add_column("Finding", style="white")
    table.add_column("Endpoint", style="cyan")
    table.add_column("Severity", style="bold red")
    table.add_column("CWE", style="magenta")

    for f in findings:
        table.add_row(f.title, f.endpoint, f.severity, f.cwe)
    
    console.print("\n")
    console.print(table)

def display_results(results: List[Tuple[str, str, str]]) -> None:
    """
    Renders the final credential audit results in a professional data table.
    
    Args:
        results (List[Tuple[str, str, str]]): A list of tuples containing
            (Endpoint URL, Username, Password) for successful authentications.
    """
    if not results:
        console.print("[yellow][*] Audit complete. No valid credentials found.[/yellow]")
        return

    table = Table(title="[bold green]VALID CREDENTIALS IDENTIFIED[/bold green]", border_style="green", expand=True)
    table.add_column("Endpoint", style="cyan", overflow="fold")
    table.add_column("Username", style="white", no_wrap=True)
    table.add_column("Password", style="bold red", no_wrap=True)

    for url, u, p in results:
        table.add_row(url, u, p)
    
    console.print(table)
