#!/usr/bin/env python3
"""
=======================================
    MailFox - Advanced Email Breach Scanner
    Author: @sid7.py
=======================================
"""

import os
import sys
import json
import time
import argparse
import requests
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# External imports
import pyfiglet
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.prompt import Prompt, Confirm
import colorama
from colorama import Fore, Style

# Initialize colorama
colorama.init(autoreset=True)

# Initialize Rich console
console = Console()

# Custom ASCII banner
CUSTOM_BANNER = r"""
                                                            _.-=;~ /_
                                                         _-~   '     ;.
                                                     _.-~     '   .-~-~`-._
                                               _.--~~:.             --.____88
                             ____.........--~~~. .' .  .        _..-------~~
                    _..--~~~~               .' .'             ,'
                _.-~                        .       .     ` ,'
              .'                                    :.    ./
            .:     ,/          `                   ::.   ,'
          .:'     ,(            ;.                ::. ,-'
         .'     ./'.`.     . . /:::._______.... _/:.o/
        /     ./'. . .)  . _.,'               `88;?88|
      ,'  . .,/'._,-~ /_.o8P'                  88P ?8b
   _,'' . .,/',-~    d888P'                    88'  88|
 _.'~  . .,:oP'        ?88b              _..--- 88.--'8b.--..__
:     ...' 88o __,------.88o ...__..._.=~- .    `~~   `~~      ~-._sid7.py_.
`.;;;:='    ~~            ~~~                ~-    -       -   -
"""

@dataclass
class SearchResult:
    """Data class for search results"""
    email: str
    password: str
    source: str
    found_at: str
    hash_md5: str = ""
    hash_sha1: str = ""
    hash_sha256: str = ""
    
    def __post_init__(self):
        """Calculate hashes after initialization"""
        if self.password:
            self.hash_md5 = hashlib.md5(self.password.encode()).hexdigest()
            self.hash_sha1 = hashlib.sha1(self.password.encode()).hexdigest()
            self.hash_sha256 = hashlib.sha256(self.password.encode()).hexdigest()

class MailFox:
    """Main MailFox scanner class"""
    
    def __init__(self, args):
        self.args = args
        self.results: List[SearchResult] = []
        self.stats = {
            'total_found': 0,
            'unique_emails': 0,
            'unique_passwords': 0,
            'start_time': datetime.now(),
            'search_duration': 0
        }
        self.config = self.load_config()
        self.session = self.create_session()
        
    def load_config(self) -> Dict:
        """Load configuration from file"""
        config_paths = [
            './mailfox_config.json',
            os.path.expanduser('~/.config/mailfox/config.json'),
            '/etc/mailfox/config.json'
        ]
        
        default_config = {
            'user_agent': 'MailFox/2.0',
            'timeout': 30,
            'max_retries': 3,
            'max_workers': 10,
            'api_endpoints': {
                'proxy_nova': 'https://api.proxynova.com/comb',
                'have_i_been_pwned': 'https://haveibeenpwned.com/api/v3/breachedaccount/'
            }
        }
        
        for path in config_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r') as f:
                        loaded_config = json.load(f)
                        default_config.update(loaded_config)
                        console.print(f"[cyan][*] Loaded config from: {path}")
                except Exception as e:
                    console.print(f"[yellow][!] Error loading config from {path}: {e}")
        
        return default_config
    
    def create_session(self) -> requests.Session:
        """Create HTTP session with configuration"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': self.config['user_agent']
        })
        
        if self.args.proxy:
            proxies = {
                'http': self.args.proxy,
                'https': self.args.proxy
            }
            session.proxies.update(proxies)
            console.print(f"[cyan][*] Using proxy: {self.args.proxy}")
        
        session.verify = not self.args.no_verify
        return session
    
    def display_banner(self):
        """Display ASCII banner"""
        # Clear screen if requested
        if self.args.clear_screen:
            os.system('cls' if os.name == 'nt' else 'clear')
        
        # Display the custom banner
        console.print(f"[bold cyan]{CUSTOM_BANNER}[/bold cyan]")
        
        # Display tool title with ASCII art
        title_art = """
PROXY NATION
        """
        console.print(f"[bold red]{title_art}[/bold red]")
        
        # Display tool info
        info_panel = Panel.fit(
            f"[bold cyan]🐺 MailFox - Advanced Email Breach Scanner[/bold cyan]\n"
            f"[bold white]Author:[/bold white] @sid7.py\n"
            f"[bold white]Version:[/bold white] 2.0\n"
            f"[bold white]Mode:[/bold white] {self.args.mode.title()}\n"
            f"[bold white]Target:[/bold white] {self.args.target if self.args.target else 'Interactive Mode'}",
            title="[bold]Scan Information[/bold]",
            border_style="green",
            padding=(1, 2)
        )
        console.print(info_panel)
        print()
    
    def search_proxynova(self, email: str) -> List[SearchResult]:
        """Search ProxyNova database"""
        results = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task(f"[cyan]Searching ProxyNova...", total=100)
            
            try:
                url = f"{self.config['api_endpoints']['proxy_nova']}?query={email}"
                response = self.session.get(url, timeout=self.config['timeout'])
                
                for i in range(0, 100, 20):
                    progress.update(task, advance=20)
                    time.sleep(0.1)
                
                if response.status_code == 200:
                    data = response.json()
                    lines = data.get("lines", [])[:self.args.limit]
                    
                    for line in lines:
                        if ':' in line:
                            email_part, password = line.split(':', 1)
                            result = SearchResult(
                                email=email_part.strip(),
                                password=password.strip(),
                                source="ProxyNova",
                                found_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            )
                            results.append(result)
                    
                    progress.update(task, completed=100)
                    console.print(f"[green][+] Found {len(results)} results from ProxyNova")
                    
            except Exception as e:
                console.print(f"[red][!] ProxyNova search error: {e}")
        
        return results
    
    def search_local_database(self, target: str) -> List[SearchResult]:
        """Search local database files"""
        results = []
        
        if not os.path.exists(self.args.database):
            console.print(f"[red][!] Database file not found: {self.args.database}")
            return results
        
        console.print(f"[cyan][*] Searching in local database: {self.args.database}")
        
        try:
            # Handle different file formats
            if self.args.database.endswith('.json'):
                with open(self.args.database, 'r') as f:
                    data = json.load(f)
                    lines = data.get("lines", [])
            else:
                with open(self.args.database, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
            
            # Search through lines
            found_count = 0
            total_lines = len(lines)
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                task = progress.add_task(
                    f"[cyan]Scanning {total_lines:,} lines...", 
                    total=total_lines
                )
                
                for line in lines:
                    line = line.strip()
                    progress.update(task, advance=1)
                    
                    # Check if target is in line (case insensitive)
                    if target.lower() in line.lower():
                        if ':' in line:
                            parts = line.split(':', 1)
                            if len(parts) == 2:
                                email_part, password = parts
                                result = SearchResult(
                                    email=email_part.strip(),
                                    password=password.strip(),
                                    source="Local Database",
                                    found_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                )
                                results.append(result)
                                found_count += 1
                                
                                if found_count >= self.args.limit:
                                    break
            
            console.print(f"[green][+] Found {len(results)} results from local database")
            
        except Exception as e:
            console.print(f"[red][!] Local database error: {e}")
        
        return results
    
    def search_multiple_sources(self, target: str) -> List[SearchResult]:
        """Search multiple sources concurrently"""
        results = []
        
        # Define search tasks
        search_tasks = []
        if self.args.sources == 'all' or 'proxynova' in self.args.sources:
            search_tasks.append(('ProxyNova', self.search_proxynova, target))
        
        if self.args.database and (self.args.sources == 'all' or 'local' in self.args.sources):
            search_tasks.append(('Local DB', self.search_local_database, target))
        
        # Execute searches concurrently
        with ThreadPoolExecutor(max_workers=len(search_tasks)) as executor:
            future_to_source = {
                executor.submit(task[1], task[2]): task[0] 
                for task in search_tasks
            }
            
            for future in as_completed(future_to_source):
                source = future_to_source[future]
                try:
                    source_results = future.result()
                    results.extend(source_results)
                except Exception as e:
                    console.print(f"[red][!] {source} search failed: {e}")
        
        return results
    
    def display_results(self, results: List[SearchResult]):
        """Display results in a beautiful table"""
        if not results:
            console.print(Panel.fit(
                "[bold yellow]No leaks found![/bold yellow]",
                border_style="yellow"
            ))
            return
        
        # Update statistics
        self.stats['total_found'] = len(results)
        self.stats['unique_emails'] = len(set(r.email for r in results))
        self.stats['unique_passwords'] = len(set(r.password for r in results))
        self.stats['search_duration'] = (datetime.now() - self.stats['start_time']).total_seconds()
        
        # Create results table
        table = Table(
            title=f"[bold cyan]🐺 Found {len(results)} Leaked Credentials[/bold cyan]",
            show_header=True,
            header_style="bold magenta",
            border_style="blue",
            show_lines=True
        )
        
        # Add columns
        table.add_column("#", style="dim", width=4)
        table.add_column("Email", style="bold white")
        table.add_column("Password", style="yellow")
        table.add_column("Source", style="green")
        table.add_column("Hash (MD5)", style="dim cyan")
        
        # Add rows
        for idx, result in enumerate(results[:self.args.limit], 1):
            # Truncate long passwords for display
            password_display = result.password
            if len(password_display) > 20:
                password_display = password_display[:17] + "..."
            
            # Truncate hash for display
            hash_display = result.hash_md5
            if len(hash_display) > 12:
                hash_display = hash_display[:10] + "..."
            
            table.add_row(
                str(idx),
                result.email,
                password_display,
                result.source,
                hash_display
            )
        
        console.print(table)
        
        # Display statistics
        stats_panel = Panel.fit(
            f"[bold cyan]Total Found:[/bold cyan] {self.stats['total_found']}\n"
            f"[bold cyan]Unique Emails:[/bold cyan] {self.stats['unique_emails']}\n"
            f"[bold cyan]Unique Passwords:[/bold cyan] {self.stats['unique_passwords']}\n"
            f"[bold cyan]Search Duration:[/bold cyan] {self.stats['search_duration']:.2f} seconds\n"
            f"[bold cyan]Sources Checked:[/bold cyan] {', '.join(self.args.sources)}",
            title="[bold]📊 Statistics[/bold]",
            border_style="cyan"
        )
        console.print(stats_panel)
        
        # Display export information if output is specified
        if self.args.output:
            console.print(f"[green][✓] Results will be saved to: [bold]{self.args.output}[/bold]")
    
    def save_results(self, results: List[SearchResult]):
        """Save results to file in JSON format"""
        if not self.args.output:
            return
        
        output_format = self.args.output.split('.')[-1].lower()
        
        try:
            if output_format == 'json':
                # Convert results to dictionary
                data = {
                    'metadata': {
                        'tool': 'MailFox',
                        'version': '2.0',
                        'author': '@JoelGMSec',
                        'website': 'https://darkbyte.net',
                        'search_date': datetime.now().isoformat(),
                        'target': self.args.target,
                        'mode': self.args.mode,
                        'sources': self.args.sources,
                        'statistics': self.stats
                    },
                    'results': [asdict(r) for r in results]
                }
                
                with open(self.args.output, 'w') as f:
                    json.dump(data, f, indent=2, default=str)
                    
            elif output_format == 'txt' or output_format == 'text':
                # Save as text
                with open(self.args.output, 'w') as f:
                    f.write("=" * 60 + "\n")
                    f.write("MailFox - Email Breach Scanner Results\n")
                    f.write("=" * 60 + "\n")
                    f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Target: {self.args.target}\n")
                    f.write(f"Mode: {self.args.mode}\n")
                    f.write(f"Sources: {', '.join(self.args.sources)}\n")
                    f.write("=" * 60 + "\n\n")
                    
                    for idx, result in enumerate(results, 1):
                        f.write(f"Result #{idx}\n")
                        f.write(f"  Email: {result.email}\n")
                        f.write(f"  Password: {result.password}\n")
                        f.write(f"  Source: {result.source}\n")
                        f.write(f"  Found At: {result.found_at}\n")
                        f.write(f"  MD5 Hash: {result.hash_md5}\n")
                        f.write(f"  SHA1 Hash: {result.hash_sha1}\n")
                        f.write(f"  SHA256 Hash: {result.hash_sha256}\n")
                        f.write("-" * 40 + "\n")
            
            elif output_format == 'csv':
                # Save as CSV
                import csv
                with open(self.args.output, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Email', 'Password', 'Source', 'Found At', 'MD5', 'SHA1', 'SHA256'])
                    for result in results:
                        writer.writerow([
                            result.email,
                            result.password,
                            result.source,
                            result.found_at,
                            result.hash_md5,
                            result.hash_sha1,
                            result.hash_sha256
                        ])
            
            console.print(f"[green][✓] Results saved to: {self.args.output}")
            
        except Exception as e:
            console.print(f"[red][!] Error saving results: {e}")
    
    def interactive_mode(self):
        """Run in interactive mode"""
        console.print("[bold cyan]🐺 MailFox Interactive Mode[/bold cyan]\n")
        
        # Get search mode
        mode_options = {
            "1": ("email", "Search by email address"),
            "2": ("domain", "Search by domain (e.g., @company.com)"),
            "3": ("password", "Search by password"),
            "4": ("username", "Search by username")
        }
        
        console.print("[bold]Select search mode:[/bold]")
        for key, (mode_name, desc) in mode_options.items():
            console.print(f"  [cyan]{key}[/cyan]. {mode_name.title()} - {desc}")
        
        mode_choice = Prompt.ask("\n[bold]Enter choice[/bold]", choices=list(mode_options.keys()), default="1")
        mode = mode_options[mode_choice][0]
        
        # Get target
        if mode == "domain":
            target = Prompt.ask("[bold]Enter domain[/bold] (e.g., company.com)", default="")
            if target and not target.startswith("@"):
                target = f"@{target}"
        else:
            target = Prompt.ask(f"[bold]Enter {mode}[/bold]")
        
        # Get sources
        source_options = {
            "1": ["all"],
            "2": ["proxynova"],
            "3": ["local"],
            "4": ["proxynova", "local"]
        }
        
        console.print("\n[bold]Select data sources:[/bold]")
        console.print("  [cyan]1[/cyan]. All sources")
        console.print("  [cyan]2[/cyan]. ProxyNova only")
        console.print("  [cyan]3[/cyan]. Local database only")
        console.print("  [cyan]4[/cyan]. Both ProxyNova and local database")
        
        source_choice = Prompt.ask("\n[bold]Enter choice[/bold]", choices=list(source_options.keys()), default="1")
        sources = source_options[source_choice]
        
        # If local database selected, ask for file
        database = None
        if "local" in sources or sources == ["all"]:
            use_local = Confirm.ask("[bold]Use local database file?[/bold]", default=True)
            if use_local:
                database = Prompt.ask(
                    "[bold]Local database path[/bold]",
                    default="./leaks.txt"
                )
        
        # Get limit
        limit = int(Prompt.ask(
            "[bold]Maximum results to display[/bold]",
            default="25"
        ))
        
        # Ask for output file
        save_output = Confirm.ask("[bold]Save results to file?[/bold]", default=True)
        output_file = None
        if save_output:
            format_choice = Prompt.ask(
                "[bold]Output format[/bold]",
                choices=["json", "txt", "csv"],
                default="json"
            )
            output_file = Prompt.ask(
                "[bold]Output filename[/bold]",
                default=f"mailfox_{mode}_{int(time.time())}.{format_choice}"
            )
        
        # Use proxy
        use_proxy = Confirm.ask("[bold]Use proxy?[/bold]", default=False)
        proxy = None
        if use_proxy:
            proxy = Prompt.ask(
                "[bold]Proxy URL[/bold]",
                default="http://localhost:8080"
            )
        
        # Update args
        self.args.mode = mode
        self.args.target = target
        self.args.sources = sources
        self.args.database = database
        self.args.limit = limit
        self.args.output = output_file
        self.args.proxy = proxy
        
        # Clear screen and run search
        console.clear()
        return self.run_search()
    
    def run_search(self):
        """Main search execution"""
        self.display_banner()
        
        if self.args.mode == 'interactive':
            return self.interactive_mode()
        
        console.print(f"[cyan][*] Starting [bold]{self.args.mode}[/bold] search for: [bold]{self.args.target}[/bold]")
        console.print(f"[cyan][*] Sources: [bold]{', '.join(self.args.sources)}[/bold]")
        console.print(f"[cyan][*] Limit: [bold]{self.args.limit}[/bold] results")
        
        # Perform search
        if self.args.sources == ['all'] or 'proxynova' in self.args.sources:
            results = self.search_proxynova(self.args.target)
        elif 'local' in self.args.sources and self.args.database:
            results = self.search_local_database(self.args.target)
        else:
            results = self.search_multiple_sources(self.args.target)
        
        # Display results
        if results:
            self.display_results(results)
            
            # Save results if output specified
            if self.args.output:
                self.save_results(results)
        else:
            console.print("[yellow][!] No leaks found for the given target!")
        
        return len(results)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="🐺 MailFox - Advanced Email Breach Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t victim@company.com              # Search email in ProxyNova
  %(prog)s -t "@company.com" -m domain        # Search all emails from domain
  %(prog)s -t "password123" -m password       # Search password in leaks
  %(prog)s -i                                  # Interactive mode
  %(prog)s -t admin@test.com -s local -d leaks.txt  # Search local database
  %(prog)s -t user@domain.com -o results.json       # Save as JSON
  %(prog)s -t user@domain.com -f csv -o results.csv # Save as CSV
        
        """
    )
    
    # Search options
    search_group = parser.add_argument_group("Search Options")
    search_group.add_argument("-t", "--target", help="Target email/domain/password to search")
    search_group.add_argument("-m", "--mode", choices=["email", "domain", "password", "username", "interactive"],
                            default="email", help="Search mode")
    search_group.add_argument("-s", "--sources", nargs="+", choices=["all", "proxynova", "local"],
                            default=["all"], help="Data sources to search")
    
    # Database options
    db_group = parser.add_argument_group("Database Options")
    db_group.add_argument("-d", "--database", help="Local database file (JSON/text)")
    db_group.add_argument("-l", "--limit", type=int, default=25,
                         help="Maximum results to display (default: 25)")
    
    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("-o", "--output", help="Save results to file")
    output_group.add_argument("-f", "--format", choices=["json", "txt", "csv"],
                            default="json", help="Output format (default: json)")
    output_group.add_argument("-v", "--verbose", action="store_true",
                            help="Verbose output")
    
    # Connection options
    conn_group = parser.add_argument_group("Connection Options")
    conn_group.add_argument("-p", "--proxy", help="HTTP/HTTPS proxy (e.g., http://127.0.0.1:8080)")
    conn_group.add_argument("-T", "--timeout", type=int, default=30,
                           help="Request timeout in seconds")
    conn_group.add_argument("--no-verify", action="store_true",
                           help="Disable SSL certificate verification")
    
    # Display options
    display_group = parser.add_argument_group("Display Options")
    display_group.add_argument("-c", "--clear-screen", action="store_true",
                             help="Clear screen before displaying banner")
    display_group.add_argument("--no-color", action="store_true",
                             help="Disable colored output")
    
    # Interactive mode
    parser.add_argument("-i", "--interactive", action="store_true",
                       help="Launch interactive mode")
    
    args = parser.parse_args()
    
    # Handle interactive mode
    if args.interactive or not args.target:
        args.mode = "interactive"
    
    # Set output format based on file extension if not specified
    if args.output and not args.format:
        ext = args.output.split('.')[-1].lower()
        if ext in ['json', 'txt', 'csv']:
            args.format = ext
    
    # Initialize and run scanner
    try:
        scanner = MailFox(args)
        results_count = scanner.run_search()
        sys.exit(0 if results_count > 0 else 1)
        
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Scan interrupted by user!")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red][!] Critical error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
