"""
Main reconnaissance engine for Bug Scan Pro
Handles subdomain enumeration, DNS resolution, and passive discovery
Created by @lonefaisal - Made with ♥️ by @lonefaisal
"""

import asyncio
import aiohttp
import dns.resolver
import dns.asyncresolver
import random
import string
from typing import List, Dict, Any, Optional, Set
from pathlib import Path
import json
import csv
import time

from rich.console import Console
from rich.progress import Progress, TaskID, BarColumn, TextColumn, TimeRemainingColumn

from .resolver import DNSResolver
from .httpcheck import HTTPChecker
from .sources.crtsh import CrtShSource
from .sources.otx import OTXSource
from .output import OutputManager
from .utils import is_valid_hostname, create_semaphore

console = Console()


class ReconEngine:
    """Main reconnaissance engine for subdomain discovery"""
    
    def __init__(
        self,
        threads: int = 100,
        timeout: int = 10,
        proxy: Optional[str] = None,
        user_agent: str = "bug-scan-pro/1.0",
        silent: bool = False,
        verbose: bool = False
    ):
        self.threads = threads
        self.timeout = timeout
        self.proxy = proxy
        self.user_agent = user_agent
        self.silent = silent
        self.verbose = verbose
        
        # Initialize components
        self.dns_resolver = DNSResolver(threads=threads, timeout=timeout//2)
        self.http_checker = HTTPChecker(
            threads=min(threads, 50),  # Limit HTTP threads
            timeout=timeout,
            proxy=proxy,
            user_agent=user_agent
        )
        
        # Initialize passive sources
        self.crtsh_source = CrtShSource()
        self.otx_source = OTXSource()
        
        self.output_manager = OutputManager()
        
        # Tracking
        self.wildcard_ips: Set[str] = set()
        self.results: List[Dict[str, Any]] = []
        
    async def load_targets_from_file(self, file_path: str) -> List[str]:
        """Load target domains from file"""
        targets = []
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if is_valid_hostname(line):
                            targets.append(line)
                        elif self.verbose:
                            console.print(f"[yellow]Invalid hostname: {line}[/yellow]")
        except FileNotFoundError:
            raise FileNotFoundError(f"Target file not found: {file_path}")
        except Exception as e:
            raise Exception(f"Error reading target file: {e}")
            
        if not targets:
            raise ValueError("No valid targets found in file")
            
        return targets
    
    async def load_wordlist(self, wordlist_path: str) -> List[str]:
        """Load subdomain wordlist from file"""
        wordlist = []
        try:
            with open(wordlist_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Remove any protocol or suffix from wordlist entries
                        subdomain = line.split('.')[0] if '.' in line else line
                        if subdomain.isalnum() or '-' in subdomain or '_' in subdomain:
                            wordlist.append(subdomain)
        except FileNotFoundError:
            raise FileNotFoundError(f"Wordlist file not found: {wordlist_path}")
        except Exception as e:
            raise Exception(f"Error reading wordlist: {e}")
            
        return list(set(wordlist))  # Remove duplicates
    
    async def detect_wildcard_dns(self, domain: str) -> bool:
        """Detect if domain has wildcard DNS configuration"""
        if not self.silent:
            console.print(f"[blue]Checking wildcard DNS for {domain}...[/blue]")
        
        # Generate random subdomains
        random_subs = []
        for _ in range(3):
            rand_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
            random_subs.append(f"{rand_str}.{domain}")
        
        wildcard_responses = set()
        
        for sub in random_subs:
            try:
                ips = await self.dns_resolver.resolve_hostname(sub)
                if ips:
                    wildcard_responses.update(ips)
            except Exception:
                pass
        
        if wildcard_responses:
            self.wildcard_ips = wildcard_responses
            if not self.silent:
                console.print(f"[yellow]Wildcard DNS detected for {domain}: {', '.join(wildcard_responses)}[/yellow]")
            return True
        
        return False
    
    async def discover_passive_subdomains(self, domain: str) -> Set[str]:
        """Discover subdomains using passive sources"""
        if not self.silent:
            console.print(f"[blue]Discovering subdomains from passive sources for {domain}...[/blue]")
        
        all_subdomains = set()
        
        # Certificate Transparency
        try:
            crt_subs = await self.crtsh_source.get_subdomains(domain)
            all_subdomains.update(crt_subs)
            if self.verbose:
                console.print(f"[green]Found {len(crt_subs)} subdomains from crt.sh[/green]")
        except Exception as e:
            if self.verbose:
                console.print(f"[red]Error with crt.sh: {e}[/red]")
        
        # OTX (if API key available)
        try:
            otx_subs = await self.otx_source.get_subdomains(domain)
            all_subdomains.update(otx_subs)
            if self.verbose:
                console.print(f"[green]Found {len(otx_subs)} subdomains from OTX[/green]")
        except Exception as e:
            if self.verbose:
                console.print(f"[red]Error with OTX: {e}[/red]")
        
        return all_subdomains
    
    async def brute_force_subdomains(self, domain: str, wordlist: List[str]) -> Set[str]:
        """Brute force subdomains using wordlist"""
        if not wordlist:
            return set()
        
        if not self.silent:
            console.print(f"[blue]Brute forcing subdomains for {domain} with {len(wordlist)} words...[/blue]")
        
        found_subdomains = set()
        semaphore = create_semaphore(self.threads)
        
        async def check_subdomain(sub: str):
            async with semaphore:
                hostname = f"{sub}.{domain}"
                try:
                    ips = await self.dns_resolver.resolve_hostname(hostname)
                    if ips and not self.is_wildcard_response(ips):
                        found_subdomains.add(hostname)
                        if self.verbose:
                            console.print(f"[green]Found: {hostname} -> {', '.join(ips)}[/green]")
                except Exception:
                    pass
        
        # Create tasks for brute force
        tasks = [check_subdomain(sub) for sub in wordlist]
        
        if not self.silent:
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("({task.completed}/{task.total})"),
                TimeRemainingColumn(),
                console=console
            ) as progress:
                task = progress.add_task(f"Brute forcing {domain}", total=len(tasks))
                
                for coro in asyncio.as_completed(tasks):
                    await coro
                    progress.advance(task)
        else:
            await asyncio.gather(*tasks, return_exceptions=True)
        
        return found_subdomains
    
    def is_wildcard_response(self, ips: List[str]) -> bool:
        """Check if IPs match wildcard responses"""
        if not self.wildcard_ips:
            return False
        return bool(set(ips) & self.wildcard_ips)
    
    async def resolve_subdomains(self, subdomains: Set[str]) -> List[Dict[str, Any]]:
        """Resolve list of subdomains to IPs"""
        if not subdomains:
            return []
        
        if not self.silent:
            console.print(f"[blue]Resolving {len(subdomains)} subdomains...[/blue]")
        
        resolved_results = []
        semaphore = create_semaphore(self.threads)
        
        async def resolve_single(hostname: str):
            async with semaphore:
                try:
                    ips = await self.dns_resolver.resolve_hostname(hostname)
                    if ips and not self.is_wildcard_response(ips):
                        result = {
                            'host': hostname,
                            'resolved': True,
                            'ips': ips,
                            'timestamp': int(time.time())
                        }
                        resolved_results.append(result)
                        return result
                except Exception as e:
                    if self.verbose:
                        console.print(f"[red]Failed to resolve {hostname}: {e}[/red]")
                
                return {
                    'host': hostname,
                    'resolved': False,
                    'ips': [],
                    'timestamp': int(time.time())
                }
        
        tasks = [resolve_single(hostname) for hostname in subdomains]
        
        if not self.silent:
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("({task.completed}/{task.total})"),
                TimeRemainingColumn(),
                console=console
            ) as progress:
                task = progress.add_task("Resolving subdomains", total=len(tasks))
                
                for coro in asyncio.as_completed(tasks):
                    await coro
                    progress.advance(task)
        else:
            await asyncio.gather(*tasks, return_exceptions=True)
        
        return resolved_results
    
    async def check_http_reachability(self, resolved_hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check HTTP/HTTPS reachability for resolved hosts"""
        if not resolved_hosts:
            return []
        
        if not self.silent:
            console.print(f"[blue]Checking HTTP reachability for {len(resolved_hosts)} hosts...[/blue]")
        
        # Extract hostnames for HTTP checking
        hostnames = [r['host'] for r in resolved_hosts if r.get('resolved', False)]
        
        if not hostnames:
            return resolved_hosts
        
        # Check HTTP reachability
        http_results = await self.http_checker.check_hosts_reachability(hostnames)
        
        # Merge HTTP results with DNS results
        http_lookup = {r['host']: r for r in http_results}
        
        for result in resolved_hosts:
            hostname = result['host']
            if hostname in http_lookup:
                http_data = http_lookup[hostname]
                result['http'] = {
                    'reachable': http_data.get('reachable', False),
                    'status': http_data.get('status'),
                    'scheme': http_data.get('scheme'),
                    'server': http_data.get('server'),
                    'title': http_data.get('title'),
                    'response_time': http_data.get('response_time')
                }
        
        return resolved_hosts
    
    async def scan_single_domain(
        self,
        domain: str,
        wordlist: Optional[List[str]] = None,
        resolve_only: bool = False,
        alive_only: bool = False
    ) -> List[Dict[str, Any]]:
        """Scan a single domain for subdomains"""
        if not self.silent:
            console.print(f"\n[bold green]Starting reconnaissance for: {domain}[/bold green]")
        
        # Step 1: Detect wildcard DNS
        has_wildcard = await self.detect_wildcard_dns(domain)
        
        # Step 2: Passive subdomain discovery
        passive_subs = await self.discover_passive_subdomains(domain)
        
        # Step 3: Brute force (if wordlist provided)
        brute_subs = set()
        if wordlist:
            brute_subs = await self.brute_force_subdomains(domain, wordlist)
        
        # Step 4: Combine all discovered subdomains
        all_subdomains = passive_subs | brute_subs
        
        # Add the root domain
        all_subdomains.add(domain)
        
        if not self.silent:
            console.print(f"[green]Total unique subdomains discovered: {len(all_subdomains)}[/green]")
        
        # Step 5: DNS Resolution
        resolved_results = await self.resolve_subdomains(all_subdomains)
        
        # Filter only resolved hosts if requested
        if resolve_only or alive_only:
            resolved_results = [r for r in resolved_results if r.get('resolved', False)]
        
        # Step 6: HTTP Checking (if not resolve_only)
        if not resolve_only and resolved_results:
            resolved_results = await self.check_http_reachability(resolved_results)
        
        # Filter only alive hosts if requested
        if alive_only:
            resolved_results = [
                r for r in resolved_results 
                if r.get('http', {}).get('reachable', False)
            ]
        
        # Add metadata
        for result in resolved_results:
            result['root'] = domain
            result['wildcard_detected'] = has_wildcard
        
        return resolved_results
    
    async def scan_targets(
        self,
        targets: List[str],
        wordlist: Optional[List[str]] = None,
        resolve_only: bool = False,
        alive_only: bool = False
    ) -> List[Dict[str, Any]]:
        """Scan multiple target domains"""
        all_results = []
        
        for i, target in enumerate(targets, 1):
            if not self.silent:
                console.print(f"\n[bold cyan]Processing target {i}/{len(targets)}: {target}[/bold cyan]")
            
            try:
                results = await self.scan_single_domain(
                    domain=target,
                    wordlist=wordlist,
                    resolve_only=resolve_only,
                    alive_only=alive_only
                )
                all_results.extend(results)
                
                if not self.silent:
                    console.print(f"[green]Found {len(results)} results for {target}[/green]")
                    
            except Exception as e:
                console.print(f"[red]Error scanning {target}: {e}[/red]")
                continue
        
        if not self.silent:
            console.print(f"\n[bold green]Total results: {len(all_results)}[/bold green]")
        
        return all_results
    
    async def save_results(
        self,
        results: List[Dict[str, Any]],
        txt_file: Optional[str] = None,
        json_file: Optional[str] = None,
        csv_file: Optional[str] = None,
        append_mode: bool = False
    ) -> None:
        """Save results to various output formats"""
        if not results:
            if not self.silent:
                console.print("[yellow]No results to save[/yellow]")
            return
        
        # Save TXT format
        if txt_file:
            await self.output_manager.save_txt(
                results=results,
                filename=txt_file,
                append=append_mode
            )
            if not self.silent:
                console.print(f"[green]Results saved to {txt_file}[/green]")
        
        # Save JSON format
        if json_file:
            await self.output_manager.save_json(
                results=results,
                filename=json_file,
                append=append_mode
            )
            if not self.silent:
                console.print(f"[green]Results saved to {json_file}[/green]")
        
        # Save CSV format
        if csv_file:
            await self.output_manager.save_csv(
                results=results,
                filename=csv_file,
                append=append_mode
            )
            if not self.silent:
                console.print(f"[green]Results saved to {csv_file}[/green]")
        
        # Print to console if no output files specified
        if not any([txt_file, json_file, csv_file]):
            for result in results:
                if result.get('resolved', False):
                    console.print(result['host'])


if __name__ == "__main__":
    # Test the recon engine
    import sys
    
    async def test_recon():
        engine = ReconEngine(threads=50, verbose=True)
        
        if len(sys.argv) < 2:
            print("Usage: python recon.py <domain>")
            sys.exit(1)
        
        domain = sys.argv[1]
        results = await engine.scan_single_domain(domain)
        
        print(f"\nFound {len(results)} results:")
        for result in results:
            print(f"{result['host']} -> {result.get('ips', [])}")
    
    asyncio.run(test_recon())