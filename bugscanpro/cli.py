"""
CLI module for Bug Scan Pro
Handles argument parsing and subcommands
Created by @lonefaisal - Made with ♥️ by @lonefaisal
"""

import argparse
import asyncio
import sys
from typing import List, Optional, Dict, Any
from pathlib import Path

from rich.console import Console
from rich.text import Text

from . import __version__, __author__
from .recon import ReconEngine
from .httpcheck import HTTPChecker
from .sslcheck import SSLChecker
from .portscan import PortScanner
from .cidrscan import CIDRScanner
from .dnsinfo import DNSLookup
from .pingcheck import PingChecker
from .iplookup import IPLookup
from .utils import FileToolkit

console = Console()


def print_banner() -> None:
    """Print the bug-scan-pro banner"""
    banner = Text()
    banner.append("╔═══════════════════════════════════════════════════════════════════════════╗\n", style="red")
    banner.append("║  ██████╗ ███████╗███████╗    ███████╗ ███████╗ ███████╗███████╗ ║\n", style="red")
    banner.append("║  ██╔══██║██╔════╝██╔════╝    ██╔════╝██╔════╝ ██╔══██║██╔════╝ ║\n", style="red")
    banner.append("║  ██████╔╝█████╗  █████╗      █████╗  ███████╗██████╔╝██║  ████  ║\n", style="red")
    banner.append("║  ██╔══██╗██╔══╝  ██╔══╝      ██╔══╝  ██╔════╝██╔══██╗██║   ██║  ║\n", style="red")
    banner.append("║  ██║  ██║███████╗███████╗    ███████╗███████╗██║  ██║╚██████╔╝  ║\n", style="red")
    banner.append("║  ╚═╝  ╚═╝╚══════╝╚══════╝    ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝   ║\n", style="red")
    banner.append("╚═══════════════════════════════════════════════════════════════════════════╝\n", style="red")
    banner.append(f"\n    Professional Bug Host Discovery & Network Reconnaissance Toolkit v{__version__}\n", style="bold cyan")
    banner.append(f"    Made with ♥️ by @lonefaisal | Telegram: @lonefaisal\n", style="green")
    
    console.print(banner)


def create_parser() -> argparse.ArgumentParser:
    """Create the main argument parser with all subcommands"""
    parser = argparse.ArgumentParser(
        prog="bug-scan-pro",
        description="Professional async-based bug host discovery and network reconnaissance toolkit",
        epilog=f"Made with ♥️ by @lonefaisal | Version {__version__}",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version=f"bug-scan-pro v{__version__} by {__author__}"
    )
    
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Disable banner display"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Main scan subcommand
    scan_parser = subparsers.add_parser(
        "scan",
        help="Main subdomain enumeration with DNS resolution and optional HTTP checking"
    )
    scan_group = scan_parser.add_mutually_exclusive_group(required=True)
    scan_group.add_argument("-d", "--domain", help="Target domain to scan")
    scan_group.add_argument("-l", "--list", help="File containing list of domains")
    
    scan_parser.add_argument("-w", "--wordlist", help="Wordlist for subdomain brute-force")
    scan_parser.add_argument("-t", "--threads", type=int, default=100, help="Number of concurrent threads (default: 100)")
    scan_parser.add_argument("-o", "--output", help="Output file path")
    scan_parser.add_argument("--json", help="JSON output file")
    scan_parser.add_argument("--csv", help="CSV output file")
    scan_parser.add_argument("--append", action="store_true", help="Append to output file")
    scan_parser.add_argument("--resolve-only", action="store_true", help="Only resolve DNS, no HTTP checking")
    scan_parser.add_argument("--alive-only", action="store_true", help="Only return HTTP reachable hosts")
    scan_parser.add_argument("--proxy", help="Proxy URL (http://ip:port or socks5://ip:port)")
    scan_parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    scan_parser.add_argument("--user-agent", default="bug-scan-pro/1.0", help="Custom User-Agent")
    scan_parser.add_argument("--silent", action="store_true", help="Silent mode - no progress output")
    scan_parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    # Advanced HTTP scanner
    scanpro_parser = subparsers.add_parser(
        "scan-pro",
        help="Advanced HTTP scanner with method selection, status filtering, header/body matching"
    )
    scanpro_parser.add_argument("-i", "--input", required=True, help="Input file with hosts")
    scanpro_parser.add_argument("-o", "--output", help="Output file path")
    scanpro_parser.add_argument("--methods", default="GET", help="HTTP methods (comma-separated)")
    scanpro_parser.add_argument("--status-include", help="Include specific status codes (comma-separated)")
    scanpro_parser.add_argument("--status-exclude", help="Exclude specific status codes (comma-separated)")
    scanpro_parser.add_argument("--non-302", action="store_true", help="Exclude 302 redirects")
    scanpro_parser.add_argument("--header-has", help="Filter by header content")
    scanpro_parser.add_argument("--contains", help="Filter by response body content")
    scanpro_parser.add_argument("--threads", type=int, default=50, help="Concurrent threads")
    scanpro_parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    scanpro_parser.add_argument("--proxy", help="Proxy URL")
    scanpro_parser.add_argument("--user-agent", default="bug-scan-pro/1.0", help="User-Agent")
    scanpro_parser.add_argument("--json", help="JSON output file")
    
    # Pure subdomain enumeration
    subfinder_parser = subparsers.add_parser(
        "subfinder",
        help="Pure subdomain enumeration (no HTTP checking)"
    )
    subfinder_group = subfinder_parser.add_mutually_exclusive_group(required=True)
    subfinder_group.add_argument("-d", "--domain", help="Target domain")
    subfinder_group.add_argument("-l", "--list", help="Domain list file")
    
    subfinder_parser.add_argument("-w", "--wordlist", help="Subdomain wordlist")
    subfinder_parser.add_argument("-t", "--threads", type=int, default=100, help="Concurrent threads")
    subfinder_parser.add_argument("-o", "--output", help="Output file")
    subfinder_parser.add_argument("--append", action="store_true", help="Append to output")
    subfinder_parser.add_argument("--silent", action="store_true", help="Silent mode")
    
    # SSL/TLS certificate inspection
    ssl_parser = subparsers.add_parser(
        "ssl",
        help="TLS/SNI certificate inspection"
    )
    ssl_group = ssl_parser.add_mutually_exclusive_group(required=True)
    ssl_group.add_argument("-H", "--host", help="Single host to check")
    ssl_group.add_argument("-i", "--input", help="Input file with hosts")
    
    ssl_parser.add_argument("-p", "--port", type=int, default=443, help="Port to check (default: 443)")
    ssl_parser.add_argument("-t", "--threads", type=int, default=50, help="Concurrent threads")
    ssl_parser.add_argument("-o", "--output", help="Output file")
    ssl_parser.add_argument("--json", help="JSON output file")
    ssl_parser.add_argument("--timeout", type=int, default=10, help="Connection timeout")
    ssl_parser.add_argument("--silent", action="store_true", help="Silent mode")
    
    # ICMP ping checker
    ping_parser = subparsers.add_parser(
        "ping",
        help="ICMP ping checker for host lists"
    )
    ping_group = ping_parser.add_mutually_exclusive_group(required=True)
    ping_group.add_argument("-H", "--host", help="Single host to ping")
    ping_group.add_argument("-i", "--input", help="Input file with hosts")
    
    ping_parser.add_argument("-c", "--count", type=int, default=3, help="Ping count (default: 3)")
    ping_parser.add_argument("-t", "--threads", type=int, default=50, help="Concurrent threads")
    ping_parser.add_argument("-o", "--output", help="Output file")
    ping_parser.add_argument("--json", help="JSON output")
    ping_parser.add_argument("--timeout", type=int, default=5, help="Ping timeout")
    ping_parser.add_argument("--alive-only", action="store_true", help="Only show alive hosts")
    
    # DNS record lookup
    dns_parser = subparsers.add_parser(
        "dns",
        help="DNS record lookup (A, AAAA, CNAME, MX, NS, TXT)"
    )
    dns_group = dns_parser.add_mutually_exclusive_group(required=True)
    dns_group.add_argument("-H", "--host", help="Single host to lookup")
    dns_group.add_argument("-i", "--input", help="Input file with hosts")
    
    dns_parser.add_argument("-r", "--record-type", default="A", help="DNS record type (default: A)")
    dns_parser.add_argument("-t", "--threads", type=int, default=50, help="Concurrent threads")
    dns_parser.add_argument("-o", "--output", help="Output file")
    dns_parser.add_argument("--json", help="JSON output")
    dns_parser.add_argument("--resolver", help="Custom DNS resolver")
    
    # Port scanner
    ports_parser = subparsers.add_parser(
        "ports",
        help="Port scanner for single hosts"
    )
    ports_parser.add_argument("-H", "--host", required=True, help="Target host")
    ports_parser.add_argument("-p", "--ports", default="80,443", help="Ports to scan (comma-separated)")
    ports_parser.add_argument("-t", "--threads", type=int, default=100, help="Concurrent threads")
    ports_parser.add_argument("-o", "--output", help="Output file")
    ports_parser.add_argument("--json", help="JSON output")
    ports_parser.add_argument("--timeout", type=int, default=3, help="Connection timeout")
    ports_parser.add_argument("--open-only", action="store_true", help="Only show open ports")
    
    # CIDR range scanning
    cidr_parser = subparsers.add_parser(
        "cidr",
        help="CIDR range port scanning"
    )
    cidr_parser.add_argument("--cidr", required=True, help="CIDR range (e.g., 192.168.1.0/24)")
    cidr_parser.add_argument("-p", "--ports", default="80,443", help="Ports to scan")
    cidr_parser.add_argument("-t", "--threads", type=int, default=100, help="Concurrent threads")
    cidr_parser.add_argument("-o", "--output", help="Output file")
    cidr_parser.add_argument("--json", help="JSON output")
    cidr_parser.add_argument("--timeout", type=int, default=3, help="Connection timeout")
    cidr_parser.add_argument("--alive-only", action="store_true", help="Only alive hosts")
    
    # IP reverse lookup
    iplookup_parser = subparsers.add_parser(
        "ip-lookup",
        help="Reverse PTR lookup"
    )
    iplookup_group = iplookup_parser.add_mutually_exclusive_group(required=True)
    iplookup_group.add_argument("-H", "--host", help="Single IP to lookup")
    iplookup_group.add_argument("-i", "--input", help="Input file with IPs")
    
    iplookup_parser.add_argument("-t", "--threads", type=int, default=50, help="Concurrent threads")
    iplookup_parser.add_argument("-o", "--output", help="Output file")
    iplookup_parser.add_argument("--json", help="JSON output")
    iplookup_parser.add_argument("--timeout", type=int, default=5, help="Lookup timeout")
    
    # File toolkit
    file_parser = subparsers.add_parser(
        "file",
        help="File toolkit (split, merge, clean, dedupe, filter operations)"
    )
    file_subparsers = file_parser.add_subparsers(dest="file_command", help="File operations")
    
    # File split
    split_parser = file_subparsers.add_parser("split", help="Split large files")
    split_parser.add_argument("-i", "--input", required=True, help="Input file")
    split_parser.add_argument("--parts", type=int, required=True, help="Number of parts")
    split_parser.add_argument("-o", "--output", help="Output prefix")
    
    # File merge
    merge_parser = file_subparsers.add_parser("merge", help="Merge multiple files")
    merge_parser.add_argument("-i", "--input", required=True, help="File list or pattern")
    merge_parser.add_argument("-o", "--output", required=True, help="Output file")
    merge_parser.add_argument("--dedupe", action="store_true", help="Remove duplicates")
    
    # File clean
    clean_parser = file_subparsers.add_parser("clean", help="Extract valid hostnames")
    clean_parser.add_argument("-i", "--input", required=True, help="Input file")
    clean_parser.add_argument("-o", "--output", required=True, help="Output file")
    
    # File dedupe
    dedupe_parser = file_subparsers.add_parser("dedupe", help="Remove duplicates")
    dedupe_parser.add_argument("-i", "--input", required=True, help="Input file")
    dedupe_parser.add_argument("-o", "--output", required=True, help="Output file")
    
    # Filter TLD
    filter_tld_parser = file_subparsers.add_parser("filter-tld", help="Filter by TLD")
    filter_tld_parser.add_argument("-i", "--input", required=True, help="Input file")
    filter_tld_parser.add_argument("-o", "--output", required=True, help="Output file")
    filter_tld_parser.add_argument("--tlds", required=True, help="TLDs to filter (comma-separated)")
    
    # Filter keywords
    filter_key_parser = file_subparsers.add_parser("filter-key", help="Filter by keywords")
    filter_key_parser.add_argument("-i", "--input", required=True, help="Input file")
    filter_key_parser.add_argument("-o", "--output", required=True, help="Output file")
    filter_key_parser.add_argument("--keywords", required=True, help="Keywords (comma-separated)")
    
    # CIDR to IP
    cidr_to_ip_parser = file_subparsers.add_parser("cidr-to-ip", help="Expand CIDR ranges")
    cidr_to_ip_parser.add_argument("-i", "--input", required=True, help="Input file with CIDRs")
    cidr_to_ip_parser.add_argument("-o", "--output", required=True, help="Output file")
    
    # Domain to IP
    domain_to_ip_parser = file_subparsers.add_parser("domain-to-ip", help="Resolve domains to IPs")
    domain_to_ip_parser.add_argument("-i", "--input", required=True, help="Input file with domains")
    domain_to_ip_parser.add_argument("-o", "--output", required=True, help="Output file")
    domain_to_ip_parser.add_argument("-t", "--threads", type=int, default=50, help="Concurrent threads")
    
    return parser


async def main() -> None:
    """Main CLI entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        if not args.no_banner:
            print_banner()
        parser.print_help()
        return
    
    if not args.no_banner and not getattr(args, 'silent', False):
        print_banner()
    
    try:
        # Route to appropriate handler based on command
        if args.command == "scan":
            await handle_scan_command(args)
        elif args.command == "scan-pro":
            await handle_scanpro_command(args)
        elif args.command == "subfinder":
            await handle_subfinder_command(args)
        elif args.command == "ssl":
            await handle_ssl_command(args)
        elif args.command == "ping":
            await handle_ping_command(args)
        elif args.command == "dns":
            await handle_dns_command(args)
        elif args.command == "ports":
            await handle_ports_command(args)
        elif args.command == "cidr":
            await handle_cidr_command(args)
        elif args.command == "ip-lookup":
            await handle_iplookup_command(args)
        elif args.command == "file":
            await handle_file_command(args)
        else:
            console.print(f"[red]Unknown command: {args.command}[/red]")
            parser.print_help()
            
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if getattr(args, 'verbose', False):
            import traceback
            console.print(traceback.format_exc())


async def handle_scan_command(args) -> None:
    """Handle main scan command"""
    engine = ReconEngine(
        threads=args.threads,
        timeout=args.timeout,
        proxy=args.proxy,
        user_agent=args.user_agent,
        silent=args.silent,
        verbose=args.verbose
    )
    
    if args.domain:
        targets = [args.domain]
    else:
        targets = await engine.load_targets_from_file(args.list)
    
    wordlist = None
    if args.wordlist:
        wordlist = await engine.load_wordlist(args.wordlist)
    
    results = await engine.scan_targets(
        targets=targets,
        wordlist=wordlist,
        resolve_only=args.resolve_only,
        alive_only=args.alive_only
    )
    
    await engine.save_results(
        results=results,
        txt_file=args.output,
        json_file=args.json,
        csv_file=args.csv,
        append_mode=args.append
    )


async def handle_scanpro_command(args) -> None:
    """Handle scan-pro command"""
    checker = HTTPChecker(
        threads=args.threads,
        timeout=args.timeout,
        proxy=args.proxy,
        user_agent=args.user_agent
    )
    
    hosts = await checker.load_hosts_from_file(args.input)
    methods = [m.strip().upper() for m in args.methods.split(",")]
    
    status_include = None
    if args.status_include:
        status_include = [int(s) for s in args.status_include.split(",")]
    
    status_exclude = None
    if args.status_exclude:
        status_exclude = [int(s) for s in args.status_exclude.split(",")]
    
    if args.non_302:
        status_exclude = status_exclude or []
        status_exclude.append(302)
    
    results = await checker.scan_hosts(
        hosts=hosts,
        methods=methods,
        status_include=status_include,
        status_exclude=status_exclude,
        header_filter=args.header_has,
        body_filter=args.contains
    )
    
    await checker.save_results(
        results=results,
        txt_file=args.output,
        json_file=args.json
    )


async def handle_subfinder_command(args) -> None:
    """Handle subfinder command"""
    engine = ReconEngine(
        threads=args.threads,
        silent=args.silent
    )
    
    if args.domain:
        targets = [args.domain]
    else:
        targets = await engine.load_targets_from_file(args.list)
    
    wordlist = None
    if args.wordlist:
        wordlist = await engine.load_wordlist(args.wordlist)
    
    results = await engine.scan_targets(
        targets=targets,
        wordlist=wordlist,
        resolve_only=True,  # No HTTP checking
        alive_only=False
    )
    
    # Extract just the hostnames
    hostnames = [r['host'] for r in results if r.get('resolved', False)]
    
    if args.output:
        mode = 'a' if args.append else 'w'
        with open(args.output, mode) as f:
            for hostname in hostnames:
                f.write(f"{hostname}\n")
    else:
        for hostname in hostnames:
            console.print(hostname)


async def handle_ssl_command(args) -> None:
    """Handle SSL command"""
    checker = SSLChecker(
        threads=args.threads,
        timeout=args.timeout,
        silent=args.silent
    )
    
    if args.host:
        hosts = [args.host]
    else:
        hosts = await checker.load_hosts_from_file(args.input)
    
    results = await checker.check_ssl_certificates(
        hosts=hosts,
        port=args.port
    )
    
    await checker.save_results(
        results=results,
        txt_file=args.output,
        json_file=args.json
    )


async def handle_ping_command(args) -> None:
    """Handle ping command"""
    checker = PingChecker(
        threads=args.threads,
        timeout=args.timeout,
        count=args.count
    )
    
    if args.host:
        hosts = [args.host]
    else:
        hosts = await checker.load_hosts_from_file(args.input)
    
    results = await checker.ping_hosts(
        hosts=hosts,
        alive_only=args.alive_only
    )
    
    await checker.save_results(
        results=results,
        txt_file=args.output,
        json_file=args.json
    )


async def handle_dns_command(args) -> None:
    """Handle DNS command"""
    lookup = DNSLookup(
        threads=args.threads,
        resolver=args.resolver
    )
    
    if args.host:
        hosts = [args.host]
    else:
        hosts = await lookup.load_hosts_from_file(args.input)
    
    results = await lookup.lookup_records(
        hosts=hosts,
        record_type=args.record_type
    )
    
    await lookup.save_results(
        results=results,
        txt_file=args.output,
        json_file=args.json
    )


async def handle_ports_command(args) -> None:
    """Handle ports command"""
    scanner = PortScanner(
        threads=args.threads,
        timeout=args.timeout
    )
    
    ports = [int(p.strip()) for p in args.ports.split(",")]
    
    results = await scanner.scan_host_ports(
        host=args.host,
        ports=ports,
        open_only=args.open_only
    )
    
    await scanner.save_results(
        results=results,
        txt_file=args.output,
        json_file=args.json
    )


async def handle_cidr_command(args) -> None:
    """Handle CIDR command"""
    scanner = CIDRScanner(
        threads=args.threads,
        timeout=args.timeout
    )
    
    ports = [int(p.strip()) for p in args.ports.split(",")]
    
    results = await scanner.scan_cidr_range(
        cidr=args.cidr,
        ports=ports,
        alive_only=args.alive_only
    )
    
    await scanner.save_results(
        results=results,
        txt_file=args.output,
        json_file=args.json
    )


async def handle_iplookup_command(args) -> None:
    """Handle IP lookup command"""
    lookup = IPLookup(
        threads=args.threads,
        timeout=args.timeout
    )
    
    if args.host:
        ips = [args.host]
    else:
        ips = await lookup.load_ips_from_file(args.input)
    
    results = await lookup.reverse_lookup(
        ips=ips
    )
    
    await lookup.save_results(
        results=results,
        txt_file=args.output,
        json_file=args.json
    )


async def handle_file_command(args) -> None:
    """Handle file command"""
    toolkit = FileToolkit()
    
    if args.file_command == "split":
        await toolkit.split_file(args.input, args.parts, args.output)
    elif args.file_command == "merge":
        await toolkit.merge_files(args.input, args.output, args.dedupe)
    elif args.file_command == "clean":
        await toolkit.clean_hostnames(args.input, args.output)
    elif args.file_command == "dedupe":
        await toolkit.deduplicate_file(args.input, args.output)
    elif args.file_command == "filter-tld":
        tlds = [t.strip() for t in args.tlds.split(",")]
        await toolkit.filter_by_tld(args.input, args.output, tlds)
    elif args.file_command == "filter-key":
        keywords = [k.strip() for k in args.keywords.split(",")]
        await toolkit.filter_by_keywords(args.input, args.output, keywords)
    elif args.file_command == "cidr-to-ip":
        await toolkit.cidr_to_ips(args.input, args.output)
    elif args.file_command == "domain-to-ip":
        await toolkit.domains_to_ips(args.input, args.output, args.threads)
    else:
        console.print(f"[red]Unknown file command: {args.file_command}[/red]")


if __name__ == "__main__":
    asyncio.run(main())