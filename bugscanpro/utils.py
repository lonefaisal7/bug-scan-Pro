"""
Utility functions and file toolkit for Bug Scan Pro
Provides common utilities and file operations
Created by @lonefaisal - Made with ♥️ by @lonefaisal
"""

import re
import ipaddress
import asyncio
import random
import string
from typing import List, Set, Optional, Dict, Any, Union
from pathlib import Path
import tldextract
import math
import socket

from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn

from .resolver import DNSResolver

console = Console()


def is_valid_hostname(hostname: str) -> bool:
    """Check if a string is a valid hostname"""
    if not hostname or len(hostname) > 253:
        return False
    
    # Remove trailing dot
    if hostname.endswith('.'):
        hostname = hostname[:-1]
    
    # Check each label
    labels = hostname.split('.')
    if len(labels) < 2:  # Must have at least two parts
        return False
    
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$', label):
            return False
    
    # Check TLD is not numeric
    if labels[-1].isdigit():
        return False
    
    return True


def is_valid_ip(ip: str) -> bool:
    """Check if a string is a valid IP address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """Check if IP address is private"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def extract_domain_info(hostname: str) -> Dict[str, str]:
    """Extract domain parts using tldextract"""
    try:
        extracted = tldextract.extract(hostname)
        return {
            'subdomain': extracted.subdomain,
            'domain': extracted.domain,
            'suffix': extracted.suffix,
            'registered_domain': extracted.registered_domain,
            'fqdn': extracted.fqdn
        }
    except Exception:
        return {}


def get_root_domain(hostname: str) -> str:
    """Get root domain from hostname"""
    try:
        extracted = tldextract.extract(hostname)
        return extracted.registered_domain
    except Exception:
        return hostname


def create_semaphore(limit: int) -> asyncio.Semaphore:
    """Create asyncio semaphore with proper limit"""
    return asyncio.Semaphore(max(1, min(limit, 1000)))


def generate_random_string(length: int = 10, charset: str = None) -> str:
    """Generate random string"""
    if charset is None:
        charset = string.ascii_lowercase + string.digits
    return ''.join(random.choices(charset, k=length))


def expand_cidr(cidr: str) -> List[str]:
    """Expand CIDR notation to list of IP addresses"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError as e:
        raise ValueError(f"Invalid CIDR notation: {cidr}")


def parse_port_range(port_str: str) -> List[int]:
    """Parse port range string into list of ports"""
    ports = set()
    
    for part in port_str.split(','):
        part = part.strip()
        
        if '-' in part:
            # Port range
            start, end = part.split('-', 1)
            try:
                start_port = int(start.strip())
                end_port = int(end.strip())
                
                if 1 <= start_port <= 65535 and 1 <= end_port <= 65535:
                    ports.update(range(start_port, end_port + 1))
            except ValueError:
                continue
        else:
            # Single port
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.add(port)
            except ValueError:
                continue
    
    return sorted(list(ports))


def format_bytes(bytes_val: int) -> str:
    """Format bytes into human readable format"""
    if bytes_val == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = int(math.floor(math.log(bytes_val, 1024)))
    p = math.pow(1024, i)
    s = round(bytes_val / p, 2)
    
    return f"{s} {size_names[i]}"


def format_duration(seconds: float) -> str:
    """Format duration into human readable format"""
    if seconds < 1:
        return f"{round(seconds * 1000)}ms"
    elif seconds < 60:
        return f"{round(seconds, 1)}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


class FileToolkit:
    """File operations toolkit"""
    
    def __init__(self):
        pass
    
    async def split_file(
        self,
        input_file: str,
        parts: int,
        output_prefix: Optional[str] = None
    ) -> List[str]:
        """Split large file into multiple parts"""
        if not Path(input_file).exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")
        
        if output_prefix is None:
            output_prefix = Path(input_file).stem
        
        # Read all lines
        with open(input_file, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip()]
        
        total_lines = len(lines)
        lines_per_part = math.ceil(total_lines / parts)
        
        output_files = []
        
        for i in range(parts):
            start_idx = i * lines_per_part
            end_idx = min((i + 1) * lines_per_part, total_lines)
            
            if start_idx >= total_lines:
                break
            
            output_file = f"{output_prefix}_part_{i+1}.txt"
            output_files.append(output_file)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                for line in lines[start_idx:end_idx]:
                    f.write(f"{line}\n")
            
            console.print(f"[green]Created: {output_file} ({end_idx - start_idx} lines)[/green]")
        
        return output_files
    
    async def merge_files(
        self,
        input_pattern: str,
        output_file: str,
        dedupe: bool = True
    ) -> None:
        """Merge multiple files into one"""
        # Handle different input patterns
        if ',' in input_pattern:
            # Comma-separated list
            input_files = [f.strip() for f in input_pattern.split(',')]
        else:
            # File pattern or list file
            if Path(input_pattern).exists() and input_pattern.endswith('.txt'):
                # Treat as file containing list of files
                with open(input_pattern, 'r') as f:
                    input_files = [line.strip() for line in f if line.strip()]
            else:
                # Treat as glob pattern
                from glob import glob
                input_files = glob(input_pattern)
        
        all_lines = []
        seen_lines = set() if dedupe else None
        
        for file_path in input_files:
            if not Path(file_path).exists():
                console.print(f"[yellow]Warning: File not found: {file_path}[/yellow]")
                continue
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            if dedupe:
                                if line not in seen_lines:
                                    seen_lines.add(line)
                                    all_lines.append(line)
                            else:
                                all_lines.append(line)
            except Exception as e:
                console.print(f"[red]Error reading {file_path}: {e}[/red]")
        
        # Write merged file
        with open(output_file, 'w', encoding='utf-8') as f:
            for line in all_lines:
                f.write(f"{line}\n")
        
        console.print(f"[green]Merged {len(input_files)} files into {output_file} ({len(all_lines)} lines)[/green]")
    
    async def clean_hostnames(
        self,
        input_file: str,
        output_file: str
    ) -> None:
        """Extract valid hostnames using regex validation"""
        if not Path(input_file).exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")
        
        valid_hostnames = []
        
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # Try to extract hostnames from various formats
                potential_hostnames = []
                
                # Direct hostname
                if is_valid_hostname(line):
                    potential_hostnames.append(line)
                
                # Extract from URLs
                url_pattern = r'https?://([^/\s]+)'
                url_matches = re.findall(url_pattern, line, re.IGNORECASE)
                potential_hostnames.extend(url_matches)
                
                # Extract hostname patterns
                hostname_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)' + \
                                 r'+[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?\b'
                hostname_matches = re.findall(hostname_pattern, line)
                potential_hostnames.extend(hostname_matches)
                
                # Validate and add unique hostnames
                for hostname in potential_hostnames:
                    hostname = hostname.lower().strip()
                    if is_valid_hostname(hostname) and hostname not in valid_hostnames:
                        valid_hostnames.append(hostname)
        
        # Write cleaned hostnames
        with open(output_file, 'w', encoding='utf-8') as f:
            for hostname in sorted(set(valid_hostnames)):
                f.write(f"{hostname}\n")
        
        console.print(f"[green]Extracted {len(valid_hostnames)} valid hostnames to {output_file}[/green]")
    
    async def deduplicate_file(
        self,
        input_file: str,
        output_file: str,
        case_sensitive: bool = False
    ) -> None:
        """Remove duplicate lines from file"""
        if not Path(input_file).exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")
        
        seen_lines = set()
        unique_lines = []
        
        with open(input_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                check_line = line if case_sensitive else line.lower()
                
                if check_line not in seen_lines:
                    seen_lines.add(check_line)
                    unique_lines.append(line)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            for line in unique_lines:
                f.write(f"{line}\n")
        
        original_count = len(unique_lines) + (len(seen_lines) if case_sensitive else 0)
        removed_count = len(seen_lines) - len(unique_lines) if not case_sensitive else 0
        
        console.print(f"[green]Deduplicated {input_file}: {len(unique_lines)} unique lines[/green]")
        if removed_count > 0:
            console.print(f"[yellow]Removed {removed_count} duplicate lines[/yellow]")
    
    async def filter_by_tld(
        self,
        input_file: str,
        output_file: str,
        tlds: List[str]
    ) -> None:
        """Filter hostnames by TLD extensions"""
        if not Path(input_file).exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")
        
        # Normalize TLDs (remove dots, convert to lowercase)
        tlds = [tld.lower().lstrip('.') for tld in tlds]
        
        filtered_lines = []
        
        with open(input_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # Extract TLD
                domain_info = extract_domain_info(line)
                if domain_info and domain_info.get('suffix'):
                    suffix = domain_info['suffix'].lower()
                    if suffix in tlds:
                        filtered_lines.append(line)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            for line in filtered_lines:
                f.write(f"{line}\n")
        
        console.print(f"[green]Filtered by TLD: {len(filtered_lines)} matching lines[/green]")
    
    async def filter_by_keywords(
        self,
        input_file: str,
        output_file: str,
        keywords: List[str],
        case_sensitive: bool = False
    ) -> None:
        """Filter lines containing keywords"""
        if not Path(input_file).exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")
        
        if not case_sensitive:
            keywords = [kw.lower() for kw in keywords]
        
        filtered_lines = []
        
        with open(input_file, 'r', encoding='utf-8') as f:
            for line in f:
                original_line = line.strip()
                if not original_line:
                    continue
                
                check_line = original_line if case_sensitive else original_line.lower()
                
                if any(keyword in check_line for keyword in keywords):
                    filtered_lines.append(original_line)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            for line in filtered_lines:
                f.write(f"{line}\n")
        
        console.print(f"[green]Filtered by keywords: {len(filtered_lines)} matching lines[/green]")
    
    async def cidr_to_ips(
        self,
        input_file: str,
        output_file: str
    ) -> None:
        """Expand CIDR ranges to individual IPs"""
        if not Path(input_file).exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")
        
        all_ips = []
        
        with open(input_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                try:
                    ips = expand_cidr(line)
                    all_ips.extend(ips)
                    console.print(f"[blue]Expanded {line}: {len(ips)} IPs[/blue]")
                except ValueError as e:
                    console.print(f"[yellow]Skipping invalid CIDR {line}: {e}[/yellow]")
        
        # Remove duplicates and sort
        unique_ips = sorted(set(all_ips), key=lambda ip: ipaddress.ip_address(ip))
        
        with open(output_file, 'w', encoding='utf-8') as f:
            for ip in unique_ips:
                f.write(f"{ip}\n")
        
        console.print(f"[green]Expanded to {len(unique_ips)} unique IP addresses[/green]")
    
    async def domains_to_ips(
        self,
        input_file: str,
        output_file: str,
        threads: int = 50
    ) -> None:
        """Resolve domains to IP addresses"""
        if not Path(input_file).exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")
        
        # Read domains
        domains = []
        with open(input_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and is_valid_hostname(line):
                    domains.append(line)
        
        if not domains:
            console.print("[yellow]No valid domains found in input file[/yellow]")
            return
        
        console.print(f"[blue]Resolving {len(domains)} domains to IP addresses...[/blue]")
        
        # Resolve domains
        resolver = DNSResolver(threads=threads, timeout=5)
        resolved_ips = set()
        
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Resolving domains", total=len(domains))
            
            for domain in domains:
                try:
                    ips = await resolver.resolve_hostname(domain)
                    if ips:
                        resolved_ips.update(ips)
                except Exception:
                    pass
                
                progress.advance(task)
        
        # Sort IPs
        sorted_ips = sorted(resolved_ips, key=lambda ip: ipaddress.ip_address(ip))
        
        with open(output_file, 'w', encoding='utf-8') as f:
            for ip in sorted_ips:
                f.write(f"{ip}\n")
        
        console.print(f"[green]Resolved {len(domains)} domains to {len(sorted_ips)} unique IPs[/green]")


if __name__ == "__main__":
    # Test utility functions
    async def test_utils():
        print("Testing utility functions...")
        
        # Test hostname validation
        test_hostnames = [
            'example.com',
            'sub.example.com',
            'invalid..hostname',
            '192.168.1.1',
            'valid-hostname.com'
        ]
        
        for hostname in test_hostnames:
            print(f"{hostname}: {is_valid_hostname(hostname)}")
        
        # Test IP validation
        test_ips = ['192.168.1.1', '2001:db8::1', 'invalid.ip', '256.256.256.256']
        for ip in test_ips:
            print(f"{ip}: {is_valid_ip(ip)}")
        
        # Test CIDR expansion
        try:
            ips = expand_cidr('192.168.1.0/30')
            print(f"CIDR expansion: {ips}")
        except ValueError as e:
            print(f"CIDR error: {e}")
        
        # Test port parsing
        ports = parse_port_range('80,443,8000-8010')
        print(f"Parsed ports: {ports[:10]}...")  # Show first 10
        
        # Test file toolkit
        toolkit = FileToolkit()
        
        # Create test file
        test_data = [
            'example.com',
            'test.example.com',
            'example.com',  # duplicate
            'invalid..hostname',
            'another-test.com'
        ]
        
        with open('test_input.txt', 'w') as f:
            for line in test_data:
                f.write(f"{line}\n")
        
        # Test deduplication
        await toolkit.deduplicate_file('test_input.txt', 'test_dedupe.txt')
        
        # Test hostname cleaning
        await toolkit.clean_hostnames('test_input.txt', 'test_clean.txt')
        
        print("Test files created: test_dedupe.txt, test_clean.txt")
        
        # Cleanup
        import os
        for file in ['test_input.txt', 'test_dedupe.txt', 'test_clean.txt']:
            try:
                os.remove(file)
            except:
                pass
    
    asyncio.run(test_utils())