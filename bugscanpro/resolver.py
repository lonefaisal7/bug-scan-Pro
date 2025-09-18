"""
DNS resolver module for Bug Scan Pro
Handles DNS resolution with wildcard detection and async support
Created by @lonefaisal - Made with ♥️ by @lonefaisal
"""

import asyncio
import dns.resolver
import dns.asyncresolver
import dns.exception
from typing import List, Optional, Dict, Any
import socket
import time
from concurrent.futures import ThreadPoolExecutor

from rich.console import Console

from .utils import create_semaphore, is_valid_ip

console = Console()


class DNSResolver:
    """Async DNS resolver with wildcard detection"""
    
    def __init__(
        self,
        threads: int = 100,
        timeout: int = 5,
        nameservers: Optional[List[str]] = None,
        retries: int = 2
    ):
        self.threads = threads
        self.timeout = timeout
        self.retries = retries
        self.semaphore = create_semaphore(threads)
        
        # Configure DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout * retries
        
        if nameservers:
            self.resolver.nameservers = nameservers
        else:
            # Use fast public DNS servers
            self.resolver.nameservers = [
                '1.1.1.1',      # Cloudflare
                '8.8.8.8',      # Google
                '1.0.0.1',      # Cloudflare
                '8.8.4.4'       # Google
            ]
        
        # Thread pool for blocking DNS operations
        self.executor = ThreadPoolExecutor(max_workers=threads)
    
    def __del__(self):
        """Cleanup thread pool"""
        if hasattr(self, 'executor'):
            self.executor.shutdown(wait=False)
    
    async def resolve_hostname(self, hostname: str, record_type: str = 'A') -> List[str]:
        """Resolve hostname to IP addresses"""
        async with self.semaphore:
            return await self._resolve_hostname_internal(hostname, record_type)
    
    async def _resolve_hostname_internal(self, hostname: str, record_type: str = 'A') -> List[str]:
        """Internal hostname resolution method"""
        try:
            # Use thread pool for blocking DNS operation
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                self.executor,
                self._sync_resolve,
                hostname,
                record_type
            )
            
            if answers:
                if record_type in ['A', 'AAAA']:
                    return [str(answer) for answer in answers]
                elif record_type == 'CNAME':
                    return [str(answer.target).rstrip('.') for answer in answers]
                elif record_type == 'MX':
                    return [f"{answer.preference} {str(answer.exchange).rstrip('.')}" for answer in answers]
                elif record_type in ['NS', 'TXT']:
                    return [str(answer).strip('"').rstrip('.') for answer in answers]
                else:
                    return [str(answer) for answer in answers]
            
        except dns.resolver.NXDOMAIN:
            return []
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.Timeout:
            return []
        except Exception as e:
            # Log error for debugging
            return []
        
        return []
    
    def _sync_resolve(self, hostname: str, record_type: str = 'A'):
        """Synchronous DNS resolution for use in thread pool"""
        try:
            answers = self.resolver.resolve(hostname, record_type)
            return answers
        except Exception:
            return None
    
    async def resolve_multiple_hostnames(
        self,
        hostnames: List[str],
        record_type: str = 'A'
    ) -> Dict[str, List[str]]:
        """Resolve multiple hostnames concurrently"""
        if not hostnames:
            return {}
        
        tasks = [
            self.resolve_hostname(hostname, record_type)
            for hostname in hostnames
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        resolved = {}
        for hostname, result in zip(hostnames, results):
            if isinstance(result, list):
                resolved[hostname] = result
            else:
                resolved[hostname] = []
        
        return resolved
    
    async def reverse_lookup(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup (PTR record)"""
        async with self.semaphore:
            try:
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    self.executor,
                    self._sync_reverse_lookup,
                    ip
                )
                return result
            except Exception:
                return None
    
    def _sync_reverse_lookup(self, ip: str) -> Optional[str]:
        """Synchronous reverse DNS lookup"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except Exception:
            return None
    
    async def get_dns_records(
        self,
        hostname: str,
        record_types: List[str] = None
    ) -> Dict[str, List[str]]:
        """Get multiple DNS record types for a hostname"""
        if record_types is None:
            record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']
        
        tasks = [
            self.resolve_hostname(hostname, record_type)
            for record_type in record_types
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        dns_records = {}
        for record_type, result in zip(record_types, results):
            if isinstance(result, list) and result:
                dns_records[record_type] = result
        
        return dns_records
    
    async def check_hostname_exists(self, hostname: str) -> bool:
        """Check if hostname exists (has any DNS records)"""
        try:
            ips = await self.resolve_hostname(hostname, 'A')
            if ips:
                return True
            
            # Try AAAA if no A records
            ips = await self.resolve_hostname(hostname, 'AAAA')
            if ips:
                return True
            
            # Try CNAME
            cnames = await self.resolve_hostname(hostname, 'CNAME')
            if cnames:
                return True
            
            return False
        except Exception:
            return False
    
    async def is_domain_resolvable(self, domain: str) -> bool:
        """Check if domain is resolvable"""
        return await self.check_hostname_exists(domain)
    
    async def get_nameservers(self, domain: str) -> List[str]:
        """Get nameservers for a domain"""
        return await self.resolve_hostname(domain, 'NS')
    
    async def get_mx_records(self, domain: str) -> List[str]:
        """Get MX records for a domain"""
        return await self.resolve_hostname(domain, 'MX')
    
    async def get_txt_records(self, domain: str) -> List[str]:
        """Get TXT records for a domain"""
        return await self.resolve_hostname(domain, 'TXT')
    
    def set_nameservers(self, nameservers: List[str]) -> None:
        """Set custom nameservers"""
        valid_nameservers = []
        for ns in nameservers:
            if is_valid_ip(ns):
                valid_nameservers.append(ns)
            else:
                console.print(f"[yellow]Invalid nameserver IP: {ns}[/yellow]")
        
        if valid_nameservers:
            self.resolver.nameservers = valid_nameservers
        else:
            console.print("[red]No valid nameservers provided[/red]")
    
    def get_current_nameservers(self) -> List[str]:
        """Get currently configured nameservers"""
        return self.resolver.nameservers.copy()
    
    async def test_dns_server(self, nameserver: str) -> Dict[str, Any]:
        """Test DNS server performance and reliability"""
        test_domain = "google.com"
        original_ns = self.resolver.nameservers.copy()
        
        try:
            # Set test nameserver
            self.resolver.nameservers = [nameserver]
            
            # Measure response time
            start_time = time.time()
            ips = await self.resolve_hostname(test_domain)
            end_time = time.time()
            
            response_time = round((end_time - start_time) * 1000, 2)  # ms
            
            result = {
                'nameserver': nameserver,
                'working': bool(ips),
                'response_time_ms': response_time,
                'resolved_ips': ips
            }
            
        except Exception as e:
            result = {
                'nameserver': nameserver,
                'working': False,
                'error': str(e),
                'response_time_ms': None,
                'resolved_ips': []
            }
        
        finally:
            # Restore original nameservers
            self.resolver.nameservers = original_ns
        
        return result
    
    async def benchmark_nameservers(self, nameservers: List[str]) -> List[Dict[str, Any]]:
        """Benchmark multiple nameservers"""
        tasks = [self.test_dns_server(ns) for ns in nameservers]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        valid_results = []
        for result in results:
            if isinstance(result, dict):
                valid_results.append(result)
        
        # Sort by response time (working servers first)
        valid_results.sort(key=lambda x: (
            not x.get('working', False),
            x.get('response_time_ms', float('inf'))
        ))
        
        return valid_results


if __name__ == "__main__":
    # Test the DNS resolver
    import sys
    
    async def test_resolver():
        resolver = DNSResolver(threads=50)
        
        if len(sys.argv) < 2:
            print("Usage: python resolver.py <hostname>")
            sys.exit(1)
        
        hostname = sys.argv[1]
        
        print(f"Testing DNS resolution for: {hostname}")
        
        # Test A records
        ips = await resolver.resolve_hostname(hostname, 'A')
        print(f"A records: {ips}")
        
        # Test all record types
        all_records = await resolver.get_dns_records(hostname)
        print(f"All DNS records: {all_records}")
        
        # Test reverse lookup if we got IPs
        if ips:
            reverse = await resolver.reverse_lookup(ips[0])
            print(f"Reverse lookup for {ips[0]}: {reverse}")
    
    asyncio.run(test_resolver())