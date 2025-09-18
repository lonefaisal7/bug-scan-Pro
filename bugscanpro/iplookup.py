"""
IP lookup module for Bug Scan Pro
Handles reverse PTR lookups and IP analysis
Created by @lonefaisal - Made with ♥️ by @lonefaisal
"""

import asyncio
import socket
import time
import ipaddress
from typing import List, Dict, Any, Optional

from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn

from .resolver import DNSResolver
from .utils import create_semaphore, is_valid_ip, is_private_ip
from .output import OutputManager

console = Console()


class IPLookup:
    """IP address lookup and analysis"""
    
    def __init__(
        self,
        threads: int = 50,
        timeout: int = 5,
        silent: bool = False
    ):
        self.threads = threads
        self.timeout = timeout
        self.silent = silent
        
        self.semaphore = create_semaphore(threads)
        self.dns_resolver = DNSResolver(threads=threads, timeout=timeout)
        self.output_manager = OutputManager()
    
    async def reverse_lookup(
        self,
        ips: List[str]
    ) -> List[Dict[str, Any]]:
        """Perform reverse DNS lookup for IP addresses"""
        if not ips:
            return []
        
        # Filter valid IPs
        valid_ips = [ip for ip in ips if is_valid_ip(ip)]
        
        if not valid_ips:
            raise ValueError("No valid IP addresses provided")
        
        if not self.silent:
            console.print(f"[blue]Performing reverse DNS lookup for {len(valid_ips)} IP addresses...[/blue]")
        
        # Create lookup tasks
        tasks = [self._reverse_lookup_single_ip(ip) for ip in valid_ips]
        
        results = []
        
        if not self.silent:
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("({task.completed}/{task.total})"),
                TimeRemainingColumn(),
                console=console
            ) as progress:
                task = progress.add_task("Reverse DNS lookup", total=len(tasks))
                
                for coro in asyncio.as_completed(tasks):
                    result = await coro
                    if result:
                        results.append(result)
                    progress.advance(task)
        else:
            lookup_results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in lookup_results:
                if isinstance(result, dict):
                    results.append(result)
        
        if not self.silent:
            successful = len([r for r in results if r.get('hostname')])
            console.print(f"[green]Found hostnames for {successful}/{len(results)} IP addresses[/green]")
        
        return results
    
    async def _reverse_lookup_single_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Reverse DNS lookup for a single IP address"""
        async with self.semaphore:
            start_time = time.time()
            
            try:
                hostname = await self.dns_resolver.reverse_lookup(ip)
                response_time = round((time.time() - start_time) * 1000, 2)
                
                # Analyze IP address
                ip_info = self._analyze_ip(ip)
                
                return {
                    'ip': ip,
                    'hostname': hostname,
                    'found': bool(hostname),
                    'response_time': response_time,
                    'ip_info': ip_info,
                    'timestamp': int(time.time())
                }
                
            except Exception as e:
                response_time = round((time.time() - start_time) * 1000, 2)
                ip_info = self._analyze_ip(ip)
                
                return {
                    'ip': ip,
                    'hostname': None,
                    'found': False,
                    'error': str(e),
                    'response_time': response_time,
                    'ip_info': ip_info,
                    'timestamp': int(time.time())
                }
    
    def _analyze_ip(self, ip: str) -> Dict[str, Any]:
        """Analyze IP address characteristics"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            analysis = {
                'version': ip_obj.version,
                'is_private': ip_obj.is_private,
                'is_global': ip_obj.is_global,
                'is_loopback': ip_obj.is_loopback,
                'is_multicast': ip_obj.is_multicast,
                'is_reserved': ip_obj.is_reserved,
                'is_link_local': ip_obj.is_link_local if hasattr(ip_obj, 'is_link_local') else False
            }
            
            # Additional IPv4 specific analysis
            if ip_obj.version == 4:
                analysis['class'] = self._get_ipv4_class(ip)
                analysis['network_type'] = self._get_network_type(ip_obj)
            
            return analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    def _get_ipv4_class(self, ip: str) -> str:
        """Get IPv4 address class (A, B, C, D, E)"""
        try:
            first_octet = int(ip.split('.')[0])
            
            if 1 <= first_octet <= 126:
                return 'A'
            elif 128 <= first_octet <= 191:
                return 'B'
            elif 192 <= first_octet <= 223:
                return 'C'
            elif 224 <= first_octet <= 239:
                return 'D (Multicast)'
            elif 240 <= first_octet <= 255:
                return 'E (Reserved)'
            else:
                return 'Unknown'
        except:
            return 'Unknown'
    
    def _get_network_type(self, ip_obj) -> str:
        """Determine network type based on IP address"""
        if ip_obj.is_private:
            if str(ip_obj).startswith('192.168.'):
                return 'Private (Class C)'
            elif str(ip_obj).startswith('10.'):
                return 'Private (Class A)'
            elif str(ip_obj).startswith('172.'):
                return 'Private (Class B)'
            else:
                return 'Private'
        elif ip_obj.is_loopback:
            return 'Loopback'
        elif ip_obj.is_link_local:
            return 'Link Local'
        elif ip_obj.is_multicast:
            return 'Multicast'
        elif ip_obj.is_reserved:
            return 'Reserved'
        else:
            return 'Public'
    
    async def bulk_ip_analysis(
        self,
        ips: List[str],
        include_geolocation: bool = False
    ) -> List[Dict[str, Any]]:
        """Perform bulk analysis of IP addresses"""
        if not ips:
            return []
        
        valid_ips = [ip for ip in ips if is_valid_ip(ip)]
        
        if not self.silent:
            console.print(f"[blue]Analyzing {len(valid_ips)} IP addresses...[/blue]")
        
        # First do reverse lookups
        reverse_results = await self.reverse_lookup(valid_ips)
        
        # Add additional analysis
        for result in reverse_results:
            ip = result['ip']
            
            # Add geolocation if requested (placeholder for future implementation)
            if include_geolocation:
                result['geolocation'] = await self._get_geolocation(ip)
            
            # Add ASN information (placeholder)
            result['asn_info'] = await self._get_asn_info(ip)
        
        return reverse_results
    
    async def _get_geolocation(self, ip: str) -> Dict[str, Any]:
        """Get geolocation information for IP (placeholder)"""
        # This would integrate with a geolocation service
        # For now, return placeholder data
        return {
            'country': None,
            'city': None,
            'region': None,
            'latitude': None,
            'longitude': None,
            'service': 'not_implemented'
        }
    
    async def _get_asn_info(self, ip: str) -> Dict[str, Any]:
        """Get ASN information for IP (placeholder)"""
        # This would query ASN databases
        # For now, return placeholder data
        return {
            'asn': None,
            'organization': None,
            'description': None,
            'service': 'not_implemented'
        }
    
    async def scan_ip_range(
        self,
        start_ip: str,
        end_ip: str,
        max_ips: int = 1000
    ) -> List[Dict[str, Any]]:
        """Scan range of IP addresses for reverse DNS"""
        try:
            start = ipaddress.IPv4Address(start_ip)
            end = ipaddress.IPv4Address(end_ip)
            
            if start > end:
                raise ValueError("Start IP must be less than or equal to end IP")
            
            # Generate IP range
            ip_range = []
            current = start
            count = 0
            
            while current <= end and count < max_ips:
                ip_range.append(str(current))
                current += 1
                count += 1
            
            if count >= max_ips:
                if not self.silent:
                    console.print(f"[yellow]Limited to {max_ips} IPs from the range[/yellow]")
            
            return await self.reverse_lookup(ip_range)
            
        except ipaddress.AddressValueError as e:
            raise ValueError(f"Invalid IP address: {e}")
    
    async def load_ips_from_file(self, file_path: str) -> List[str]:
        """Load IP addresses from file"""
        ips = []
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if is_valid_ip(line):
                            ips.append(line)
        except FileNotFoundError:
            raise FileNotFoundError(f"IP file not found: {file_path}")
        except Exception as e:
            raise Exception(f"Error reading IP file: {e}")
        
        return list(set(ips))  # Remove duplicates
    
    async def save_results(
        self,
        results: List[Dict[str, Any]],
        txt_file: Optional[str] = None,
        json_file: Optional[str] = None,
        csv_file: Optional[str] = None,
        append: bool = False
    ) -> None:
        """Save IP lookup results"""
        if not results:
            console.print("[yellow]No results to save[/yellow]")
            return
        
        # Save TXT format (IP:hostname for found entries)
        if txt_file:
            txt_results = []
            for r in results:
                if r.get('found', False) and r.get('hostname'):
                    txt_results.append({'host': f"{r['ip']}:{r['hostname']}"}) 
                else:
                    txt_results.append({'host': r['ip']})
            
            await self.output_manager.save_txt(
                results=txt_results,
                filename=txt_file,
                append=append
            )
            console.print(f"[green]Results saved to {txt_file}[/green]")
        
        # Save JSON format
        if json_file:
            await self.output_manager.save_json(
                results=results,
                filename=json_file,
                append=append
            )
            console.print(f"[green]Results saved to {json_file}[/green]")
        
        # Save CSV format
        if csv_file:
            await self.output_manager.save_csv(
                results=results,
                filename=csv_file,
                append=append
            )
            console.print(f"[green]Results saved to {csv_file}[/green]")
        
        # Print to console if no output files
        if not any([txt_file, json_file, csv_file]):
            for result in results:
                ip = result.get('ip')
                hostname = result.get('hostname')
                ip_info = result.get('ip_info', {})
                network_type = ip_info.get('network_type', 'Unknown')
                
                if hostname:
                    console.print(f"[green]{ip}[/green] -> {hostname} ({network_type})")
                else:
                    error = result.get('error', 'No PTR record')
                    console.print(f"[red]{ip}[/red] -> {error} ({network_type})")


if __name__ == "__main__":
    # Test the IP lookup
    import sys
    
    async def test_ip_lookup():
        if len(sys.argv) < 2:
            print("Usage: python iplookup.py <ip_address>")
            sys.exit(1)
        
        ip = sys.argv[1]
        
        lookup = IPLookup(threads=10)
        
        print(f"Testing reverse DNS lookup for: {ip}")
        
        results = await lookup.reverse_lookup([ip])
        
        if results:
            result = results[0]
            print(f"\nResults:")
            print(f"  IP: {result['ip']}")
            print(f"  Hostname: {result.get('hostname', 'Not found')}")
            print(f"  Response time: {result.get('response_time', 0)}ms")
            
            ip_info = result.get('ip_info', {})
            print(f"\nIP Analysis:")
            print(f"  Version: IPv{ip_info.get('version', 'Unknown')}")
            print(f"  Network type: {ip_info.get('network_type', 'Unknown')}")
            print(f"  Is private: {ip_info.get('is_private', False)}")
            print(f"  Is global: {ip_info.get('is_global', False)}")
            
            if 'class' in ip_info:
                print(f"  IPv4 class: {ip_info['class']}")
        
        # Test bulk analysis
        test_ips = [ip, '8.8.8.8', '1.1.1.1']
        print(f"\nBulk analysis for test IPs: {', '.join(test_ips)}")
        
        bulk_results = await lookup.bulk_ip_analysis(test_ips)
        
        for result in bulk_results:
            ip_addr = result['ip']
            hostname = result.get('hostname', 'No PTR')
            network_type = result.get('ip_info', {}).get('network_type', 'Unknown')
            print(f"  {ip_addr} -> {hostname} ({network_type})")
    
    asyncio.run(test_ip_lookup())