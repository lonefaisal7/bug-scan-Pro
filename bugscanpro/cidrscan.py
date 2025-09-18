"""
CIDR range scanner for Bug Scan Pro
Handles IP range scanning with port enumeration
Created by @lonefaisal - Made with ♥️ by @lonefaisal
"""

import asyncio
import ipaddress
import time
from typing import List, Dict, Any, Optional

from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn

from .portscan import PortScanner
from .pingcheck import PingChecker
from .utils import create_semaphore, expand_cidr, parse_port_range
from .output import OutputManager

console = Console()


class CIDRScanner:
    """CIDR range scanning with port enumeration"""
    
    def __init__(
        self,
        threads: int = 100,
        timeout: int = 3,
        silent: bool = False
    ):
        self.threads = threads
        self.timeout = timeout
        self.silent = silent
        
        self.semaphore = create_semaphore(threads)
        self.port_scanner = PortScanner(threads=threads, timeout=timeout, silent=True)
        self.ping_checker = PingChecker(threads=threads, timeout=timeout//2, count=1)
        self.output_manager = OutputManager()
    
    async def scan_cidr_range(
        self,
        cidr: str,
        ports: List[int],
        alive_only: bool = False,
        ping_first: bool = True
    ) -> List[Dict[str, Any]]:
        """Scan CIDR range for open ports"""
        try:
            # Expand CIDR to IP list
            ip_list = expand_cidr(cidr)
            
            if not ip_list:
                raise ValueError(f"No IPs found in CIDR range: {cidr}")
            
            if not self.silent:
                console.print(f"[blue]Scanning CIDR {cidr} ({len(ip_list)} IPs) on {len(ports)} ports...[/blue]")
            
            all_results = []
            
            # Step 1: Ping sweep if requested
            alive_ips = ip_list
            if ping_first:
                if not self.silent:
                    console.print(f"[blue]Performing ping sweep...[/blue]")
                
                ping_results = await self.ping_checker.ping_hosts(ip_list, alive_only=True)
                alive_ips = [r['host'] for r in ping_results if r.get('alive', False)]
                
                if not self.silent:
                    console.print(f"[green]Found {len(alive_ips)} alive hosts[/green]")
                
                if not alive_ips:
                    return []
            
            # Step 2: Port scanning
            scan_tasks = []
            for ip in alive_ips:
                scan_tasks.append(self._scan_ip_ports(ip, ports, alive_only))
            
            if not self.silent:
                with Progress(
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TextColumn("({task.completed}/{task.total})"),
                    TimeRemainingColumn(),
                    console=console
                ) as progress:
                    task = progress.add_task(f"CIDR scanning", total=len(scan_tasks))
                    
                    for coro in asyncio.as_completed(scan_tasks):
                        results = await coro
                        all_results.extend(results)
                        progress.advance(task)
            else:
                scan_results = await asyncio.gather(*scan_tasks, return_exceptions=True)
                for results in scan_results:
                    if isinstance(results, list):
                        all_results.extend(results)
            
            # Filter results if alive_only
            if alive_only:
                all_results = [r for r in all_results if r.get('open', False)]
            
            # Add metadata
            for result in all_results:
                result['cidr'] = cidr
                result['scan_type'] = 'cidr_range'
            
            if not self.silent:
                open_ports_count = len([r for r in all_results if r.get('open', False)])
                console.print(f"[green]CIDR scan complete: {open_ports_count} open ports found[/green]")
            
            return all_results
            
        except ValueError as e:
            raise e
        except Exception as e:
            raise Exception(f"Error scanning CIDR range: {e}")
    
    async def _scan_ip_ports(
        self,
        ip: str,
        ports: List[int],
        open_only: bool = False
    ) -> List[Dict[str, Any]]:
        """Scan ports on a single IP"""
        try:
            results = await self.port_scanner.scan_host_ports(ip, ports, open_only)
            return results
        except Exception:
            return []
    
    async def scan_multiple_cidrs(
        self,
        cidrs: List[str],
        ports: List[int],
        alive_only: bool = False,
        ping_first: bool = True
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Scan multiple CIDR ranges"""
        if not cidrs:
            return {}
        
        if not self.silent:
            console.print(f"[blue]Scanning {len(cidrs)} CIDR ranges...[/blue]")
        
        all_results = {}
        
        for cidr in cidrs:
            try:
                if not self.silent:
                    console.print(f"\n[cyan]Scanning CIDR: {cidr}[/cyan]")
                
                cidr_results = await self.scan_cidr_range(
                    cidr=cidr,
                    ports=ports,
                    alive_only=alive_only,
                    ping_first=ping_first
                )
                
                all_results[cidr] = cidr_results
                
                if not self.silent:
                    open_count = len([r for r in cidr_results if r.get('open', False)])
                    console.print(f"[green]{cidr}: {open_count} open ports[/green]")
                    
            except Exception as e:
                if not self.silent:
                    console.print(f"[red]Error scanning {cidr}: {e}[/red]")
                all_results[cidr] = []
        
        return all_results
    
    async def discover_live_hosts(
        self,
        cidr: str,
        discovery_ports: List[int] = None
    ) -> List[Dict[str, Any]]:
        """Discover live hosts in CIDR range using various methods"""
        if discovery_ports is None:
            # Common ports for host discovery
            discovery_ports = [22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3389, 5900]
        
        try:
            ip_list = expand_cidr(cidr)
            
            if not self.silent:
                console.print(f"[blue]Discovering live hosts in {cidr} ({len(ip_list)} IPs)...[/blue]")
            
            live_hosts = []
            
            # Method 1: Ping sweep
            ping_results = await self.ping_checker.ping_hosts(ip_list, alive_only=True)
            ping_alive = set(r['host'] for r in ping_results if r.get('alive', False))
            
            # Method 2: Port scanning on discovery ports
            port_alive = set()
            scan_tasks = []
            
            for ip in ip_list:
                scan_tasks.append(self._quick_port_check(ip, discovery_ports))
            
            scan_results = await asyncio.gather(*scan_tasks, return_exceptions=True)
            for result in scan_results:
                if isinstance(result, str):  # IP with open ports
                    port_alive.add(result)
            
            # Combine results
            all_alive = ping_alive | port_alive
            
            for ip in all_alive:
                host_info = {
                    'ip': ip,
                    'alive': True,
                    'ping_responsive': ip in ping_alive,
                    'port_responsive': ip in port_alive,
                    'discovery_method': []
                }
                
                if ip in ping_alive:
                    host_info['discovery_method'].append('ping')
                if ip in port_alive:
                    host_info['discovery_method'].append('port_scan')
                
                live_hosts.append(host_info)
            
            if not self.silent:
                console.print(f"[green]Discovered {len(live_hosts)} live hosts in {cidr}[/green]")
                console.print(f"[blue]  Ping responsive: {len(ping_alive)}[/blue]")
                console.print(f"[blue]  Port responsive: {len(port_alive)}[/blue]")
            
            return live_hosts
            
        except Exception as e:
            raise Exception(f"Error discovering live hosts: {e}")
    
    async def _quick_port_check(
        self,
        ip: str,
        ports: List[int]
    ) -> Optional[str]:
        """Quick check for any open ports on an IP"""
        async with self.semaphore:
            for port in ports[:5]:  # Check only first 5 ports for speed
                try:
                    result = await self.port_scanner.scan_port(ip, port)
                    if result.get('open', False):
                        return ip
                except Exception:
                    continue
            return None
    
    async def generate_ip_ranges(
        self,
        start_ip: str,
        end_ip: str
    ) -> List[str]:
        """Generate list of IP addresses between start and end IPs"""
        try:
            start = ipaddress.IPv4Address(start_ip)
            end = ipaddress.IPv4Address(end_ip)
            
            if start > end:
                raise ValueError("Start IP must be less than or equal to end IP")
            
            ip_list = []
            current = start
            
            while current <= end:
                ip_list.append(str(current))
                current += 1
            
            return ip_list
            
        except ipaddress.AddressValueError as e:
            raise ValueError(f"Invalid IP address: {e}")
    
    async def save_results(
        self,
        results: List[Dict[str, Any]],
        txt_file: Optional[str] = None,
        json_file: Optional[str] = None,
        csv_file: Optional[str] = None,
        append: bool = False
    ) -> None:
        """Save CIDR scan results"""
        if not results:
            console.print("[yellow]No results to save[/yellow]")
            return
        
        # Save TXT format (IP:port for open ports)
        if txt_file:
            txt_results = []
            for r in results:
                if r.get('open', False):
                    txt_results.append({'host': f"{r['host']}:{r['port']}"}) 
            
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
            # Group results by IP for better display
            ip_results = {}
            for result in results:
                ip = result.get('host')
                if ip not in ip_results:
                    ip_results[ip] = []
                ip_results[ip].append(result)
            
            for ip, port_results in ip_results.items():
                open_ports = [str(r['port']) for r in port_results if r.get('open', False)]
                if open_ports:
                    console.print(f"[green]{ip}[/green] - Open ports: {', '.join(open_ports)}")


if __name__ == "__main__":
    # Test the CIDR scanner
    import sys
    
    async def test_cidr_scanner():
        if len(sys.argv) < 2:
            print("Usage: python cidrscan.py <cidr> [ports]")
            print("Example: python cidrscan.py 192.168.1.0/24 80,443,22")
            sys.exit(1)
        
        cidr = sys.argv[1]
        ports_str = sys.argv[2] if len(sys.argv) > 2 else "80,443,22,21,25"
        
        scanner = CIDRScanner(threads=100, timeout=3)
        
        # Parse ports
        ports = parse_port_range(ports_str)
        
        print(f"Testing CIDR scan for: {cidr}")
        print(f"Ports to scan: {ports}")
        
        # First discover live hosts
        print("\nDiscovering live hosts...")
        live_hosts = await scanner.discover_live_hosts(cidr)
        
        print(f"Found {len(live_hosts)} live hosts:")
        for host in live_hosts[:10]:  # Show first 10
            ip = host['ip']
            methods = ', '.join(host['discovery_method'])
            print(f"  {ip} ({methods})")
        
        if len(live_hosts) > 10:
            print(f"  ... and {len(live_hosts) - 10} more")
        
        # Now scan for specific ports on live hosts
        if live_hosts:
            print(f"\nScanning specific ports on live hosts...")
            live_ips = [host['ip'] for host in live_hosts[:5]]  # Limit to first 5
            
            results = await scanner.scan_cidr_range(
                cidr=cidr,
                ports=ports,
                alive_only=True,
                ping_first=False  # We already know these are alive
            )
            
            print(f"\nPort scan results:")
            open_results = [r for r in results if r.get('open', False)]
            
            for result in open_results:
                ip = result['host']
                port = result['port']
                response_time = result.get('response_time', 0)
                print(f"  {ip}:{port} OPEN ({response_time}ms)")
    
    asyncio.run(test_cidr_scanner())