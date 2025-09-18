"""
Port scanner module for Bug Scan Pro
Handles TCP port scanning with async support
Created by @lonefaisal - Made with ♥️ by @lonefaisal
"""

import asyncio
import socket
import time
from typing import List, Dict, Any, Optional

from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn

from .utils import create_semaphore, is_valid_hostname, parse_port_range
from .output import OutputManager

console = Console()


class PortScanner:
    """TCP port scanner with async support"""
    
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
        self.output_manager = OutputManager()
    
    async def scan_port(
        self,
        host: str,
        port: int
    ) -> Dict[str, Any]:
        """Scan a single port on a host"""
        async with self.semaphore:
            start_time = time.time()
            
            try:
                # Create socket connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                
                result = sock.connect_ex((host, port))
                sock.close()
                
                response_time = round((time.time() - start_time) * 1000, 2)
                
                is_open = (result == 0)
                
                return {
                    'host': host,
                    'port': port,
                    'open': is_open,
                    'response_time': response_time,
                    'timestamp': int(time.time())
                }
                
            except socket.gaierror:
                return {
                    'host': host,
                    'port': port,
                    'open': False,
                    'error': 'Name resolution failed',
                    'response_time': round((time.time() - start_time) * 1000, 2),
                    'timestamp': int(time.time())
                }
            except Exception as e:
                return {
                    'host': host,
                    'port': port,
                    'open': False,
                    'error': str(e),
                    'response_time': round((time.time() - start_time) * 1000, 2),
                    'timestamp': int(time.time())
                }
    
    async def scan_host_ports(
        self,
        host: str,
        ports: List[int],
        open_only: bool = False
    ) -> List[Dict[str, Any]]:
        """Scan multiple ports on a single host"""
        if not is_valid_hostname(host) and not host.replace('.', '').isdigit():
            raise ValueError(f"Invalid host: {host}")
        
        if not self.silent:
            console.print(f"[blue]Scanning {len(ports)} ports on {host}...[/blue]")
        
        # Create scan tasks
        tasks = [self.scan_port(host, port) for port in ports]
        
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
                task = progress.add_task(f"Port scanning {host}", total=len(tasks))
                
                for coro in asyncio.as_completed(tasks):
                    result = await coro
                    
                    # Filter results if open_only is True
                    if not open_only or result.get('open', False):
                        results.append(result)
                    
                    progress.advance(task)
        else:
            scan_results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in scan_results:
                if isinstance(result, dict):
                    if not open_only or result.get('open', False):
                        results.append(result)
        
        # Sort by port number
        results.sort(key=lambda x: x.get('port', 0))
        
        if not self.silent:
            open_ports = [r for r in results if r.get('open', False)]
            console.print(f"[green]Found {len(open_ports)} open ports on {host}[/green]")
        
        return results
    
    async def scan_multiple_hosts(
        self,
        hosts: List[str],
        ports: List[int],
        open_only: bool = False
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Scan multiple hosts and ports"""
        if not hosts:
            return {}
        
        if not self.silent:
            console.print(f"[blue]Scanning {len(hosts)} hosts on {len(ports)} ports...[/blue]")
        
        all_results = {}
        
        for host in hosts:
            try:
                host_results = await self.scan_host_ports(host, ports, open_only)
                all_results[host] = host_results
                
                if not self.silent:
                    open_count = len([r for r in host_results if r.get('open', False)])
                    console.print(f"[green]{host}: {open_count} open ports[/green]")
                    
            except Exception as e:
                if not self.silent:
                    console.print(f"[red]Error scanning {host}: {e}[/red]")
                all_results[host] = []
        
        return all_results
    
    async def banner_grab(
        self,
        host: str,
        port: int,
        timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """Attempt to grab service banner from an open port"""
        if timeout is None:
            timeout = self.timeout
        
        try:
            # First check if port is open
            port_result = await self.scan_port(host, port)
            if not port_result.get('open', False):
                return {
                    'host': host,
                    'port': port,
                    'open': False,
                    'banner': None
                }
            
            # Try to grab banner
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            sock.connect((host, port))
            
            # Send common probes based on port
            probe_data = self._get_probe_for_port(port)
            if probe_data:
                sock.send(probe_data.encode('utf-8', errors='ignore'))
            
            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return {
                'host': host,
                'port': port,
                'open': True,
                'banner': banner if banner else None,
                'service': self._identify_service(port, banner)
            }
            
        except Exception as e:
            return {
                'host': host,
                'port': port,
                'open': True,
                'banner': None,
                'error': str(e)
            }
    
    def _get_probe_for_port(self, port: int) -> Optional[str]:
        """Get appropriate probe data for common ports"""
        probes = {
            21: "\r\n",  # FTP
            22: "\r\n",  # SSH
            23: "\r\n",  # Telnet
            25: "EHLO example.com\r\n",  # SMTP
            53: "\r\n",  # DNS
            80: "GET / HTTP/1.1\r\nHost: {}\r\n\r\n",  # HTTP
            110: "\r\n",  # POP3
            143: "\r\n",  # IMAP
            443: "\r\n",  # HTTPS
            993: "\r\n",  # IMAPS
            995: "\r\n",  # POP3S
        }
        
        return probes.get(port)
    
    def _identify_service(self, port: int, banner: str) -> str:
        """Identify service based on port and banner"""
        # Common port to service mapping
        common_services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            3389: "RDP",
            5432: "PostgreSQL",
            3306: "MySQL",
            1433: "MSSQL",
            6379: "Redis",
            27017: "MongoDB"
        }
        
        service = common_services.get(port, "Unknown")
        
        # Refine based on banner if available
        if banner:
            banner_lower = banner.lower()
            if "ssh" in banner_lower:
                service = "SSH"
            elif "ftp" in banner_lower:
                service = "FTP"
            elif "http" in banner_lower or "apache" in banner_lower or "nginx" in banner_lower:
                service = "HTTP"
            elif "smtp" in banner_lower or "mail" in banner_lower:
                service = "SMTP"
            elif "mysql" in banner_lower:
                service = "MySQL"
            elif "postgresql" in banner_lower or "postgres" in banner_lower:
                service = "PostgreSQL"
        
        return service
    
    async def save_results(
        self,
        results: List[Dict[str, Any]],
        txt_file: Optional[str] = None,
        json_file: Optional[str] = None,
        csv_file: Optional[str] = None,
        append: bool = False
    ) -> None:
        """Save port scan results"""
        if not results:
            console.print("[yellow]No results to save[/yellow]")
            return
        
        # Save TXT format (host:port for open ports)
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
            for result in results:
                host = result.get('host')
                port = result.get('port')
                is_open = result.get('open', False)
                service = result.get('service', 'Unknown')
                
                if is_open:
                    console.print(f"[green]{host}:{port}[/green] - {service}")
                else:
                    console.print(f"[red]{host}:{port}[/red] - Closed")


if __name__ == "__main__":
    # Test the port scanner
    import sys
    
    async def test_port_scanner():
        if len(sys.argv) < 2:
            print("Usage: python portscan.py <host> [ports]")
            sys.exit(1)
        
        host = sys.argv[1]
        ports_str = sys.argv[2] if len(sys.argv) > 2 else "80,443,22,21,25"
        
        scanner = PortScanner(threads=50, timeout=3)
        
        # Parse ports
        ports = parse_port_range(ports_str)
        
        print(f"Testing port scan for: {host}")
        print(f"Ports to scan: {ports}")
        
        results = await scanner.scan_host_ports(host, ports, open_only=False)
        
        print(f"\nScan results:")
        for result in results:
            port = result['port']
            is_open = result.get('open', False)
            response_time = result.get('response_time', 0)
            
            status = "OPEN" if is_open else "CLOSED"
            print(f"  {port}/tcp: {status} ({response_time}ms)")
        
        # Test banner grabbing on open ports
        open_ports = [r['port'] for r in results if r.get('open', False)]
        if open_ports:
            print(f"\nBanner grabbing on open ports...")
            for port in open_ports[:3]:  # Limit to first 3
                banner_result = await scanner.banner_grab(host, port)
                banner = banner_result.get('banner')
                service = banner_result.get('service', 'Unknown')
                print(f"  {port}/tcp ({service}): {banner[:50] if banner else 'No banner'}")
    
    asyncio.run(test_port_scanner())