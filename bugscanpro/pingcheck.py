"""
Ping checker module for Bug Scan Pro
Handles ICMP ping functionality with async support
Created by @lonefaisal - Made with ♥️ by @lonefaisal
"""

import asyncio
import time
from typing import List, Dict, Any, Optional

try:
    import icmplib
except ImportError:
    icmplib = None

from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn

from .utils import create_semaphore, is_valid_hostname, is_valid_ip
from .output import OutputManager

console = Console()


class PingChecker:
    """ICMP ping checker with async support"""
    
    def __init__(
        self,
        threads: int = 50,
        timeout: int = 5,
        count: int = 3,
        silent: bool = False
    ):
        self.threads = threads
        self.timeout = timeout
        self.count = count
        self.silent = silent
        
        if not icmplib:
            raise ImportError("icmplib is required for ping functionality. Install with: pip install icmplib")
        
        self.semaphore = create_semaphore(threads)
        self.output_manager = OutputManager()
    
    async def ping_host(
        self,
        host: str,
        count: Optional[int] = None,
        timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """Ping a single host"""
        async with self.semaphore:
            if count is None:
                count = self.count
            if timeout is None:
                timeout = self.timeout
            
            start_time = time.time()
            
            try:
                # Use icmplib for ping
                ping_result = icmplib.ping(
                    address=host,
                    count=count,
                    timeout=timeout,
                    privileged=False  # Try unprivileged first
                )
                
                total_time = round((time.time() - start_time) * 1000, 2)
                
                result = {
                    'host': host,
                    'alive': ping_result.is_alive,
                    'packets_sent': ping_result.packets_sent,
                    'packets_received': ping_result.packets_received,
                    'packet_loss': ping_result.packet_loss,
                    'min_rtt': round(ping_result.min_rtt, 2) if ping_result.min_rtt else None,
                    'avg_rtt': round(ping_result.avg_rtt, 2) if ping_result.avg_rtt else None,
                    'max_rtt': round(ping_result.max_rtt, 2) if ping_result.max_rtt else None,
                    'total_time': total_time,
                    'timestamp': int(time.time())
                }
                
                return result
                
            except icmplib.NameLookupError:
                return {
                    'host': host,
                    'alive': False,
                    'error': 'Name lookup failed',
                    'total_time': round((time.time() - start_time) * 1000, 2),
                    'timestamp': int(time.time())
                }
            except icmplib.SocketPermissionError:
                # Try with privileged mode
                try:
                    ping_result = icmplib.ping(
                        address=host,
                        count=count,
                        timeout=timeout,
                        privileged=True
                    )
                    
                    total_time = round((time.time() - start_time) * 1000, 2)
                    
                    return {
                        'host': host,
                        'alive': ping_result.is_alive,
                        'packets_sent': ping_result.packets_sent,
                        'packets_received': ping_result.packets_received,
                        'packet_loss': ping_result.packet_loss,
                        'min_rtt': round(ping_result.min_rtt, 2) if ping_result.min_rtt else None,
                        'avg_rtt': round(ping_result.avg_rtt, 2) if ping_result.avg_rtt else None,
                        'max_rtt': round(ping_result.max_rtt, 2) if ping_result.max_rtt else None,
                        'total_time': total_time,
                        'privileged': True,
                        'timestamp': int(time.time())
                    }
                    
                except Exception as e:
                    return {
                        'host': host,
                        'alive': False,
                        'error': f'Socket permission error: {str(e)}',
                        'total_time': round((time.time() - start_time) * 1000, 2),
                        'timestamp': int(time.time())
                    }
            except Exception as e:
                return {
                    'host': host,
                    'alive': False,
                    'error': str(e),
                    'total_time': round((time.time() - start_time) * 1000, 2),
                    'timestamp': int(time.time())
                }
    
    async def ping_hosts(
        self,
        hosts: List[str],
        alive_only: bool = False,
        count: Optional[int] = None,
        timeout: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Ping multiple hosts"""
        if not hosts:
            return []
        
        if not self.silent:
            console.print(f"[blue]Pinging {len(hosts)} hosts...[/blue]")
        
        # Create ping tasks
        tasks = [self.ping_host(host, count, timeout) for host in hosts if self._is_pingable(host)]
        
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
                task = progress.add_task("Pinging hosts", total=len(tasks))
                
                for coro in asyncio.as_completed(tasks):
                    result = await coro
                    
                    # Filter results if alive_only is True
                    if not alive_only or result.get('alive', False):
                        results.append(result)
                    
                    progress.advance(task)
        else:
            ping_results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in ping_results:
                if isinstance(result, dict):
                    if not alive_only or result.get('alive', False):
                        results.append(result)
        
        if not self.silent:
            alive_count = len([r for r in results if r.get('alive', False)])
            console.print(f"[green]Found {alive_count} alive hosts out of {len(results)} tested[/green]")
        
        return results
    
    def _is_pingable(self, host: str) -> bool:
        """Check if host can be pinged (valid hostname or IP)"""
        return is_valid_hostname(host) or is_valid_ip(host)
    
    async def continuous_ping(
        self,
        host: str,
        interval: float = 1.0,
        duration: int = 60,
        timeout: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Perform continuous ping for specified duration"""
        if timeout is None:
            timeout = self.timeout
        
        if not self.silent:
            console.print(f"[blue]Continuous ping to {host} for {duration} seconds...[/blue]")
        
        results = []
        start_time = time.time()
        ping_count = 0
        
        while (time.time() - start_time) < duration:
            ping_count += 1
            
            try:
                ping_result = icmplib.ping(
                    address=host,
                    count=1,
                    timeout=timeout,
                    privileged=False
                )
                
                result = {
                    'host': host,
                    'sequence': ping_count,
                    'alive': ping_result.is_alive,
                    'rtt': round(ping_result.avg_rtt, 2) if ping_result.avg_rtt else None,
                    'timestamp': time.time()
                }
                
                results.append(result)
                
                if not self.silent:
                    status = "alive" if result['alive'] else "timeout"
                    rtt_str = f" ({result['rtt']}ms)" if result['rtt'] else ""
                    console.print(f"[{ping_count:>3}] {host}: {status}{rtt_str}")
                
            except Exception as e:
                result = {
                    'host': host,
                    'sequence': ping_count,
                    'alive': False,
                    'error': str(e),
                    'timestamp': time.time()
                }
                results.append(result)
                
                if not self.silent:
                    console.print(f"[{ping_count:>3}] {host}: error - {str(e)}")
            
            # Wait for next interval
            if (time.time() - start_time) < duration:
                await asyncio.sleep(interval)
        
        # Calculate statistics
        alive_count = len([r for r in results if r.get('alive', False)])
        packet_loss = round((1 - alive_count / len(results)) * 100, 1) if results else 100
        
        if not self.silent:
            console.print(f"\n[green]Continuous ping complete:[/green]")
            console.print(f"  Packets sent: {len(results)}")
            console.print(f"  Packets received: {alive_count}")
            console.print(f"  Packet loss: {packet_loss}%")
        
        return results
    
    async def load_hosts_from_file(self, file_path: str) -> List[str]:
        """Load hosts from file"""
        hosts = []
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if self._is_pingable(line):
                            hosts.append(line)
        except FileNotFoundError:
            raise FileNotFoundError(f"Host file not found: {file_path}")
        except Exception as e:
            raise Exception(f"Error reading host file: {e}")
        
        return list(set(hosts))  # Remove duplicates
    
    async def save_results(
        self,
        results: List[Dict[str, Any]],
        txt_file: Optional[str] = None,
        json_file: Optional[str] = None,
        csv_file: Optional[str] = None,
        append: bool = False
    ) -> None:
        """Save ping results"""
        if not results:
            console.print("[yellow]No results to save[/yellow]")
            return
        
        # Save TXT format (hostnames for alive hosts)
        if txt_file:
            txt_results = []
            for r in results:
                if r.get('alive', False):
                    txt_results.append({'host': r['host']}) 
            
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
                alive = result.get('alive', False)
                avg_rtt = result.get('avg_rtt')
                packet_loss = result.get('packet_loss', 0)
                
                if alive:
                    rtt_str = f" (avg: {avg_rtt}ms)" if avg_rtt else ""
                    loss_str = f" (loss: {packet_loss}%)" if packet_loss else ""
                    console.print(f"[green]{host}[/green] - ALIVE{rtt_str}{loss_str}")
                else:
                    error = result.get('error', 'Timeout')
                    console.print(f"[red]{host}[/red] - {error}")


if __name__ == "__main__":
    # Test the ping checker
    import sys
    
    async def test_ping_checker():
        if len(sys.argv) < 2:
            print("Usage: python pingcheck.py <host> [count] [timeout]")
            sys.exit(1)
        
        host = sys.argv[1]
        count = int(sys.argv[2]) if len(sys.argv) > 2 else 3
        timeout = int(sys.argv[3]) if len(sys.argv) > 3 else 5
        
        checker = PingChecker(timeout=timeout, count=count)
        
        print(f"Testing ping for: {host}")
        print(f"Count: {count}, Timeout: {timeout}s")
        
        result = await checker.ping_host(host)
        
        print(f"\nPing result:")
        print(f"  Alive: {result.get('alive', False)}")
        print(f"  Packets sent: {result.get('packets_sent', 0)}")
        print(f"  Packets received: {result.get('packets_received', 0)}")
        print(f"  Packet loss: {result.get('packet_loss', 0)}%")
        
        if result.get('alive'):
            print(f"  Min RTT: {result.get('min_rtt')}ms")
            print(f"  Avg RTT: {result.get('avg_rtt')}ms")
            print(f"  Max RTT: {result.get('max_rtt')}ms")
        
        if result.get('error'):
            print(f"  Error: {result.get('error')}")
        
        # Test continuous ping for 10 seconds
        print(f"\nTesting continuous ping for 10 seconds...")
        continuous_results = await checker.continuous_ping(host, interval=1.0, duration=10)
        
        alive_count = len([r for r in continuous_results if r.get('alive', False)])
        print(f"Continuous ping complete: {alive_count}/{len(continuous_results)} alive")
    
    try:
        asyncio.run(test_ping_checker())
    except ImportError as e:
        print(f"Error: {e}")
        print("Install icmplib with: pip install icmplib")