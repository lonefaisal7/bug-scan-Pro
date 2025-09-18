"""
DNS information lookup module for Bug Scan Pro
Handles DNS record queries and analysis
Created by @lonefaisal - Made with ♥️ by @lonefaisal
"""

import asyncio
import time
from typing import List, Dict, Any, Optional

from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from rich.table import Table

from .resolver import DNSResolver
from .utils import create_semaphore, is_valid_hostname
from .output import OutputManager

console = Console()


class DNSLookup:
    """DNS record lookup and analysis"""
    
    def __init__(
        self,
        threads: int = 50,
        resolver: Optional[str] = None,
        timeout: int = 5,
        silent: bool = False
    ):
        self.threads = threads
        self.timeout = timeout
        self.silent = silent
        
        # Initialize DNS resolver
        nameservers = [resolver] if resolver else None
        self.dns_resolver = DNSResolver(
            threads=threads,
            timeout=timeout,
            nameservers=nameservers
        )
        
        self.semaphore = create_semaphore(threads)
        self.output_manager = OutputManager()
    
    async def lookup_records(
        self,
        hosts: List[str],
        record_type: str = 'A'
    ) -> List[Dict[str, Any]]:
        """Lookup DNS records for multiple hosts"""
        if not hosts:
            return []
        
        record_type = record_type.upper()
        
        if not self.silent:
            console.print(f"[blue]Looking up {record_type} records for {len(hosts)} hosts...[/blue]")
        
        # Create lookup tasks
        tasks = [self._lookup_single_host(host, record_type) for host in hosts]
        
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
                task = progress.add_task(f"DNS {record_type} lookup", total=len(tasks))
                
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
            successful = len([r for r in results if r.get('records')])
            console.print(f"[green]Found {record_type} records for {successful}/{len(hosts)} hosts[/green]")
        
        return results
    
    async def _lookup_single_host(
        self,
        hostname: str,
        record_type: str
    ) -> Optional[Dict[str, Any]]:
        """Lookup DNS records for a single host"""
        async with self.semaphore:
            start_time = time.time()
            
            try:
                records = await self.dns_resolver.resolve_hostname(hostname, record_type)
                response_time = round((time.time() - start_time) * 1000, 2)
                
                return {
                    'host': hostname,
                    'record_type': record_type,
                    'records': records,
                    'found': bool(records),
                    'count': len(records) if records else 0,
                    'response_time': response_time,
                    'timestamp': int(time.time())
                }
                
            except Exception as e:
                return {
                    'host': hostname,
                    'record_type': record_type,
                    'records': [],
                    'found': False,
                    'count': 0,
                    'error': str(e),
                    'response_time': round((time.time() - start_time) * 1000, 2),
                    'timestamp': int(time.time())
                }
    
    async def comprehensive_dns_lookup(
        self,
        hostname: str,
        record_types: List[str] = None
    ) -> Dict[str, Any]:
        """Perform comprehensive DNS lookup for all record types"""
        if record_types is None:
            record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
        
        if not self.silent:
            console.print(f"[blue]Comprehensive DNS lookup for {hostname}...[/blue]")
        
        all_records = await self.dns_resolver.get_dns_records(hostname, record_types)
        
        result = {
            'host': hostname,
            'records': all_records,
            'record_types_found': list(all_records.keys()),
            'total_records': sum(len(records) for records in all_records.values()),
            'timestamp': int(time.time())
        }
        
        # Add some analysis
        result['has_ipv4'] = bool(all_records.get('A'))
        result['has_ipv6'] = bool(all_records.get('AAAA'))
        result['has_mail_servers'] = bool(all_records.get('MX'))
        result['is_cname'] = bool(all_records.get('CNAME'))
        
        if not self.silent:
            self._display_comprehensive_results(result)
        
        return result
    
    def _display_comprehensive_results(self, result: Dict[str, Any]) -> None:
        """Display comprehensive DNS results in a nice table"""
        hostname = result['host']
        records = result['records']
        
        console.print(f"\n[bold cyan]DNS Records for {hostname}[/bold cyan]")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Record Type", style="cyan", no_wrap=True)
        table.add_column("Count", style="green", no_wrap=True)
        table.add_column("Values", style="white")
        
        for record_type, values in records.items():
            if values:
                # Limit displayed values to avoid too much output
                display_values = values[:5]  # Show first 5
                values_str = "\n".join(display_values)
                if len(values) > 5:
                    values_str += f"\n... and {len(values) - 5} more"
                
                table.add_row(record_type, str(len(values)), values_str)
        
        console.print(table)
        
        # Summary
        total_records = result['total_records']
        console.print(f"\n[green]Total records found: {total_records}[/green]")
    
    async def reverse_dns_lookup(
        self,
        ips: List[str]
    ) -> List[Dict[str, Any]]:
        """Perform reverse DNS lookup for IP addresses"""
        if not ips:
            return []
        
        if not self.silent:
            console.print(f"[blue]Reverse DNS lookup for {len(ips)} IP addresses...[/blue]")
        
        tasks = [self._reverse_lookup_single_ip(ip) for ip in ips]
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
        
        return results
    
    async def _reverse_lookup_single_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Reverse DNS lookup for a single IP"""
        async with self.semaphore:
            start_time = time.time()
            
            try:
                hostname = await self.dns_resolver.reverse_lookup(ip)
                response_time = round((time.time() - start_time) * 1000, 2)
                
                return {
                    'ip': ip,
                    'hostname': hostname,
                    'found': bool(hostname),
                    'response_time': response_time,
                    'timestamp': int(time.time())
                }
                
            except Exception as e:
                return {
                    'ip': ip,
                    'hostname': None,
                    'found': False,
                    'error': str(e),
                    'response_time': round((time.time() - start_time) * 1000, 2),
                    'timestamp': int(time.time())
                }
    
    async def dns_zone_transfer(
        self,
        domain: str,
        nameserver: Optional[str] = None
    ) -> Dict[str, Any]:
        """Attempt DNS zone transfer (AXFR)"""
        try:
            import dns.zone
            import dns.query
            
            if not nameserver:
                # Get authoritative nameservers
                ns_records = await self.dns_resolver.get_nameservers(domain)
                if not ns_records:
                    return {
                        'domain': domain,
                        'success': False,
                        'error': 'No nameservers found'
                    }
                nameserver = ns_records[0].rstrip('.')
            
            # Attempt zone transfer
            zone_data = dns.zone.from_xfr(dns.query.xfr(nameserver, domain))
            
            # Extract records from zone
            records = []
            for name, node in zone_data.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        records.append({
                            'name': str(name),
                            'type': dns.rdatatype.to_text(rdataset.rdtype),
                            'value': str(rdata)
                        })
            
            return {
                'domain': domain,
                'nameserver': nameserver,
                'success': True,
                'records': records,
                'record_count': len(records),
                'timestamp': int(time.time())
            }
            
        except ImportError:
            return {
                'domain': domain,
                'success': False,
                'error': 'DNS zone transfer requires dnspython library'
            }
        except Exception as e:
            return {
                'domain': domain,
                'nameserver': nameserver,
                'success': False,
                'error': str(e),
                'timestamp': int(time.time())
            }
    
    async def load_hosts_from_file(self, file_path: str) -> List[str]:
        """Load hosts from file"""
        hosts = []
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if is_valid_hostname(line):
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
        """Save DNS lookup results"""
        if not results:
            console.print("[yellow]No results to save[/yellow]")
            return
        
        # Save TXT format (hostname:record for found records)
        if txt_file:
            txt_results = []
            for r in results:
                if r.get('found', False) and r.get('records'):
                    for record in r['records']:
                        txt_results.append({'host': f"{r['host']}:{record}"}) 
            
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
                record_type = result.get('record_type', 'A')
                records = result.get('records', [])
                
                if records:
                    console.print(f"[green]{host}[/green] ({record_type}): {', '.join(records[:5])}")
                    if len(records) > 5:
                        console.print(f"  ... and {len(records) - 5} more records")
                else:
                    error = result.get('error', 'No records found')
                    console.print(f"[red]{host}[/red] ({record_type}): {error}")


if __name__ == "__main__":
    # Test the DNS lookup
    import sys
    
    async def test_dns_lookup():
        if len(sys.argv) < 2:
            print("Usage: python dnsinfo.py <hostname> [record_type]")
            sys.exit(1)
        
        hostname = sys.argv[1]
        record_type = sys.argv[2] if len(sys.argv) > 2 else 'A'
        
        lookup = DNSLookup(threads=10)
        
        print(f"Testing DNS lookup for: {hostname}")
        
        # Test single record type
        results = await lookup.lookup_records([hostname], record_type)
        
        if results:
            result = results[0]
            records = result.get('records', [])
            print(f"\n{record_type} records: {records}")
        
        # Test comprehensive lookup
        print(f"\nComprehensive DNS lookup:")
        comp_result = await lookup.comprehensive_dns_lookup(hostname)
        
        # Test zone transfer
        print(f"\nAttempting zone transfer:")
        zone_result = await lookup.dns_zone_transfer(hostname)
        
        if zone_result.get('success'):
            print(f"Zone transfer successful: {zone_result.get('record_count', 0)} records")
        else:
            print(f"Zone transfer failed: {zone_result.get('error')}")
    
    asyncio.run(test_dns_lookup())