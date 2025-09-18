"""
HTTP/HTTPS reachability checker for Bug Scan Pro
Handles HTTP requests with proxy support and advanced filtering
Created by @lonefaisal - Made with ♥️ by @lonefaisal
"""

import asyncio
import aiohttp
import aiohttp_socks
import ssl
import time
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlparse
import re

from rich.console import Console
from rich.progress import Progress, TaskID, BarColumn, TextColumn, TimeRemainingColumn

from .utils import create_semaphore, is_valid_hostname
from .output import OutputManager

console = Console()


class HTTPChecker:
    """HTTP/HTTPS reachability and response analysis"""
    
    def __init__(
        self,
        threads: int = 50,
        timeout: int = 10,
        proxy: Optional[str] = None,
        user_agent: str = "bug-scan-pro/1.0",
        retries: int = 1,
        follow_redirects: bool = True,
        verify_ssl: bool = False
    ):
        self.threads = threads
        self.timeout = timeout
        self.proxy = proxy
        self.user_agent = user_agent
        self.retries = retries
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        
        self.semaphore = create_semaphore(threads)
        self.session = None
        self.output_manager = OutputManager()
        
        # SSL context for ignoring certificate errors
        self.ssl_context = ssl.create_default_context()
        if not verify_ssl:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self._create_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self._close_session()
    
    async def _create_session(self) -> None:
        """Create aiohttp session with proxy support"""
        connector_kwargs = {
            'limit': self.threads * 2,
            'limit_per_host': self.threads,
            'ssl': self.ssl_context,
            'ttl_dns_cache': 300,
            'use_dns_cache': True,
            'enable_cleanup_closed': True
        }
        
        timeout = aiohttp.ClientTimeout(
            total=self.timeout,
            connect=self.timeout // 2,
            sock_read=self.timeout
        )
        
        if self.proxy:
            # Parse proxy URL
            parsed_proxy = urlparse(self.proxy)
            if parsed_proxy.scheme in ['http', 'https']:
                connector = aiohttp.TCPConnector(**connector_kwargs)
            elif parsed_proxy.scheme in ['socks4', 'socks5']:
                connector = aiohttp_socks.ProxyConnector.from_url(
                    self.proxy,
                    **connector_kwargs
                )
            else:
                raise ValueError(f"Unsupported proxy scheme: {parsed_proxy.scheme}")
        else:
            connector = aiohttp.TCPConnector(**connector_kwargs)
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': self.user_agent},
            skip_auto_headers=['User-Agent'] if self.user_agent else None
        )
    
    async def _close_session(self) -> None:
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
    
    async def check_single_host(
        self,
        hostname: str,
        method: str = 'GET',
        schemes: List[str] = None,
        paths: List[str] = None
    ) -> Dict[str, Any]:
        """Check single host HTTP/HTTPS reachability"""
        if schemes is None:
            schemes = ['https', 'http']
        if paths is None:
            paths = ['/']
        
        if not self.session:
            await self._create_session()
        
        best_result = None
        
        for scheme in schemes:
            for path in paths:
                url = f"{scheme}://{hostname}{path}"
                
                try:
                    result = await self._make_request(url, method)
                    if result and result.get('reachable', False):
                        result['host'] = hostname
                        result['scheme'] = scheme
                        result['path'] = path
                        
                        # Prefer HTTPS over HTTP
                        if not best_result or (scheme == 'https' and best_result.get('scheme') == 'http'):
                            best_result = result
                        
                        # If HTTPS worked, don't try HTTP
                        if scheme == 'https':
                            break
                            
                except Exception as e:
                    continue
            
            # If we found a result with this scheme, continue to next host
            if best_result and best_result.get('scheme') == scheme:
                break
        
        if not best_result:
            return {
                'host': hostname,
                'reachable': False,
                'error': 'No successful connections',
                'schemes_tried': schemes,
                'timestamp': int(time.time())
            }
        
        return best_result
    
    async def _make_request(self, url: str, method: str = 'GET') -> Optional[Dict[str, Any]]:
        """Make HTTP request and return response details"""
        async with self.semaphore:
            start_time = time.time()
            
            try:
                async with self.session.request(
                    method,
                    url,
                    allow_redirects=self.follow_redirects,
                    ssl=self.ssl_context
                ) as response:
                    
                    response_time = round((time.time() - start_time) * 1000, 2)
                    
                    # Read response content (limit to prevent memory issues)
                    content = await response.read()
                    content_text = content.decode('utf-8', errors='ignore')[:10000]
                    
                    # Extract title from HTML
                    title = None
                    if 'text/html' in response.headers.get('content-type', ''):
                        title_match = re.search(r'<title[^>]*>([^<]+)</title>', content_text, re.IGNORECASE)
                        if title_match:
                            title = title_match.group(1).strip()[:100]
                    
                    result = {
                        'url': url,
                        'reachable': True,
                        'status': response.status,
                        'method': method,
                        'response_time': response_time,
                        'content_length': len(content),
                        'content_type': response.headers.get('content-type', ''),
                        'server': response.headers.get('server', ''),
                        'title': title,
                        'headers': dict(response.headers),
                        'redirect_url': str(response.url) if str(response.url) != url else None,
                        'timestamp': int(time.time())
                    }
                    
                    return result
                    
            except asyncio.TimeoutError:
                return {
                    'url': url,
                    'reachable': False,
                    'error': 'Timeout',
                    'response_time': round((time.time() - start_time) * 1000, 2)
                }
            except Exception as e:
                return {
                    'url': url,
                    'reachable': False,
                    'error': str(e),
                    'response_time': round((time.time() - start_time) * 1000, 2)
                }
    
    async def check_hosts_reachability(
        self,
        hostnames: List[str],
        method: str = 'GET',
        schemes: List[str] = None,
        silent: bool = False
    ) -> List[Dict[str, Any]]:
        """Check multiple hosts for HTTP reachability"""
        if not hostnames:
            return []
        
        if not self.session:
            await self._create_session()
        
        if not silent:
            console.print(f"[blue]Checking HTTP reachability for {len(hostnames)} hosts...[/blue]")
        
        tasks = []
        for hostname in hostnames:
            if is_valid_hostname(hostname):
                tasks.append(self.check_single_host(hostname, method, schemes))
        
        results = []
        
        if not silent:
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("({task.completed}/{task.total})"),
                TimeRemainingColumn(),
                console=console
            ) as progress:
                task = progress.add_task("HTTP checking", total=len(tasks))
                
                for coro in asyncio.as_completed(tasks):
                    result = await coro
                    results.append(result)
                    progress.advance(task)
        else:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            results = [r for r in results if isinstance(r, dict)]
        
        return results
    
    async def scan_hosts(
        self,
        hosts: List[str],
        methods: List[str] = None,
        status_include: Optional[List[int]] = None,
        status_exclude: Optional[List[int]] = None,
        header_filter: Optional[str] = None,
        body_filter: Optional[str] = None,
        silent: bool = False
    ) -> List[Dict[str, Any]]:
        """Advanced HTTP scanning with filtering"""
        if methods is None:
            methods = ['GET']
        
        if not self.session:
            await self._create_session()
        
        all_results = []
        
        for method in methods:
            if not silent:
                console.print(f"[blue]Scanning with {method} method...[/blue]")
            
            method_results = await self.check_hosts_reachability(
                hostnames=hosts,
                method=method,
                silent=silent
            )
            
            # Apply filters
            filtered_results = []
            for result in method_results:
                if not result.get('reachable', False):
                    continue
                
                status = result.get('status')
                
                # Status code filtering
                if status_include and status not in status_include:
                    continue
                if status_exclude and status in status_exclude:
                    continue
                
                # Header filtering
                if header_filter:
                    headers_str = '\n'.join(f"{k}: {v}" for k, v in result.get('headers', {}).items())
                    if header_filter.lower() not in headers_str.lower():
                        continue
                
                # Body content filtering (would need to fetch content)
                if body_filter:
                    # This would require making another request to get body content
                    # For now, we'll skip this or implement it as needed
                    pass
                
                result['method'] = method
                filtered_results.append(result)
            
            all_results.extend(filtered_results)
            
            if not silent:
                console.print(f"[green]Found {len(filtered_results)} matches with {method}[/green]")
        
        # Remove duplicates based on host
        seen_hosts = set()
        unique_results = []
        for result in all_results:
            host = result.get('host')
            if host not in seen_hosts:
                seen_hosts.add(host)
                unique_results.append(result)
        
        return unique_results
    
    async def load_hosts_from_file(self, file_path: str) -> List[str]:
        """Load hosts from file"""
        hosts = []
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Handle URLs by extracting hostname
                        if line.startswith(('http://', 'https://')):
                            parsed = urlparse(line)
                            hostname = parsed.hostname
                            if hostname:
                                hosts.append(hostname)
                        elif is_valid_hostname(line):
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
        """Save HTTP check results"""
        if not results:
            console.print("[yellow]No results to save[/yellow]")
            return
        
        # Save TXT format (just URLs)
        if txt_file:
            await self.output_manager.save_txt(
                results=[{'host': r.get('url', r.get('host', ''))} for r in results if r.get('reachable', False)],
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
                if result.get('reachable', False):
                    url = result.get('url', f"https://{result.get('host')}")
                    status = result.get('status', 'N/A')
                    title = result.get('title', 'N/A')[:50]
                    console.print(f"[green]{url}[/green] [{status}] - {title}")
    
    async def test_http_methods(
        self,
        hostname: str,
        methods: List[str] = None
    ) -> Dict[str, Dict[str, Any]]:
        """Test different HTTP methods on a hostname"""
        if methods is None:
            methods = ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'DELETE', 'PATCH']
        
        if not self.session:
            await self._create_session()
        
        results = {}
        
        for method in methods:
            try:
                result = await self.check_single_host(hostname, method)
                results[method] = result
            except Exception as e:
                results[method] = {
                    'host': hostname,
                    'method': method,
                    'reachable': False,
                    'error': str(e)
                }
        
        return results


if __name__ == "__main__":
    # Test the HTTP checker
    import sys
    
    async def test_http_checker():
        if len(sys.argv) < 2:
            print("Usage: python httpcheck.py <hostname>")
            sys.exit(1)
        
        hostname = sys.argv[1]
        
        async with HTTPChecker(threads=10, timeout=5) as checker:
            print(f"Testing HTTP reachability for: {hostname}")
            
            result = await checker.check_single_host(hostname)
            print(f"Result: {result}")
            
            # Test multiple methods
            methods_test = await checker.test_http_methods(hostname)
            print(f"\nMethod tests:")
            for method, result in methods_test.items():
                status = result.get('status', 'Failed')
                print(f"  {method}: {status}")
    
    asyncio.run(test_http_checker())