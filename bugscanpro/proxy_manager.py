"""
Advanced proxy manager with intelligent selection and health monitoring
Created by @lonefaisal - Made with ♥️ by @lonefaisal
"""

import asyncio
import aiohttp
import time
import random
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass
from urllib.parse import urlparse
import json
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn

console = Console()


@dataclass
class ProxyInfo:
    """Proxy information and metrics"""
    url: str
    proxy_type: str  # http, socks4, socks5
    country: Optional[str] = None
    city: Optional[str] = None
    response_time: Optional[float] = None
    success_rate: float = 0.0
    last_checked: Optional[float] = None
    is_healthy: bool = True
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0


class ProxyHealthChecker:
    """Health monitoring for proxy servers"""
    
    def __init__(self, check_interval: int = 300, timeout: int = 10):
        self.check_interval = check_interval  # 5 minutes
        self.timeout = timeout
        self.test_urls = [
            'http://httpbin.org/ip',
            'https://api.ipify.org',
            'http://icanhazip.com'
        ]
    
    async def check_proxy_health(self, proxy_info: ProxyInfo) -> ProxyInfo:
        """Check health of a single proxy"""
        start_time = time.time()
        
        try:
            # Parse proxy URL
            parsed = urlparse(proxy_info.url)
            
            if parsed.scheme in ['http', 'https']:
                connector = aiohttp.TCPConnector()
                proxy_url = proxy_info.url
            elif parsed.scheme in ['socks4', 'socks5']:
                import aiohttp_socks
                connector = aiohttp_socks.ProxyConnector.from_url(proxy_info.url)
                proxy_url = None
            else:
                proxy_info.is_healthy = False
                proxy_info.last_checked = time.time()
                return proxy_info
            
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout
            ) as session:
                
                # Test with multiple URLs
                successful_tests = 0
                
                for test_url in self.test_urls:
                    try:
                        async with session.get(
                            test_url,
                            proxy=proxy_url
                        ) as response:
                            if response.status == 200:
                                successful_tests += 1
                    except Exception:
                        continue
                
                # Calculate health metrics
                proxy_info.response_time = (time.time() - start_time) * 1000
                proxy_info.success_rate = successful_tests / len(self.test_urls)
                proxy_info.is_healthy = proxy_info.success_rate > 0.5
                proxy_info.last_checked = time.time()
                
        except Exception as e:
            proxy_info.is_healthy = False
            proxy_info.response_time = (time.time() - start_time) * 1000
            proxy_info.last_checked = time.time()
        
        return proxy_info
    
    async def check_proxy_pool_health(self, proxy_pool: List[ProxyInfo]) -> List[ProxyInfo]:
        """Check health of entire proxy pool"""
        if not proxy_pool:
            return []
        
        console.print(f"[blue]🔍 Checking health of {len(proxy_pool)} proxies...[/blue]")
        
        # Create health check tasks
        tasks = [self.check_proxy_health(proxy) for proxy in proxy_pool]
        
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("Health checking proxies", total=len(tasks))
            
            results = []
            for coro in asyncio.as_completed(tasks):
                result = await coro
                results.append(result)
                progress.advance(task)
        
        healthy_count = len([p for p in results if p.is_healthy])
        console.print(f"[green]✅ {healthy_count}/{len(results)} proxies are healthy[/green]")
        
        return results


class AdvancedProxyManager:
    """Advanced proxy management with intelligent selection"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.proxy_pool: List[ProxyInfo] = []
        self.health_checker = ProxyHealthChecker()
        self.config_file = config_file
        self.usage_stats: Dict[str, Dict] = {}
        
        # Load proxy configuration if provided
        if config_file and Path(config_file).exists():
            asyncio.create_task(self.load_proxy_config(config_file))
    
    async def load_proxy_config(self, config_file: str) -> None:
        """Load proxy configuration from file"""
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            
            for proxy_data in config.get('proxies', []):
                proxy_info = ProxyInfo(
                    url=proxy_data['url'],
                    proxy_type=proxy_data.get('type', 'http'),
                    country=proxy_data.get('country'),
                    city=proxy_data.get('city')
                )
                self.proxy_pool.append(proxy_info)
            
            console.print(f"[green]✅ Loaded {len(self.proxy_pool)} proxies from config[/green]")
            
        except Exception as e:
            console.print(f"[red]❌ Error loading proxy config: {e}[/red]")
    
    async def add_proxy(self, proxy_url: str, proxy_type: str = 'http') -> None:
        """Add a proxy to the pool"""
        proxy_info = ProxyInfo(url=proxy_url, proxy_type=proxy_type)
        
        # Test proxy health before adding
        proxy_info = await self.health_checker.check_proxy_health(proxy_info)
        
        if proxy_info.is_healthy:
            self.proxy_pool.append(proxy_info)
            console.print(f"[green]✅ Added healthy proxy: {proxy_url}[/green]")
        else:
            console.print(f"[red]❌ Proxy failed health check: {proxy_url}[/red]")
    
    async def get_best_proxy(
        self,
        target: Optional[str] = None,
        prefer_country: Optional[str] = None
    ) -> Optional[ProxyInfo]:
        """Get the best performing proxy for a target"""
        healthy_proxies = [p for p in self.proxy_pool if p.is_healthy]
        
        if not healthy_proxies:
            return None
        
        # Filter by country preference if specified
        if prefer_country:
            country_proxies = [p for p in healthy_proxies if p.country == prefer_country]
            if country_proxies:
                healthy_proxies = country_proxies
        
        # Sort by performance (response time and success rate)
        healthy_proxies.sort(key=lambda p: (
            -p.success_rate,  # Higher success rate first
            p.response_time or float('inf')  # Lower response time first
        ))
        
        return healthy_proxies[0] if healthy_proxies else None
    
    async def get_random_proxy(self) -> Optional[ProxyInfo]:
        """Get a random healthy proxy"""
        healthy_proxies = [p for p in self.proxy_pool if p.is_healthy]
        
        if not healthy_proxies:
            return None
        
        return random.choice(healthy_proxies)
    
    async def rotate_proxy_pool(self) -> None:
        """Rotate and refresh proxy pool health"""
        if not self.proxy_pool:
            return
        
        console.print("[blue]🔄 Rotating proxy pool...[/blue]")
        
        # Check health of all proxies
        self.proxy_pool = await self.health_checker.check_proxy_pool_health(
            self.proxy_pool
        )
        
        # Remove consistently failing proxies
        self.proxy_pool = [
            p for p in self.proxy_pool 
            if p.success_rate > 0.1 or p.total_requests < 10
        ]
    
    async def update_proxy_stats(self, proxy_url: str, success: bool) -> None:
        """Update proxy usage statistics"""
        for proxy in self.proxy_pool:
            if proxy.url == proxy_url:
                proxy.total_requests += 1
                
                if success:
                    proxy.successful_requests += 1
                else:
                    proxy.failed_requests += 1
                
                # Recalculate success rate
                if proxy.total_requests > 0:
                    proxy.success_rate = proxy.successful_requests / proxy.total_requests
                
                break
    
    async def get_proxy_statistics(self) -> Dict[str, Any]:
        """Get comprehensive proxy statistics"""
        if not self.proxy_pool:
            return {'total_proxies': 0}
        
        healthy_count = len([p for p in self.proxy_pool if p.is_healthy])
        avg_response_time = sum(
            p.response_time for p in self.proxy_pool 
            if p.response_time is not None
        ) / len([p for p in self.proxy_pool if p.response_time is not None])
        
        avg_success_rate = sum(p.success_rate for p in self.proxy_pool) / len(self.proxy_pool)
        
        total_requests = sum(p.total_requests for p in self.proxy_pool)
        total_successful = sum(p.successful_requests for p in self.proxy_pool)
        
        return {
            'total_proxies': len(self.proxy_pool),
            'healthy_proxies': healthy_count,
            'health_percentage': (healthy_count / len(self.proxy_pool)) * 100,
            'average_response_time_ms': avg_response_time,
            'average_success_rate': avg_success_rate,
            'total_requests_made': total_requests,
            'total_successful_requests': total_successful,
            'overall_success_rate': (total_successful / total_requests * 100) if total_requests > 0 else 0
        }
    
    def export_proxy_config(self, filename: str) -> None:
        """Export current proxy configuration"""
        config = {
            'proxies': [
                {
                    'url': proxy.url,
                    'type': proxy.proxy_type,
                    'country': proxy.country,
                    'city': proxy.city,
                    'is_healthy': proxy.is_healthy,
                    'success_rate': proxy.success_rate,
                    'response_time': proxy.response_time
                }
                for proxy in self.proxy_pool
            ]
        }
        
        with open(filename, 'w') as f:
            json.dump(config, f, indent=2)
        
        console.print(f"[green]✅ Exported proxy config to {filename}[/green]")