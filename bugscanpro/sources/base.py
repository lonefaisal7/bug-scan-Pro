"""
Base class for passive subdomain discovery sources
Created by @lonefaisal - Made with ♥️ by @lonefaisal
"""

from abc import ABC, abstractmethod
from typing import List, Set, Optional, Dict, Any
import aiohttp
import asyncio
import time

from rich.console import Console

console = Console()


class BaseSource(ABC):
    """Abstract base class for passive subdomain discovery sources"""
    
    def __init__(
        self,
        name: str,
        timeout: int = 30,
        max_retries: int = 3,
        user_agent: str = "bug-scan-pro/1.0"
    ):
        self.name = name
        self.timeout = timeout
        self.max_retries = max_retries
        self.user_agent = user_agent
        self._session = None
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self._create_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self._close_session()
    
    async def _create_session(self) -> None:
        """Create aiohttp session"""
        if not self._session:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            headers = {'User-Agent': self.user_agent}
            
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                headers=headers,
                connector=aiohttp.TCPConnector(
                    limit=100,
                    limit_per_host=30,
                    ttl_dns_cache=300
                )
            )
    
    async def _close_session(self) -> None:
        """Close aiohttp session"""
        if self._session:
            await self._session.close()
            self._session = None
    
    async def _make_request(
        self,
        url: str,
        method: str = 'GET',
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        json_data: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """Make HTTP request with retry logic"""
        if not self._session:
            await self._create_session()
        
        for attempt in range(self.max_retries + 1):
            try:
                async with self._session.request(
                    method=method,
                    url=url,
                    params=params,
                    headers=headers,
                    json=json_data
                ) as response:
                    if response.status == 200:
                        # Try to parse as JSON first
                        try:
                            data = await response.json()
                            return {'status': response.status, 'data': data, 'text': None}
                        except:
                            # Fallback to text
                            text = await response.text()
                            return {'status': response.status, 'data': None, 'text': text}
                    elif response.status == 429:  # Rate limited
                        if attempt < self.max_retries:
                            wait_time = 2 ** attempt  # Exponential backoff
                            console.print(f"[yellow]Rate limited by {self.name}, waiting {wait_time}s...[/yellow]")
                            await asyncio.sleep(wait_time)
                            continue
                    else:
                        console.print(f"[red]HTTP {response.status} from {self.name}: {url}[/red]")
                        return None
            
            except asyncio.TimeoutError:
                if attempt < self.max_retries:
                    console.print(f"[yellow]Timeout from {self.name}, retrying ({attempt + 1}/{self.max_retries})...[/yellow]")
                    await asyncio.sleep(1)
                    continue
                else:
                    console.print(f"[red]Timeout from {self.name} after {self.max_retries} retries[/red]")
                    return None
            
            except Exception as e:
                if attempt < self.max_retries:
                    console.print(f"[yellow]Error from {self.name}: {str(e)}, retrying...[/yellow]")
                    await asyncio.sleep(1)
                    continue
                else:
                    console.print(f"[red]Failed to query {self.name}: {str(e)}[/red]")
                    return None
        
        return None
    
    @abstractmethod
    async def get_subdomains(self, domain: str) -> Set[str]:
        """Get subdomains for a domain from this source"""
        pass
    
    def clean_subdomain(self, subdomain: str, domain: str) -> Optional[str]:
        """Clean and validate subdomain"""
        if not subdomain or not domain:
            return None
        
        # Remove common prefixes
        subdomain = subdomain.strip()
        subdomain = subdomain.lstrip('*.')
        subdomain = subdomain.lower()
        
        # Validate subdomain format
        if not subdomain.endswith(f'.{domain}') and subdomain != domain:
            if '.' in subdomain and not subdomain.endswith(domain):
                return None
        
        # Remove trailing dots
        subdomain = subdomain.rstrip('.')
        
        # Basic validation
        if len(subdomain) > 253 or '..' in subdomain:
            return None
        
        # Check for valid characters
        for label in subdomain.split('.'):
            if not label or len(label) > 63:
                return None
            if not label.replace('-', '').replace('_', '').isalnum():
                return None
        
        return subdomain
    
    def extract_subdomains_from_text(
        self,
        text: str,
        domain: str
    ) -> Set[str]:
        """Extract subdomains from text using regex"""
        import re
        
        subdomains = set()
        
        # Pattern to match subdomains
        # This pattern matches: word.word.domain.tld or domain.tld
        escaped_domain = re.escape(domain)
        pattern = rf'\b(?:[a-zA-Z0-9-_]+\.)*{escaped_domain}\b'
        
        matches = re.findall(pattern, text, re.IGNORECASE)
        
        for match in matches:
            cleaned = self.clean_subdomain(match, domain)
            if cleaned:
                subdomains.add(cleaned)
        
        return subdomains
    
    async def get_metadata(self) -> Dict[str, Any]:
        """Get metadata about this source"""
        return {
            'name': self.name,
            'timeout': self.timeout,
            'max_retries': self.max_retries,
            'user_agent': self.user_agent
        }
    
    def get_rate_limit_info(self) -> Dict[str, Any]:
        """Get rate limit information for this source"""
        return {
            'requests_per_minute': None,
            'requests_per_hour': None,
            'requests_per_day': None,
            'burst_limit': None
        }
    
    async def test_connectivity(self) -> Dict[str, Any]:
        """Test connectivity to the source"""
        start_time = time.time()
        
        try:
            # This should be overridden by subclasses with their specific test
            result = await self._test_source_specific()
            response_time = round((time.time() - start_time) * 1000, 2)
            
            return {
                'source': self.name,
                'accessible': result.get('accessible', False),
                'response_time_ms': response_time,
                'error': result.get('error'),
                'details': result.get('details', {})
            }
        
        except Exception as e:
            response_time = round((time.time() - start_time) * 1000, 2)
            return {
                'source': self.name,
                'accessible': False,
                'response_time_ms': response_time,
                'error': str(e)
            }
    
    async def _test_source_specific(self) -> Dict[str, Any]:
        """Source-specific connectivity test (override in subclasses)"""
        return {'accessible': True}
    
    def __str__(self) -> str:
        return f"{self.__class__.__name__}({self.name})"
    
    def __repr__(self) -> str:
        return self.__str__()