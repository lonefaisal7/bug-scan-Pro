"""
AlienVault OTX (Open Threat Exchange) source for subdomain discovery
Created by @lonefaisal - Made with ♥️ by @lonefaisal
"""

import os
from typing import Set, Dict, Any, Optional

from rich.console import Console

from .base import BaseSource

console = Console()


class OTXSource(BaseSource):
    """AlienVault OTX passive DNS subdomain discovery"""
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: int = 30
    ):
        super().__init__(
            name="AlienVault OTX",
            timeout=timeout,
            max_retries=3,
            user_agent="bug-scan-pro/1.0"
        )
        
        # Get API key from parameter or environment
        self.api_key = api_key or os.getenv('OTX_API_KEY')
        
        self.base_url = "https://otx.alienvault.com"
        self.api_url = f"{self.base_url}/api/v1"
    
    async def get_subdomains(self, domain: str) -> Set[str]:
        """Get subdomains from AlienVault OTX passive DNS"""
        if not self.api_key:
            console.print(f"[yellow]OTX API key not provided, skipping OTX source[/yellow]")
            return set()
        
        subdomains = set()
        
        # Method 1: Get passive DNS data
        passive_dns_subs = await self._get_passive_dns_subdomains(domain)
        subdomains.update(passive_dns_subs)
        
        # Method 2: Get URL list data
        url_list_subs = await self._get_url_list_subdomains(domain)
        subdomains.update(url_list_subs)
        
        return subdomains
    
    async def _get_passive_dns_subdomains(self, domain: str) -> Set[str]:
        """Get subdomains from OTX passive DNS data"""
        subdomains = set()
        
        url = f"{self.api_url}/indicators/domain/{domain}/passive_dns"
        headers = {'X-OTX-API-KEY': self.api_key}
        
        try:
            response = await self._make_request(
                url=url,
                headers=headers
            )
            
            if response and response.get('data'):
                passive_dns_data = response['data']
                
                if 'passive_dns' in passive_dns_data:
                    for record in passive_dns_data['passive_dns']:
                        hostname = record.get('hostname', '')
                        if hostname and domain in hostname:
                            cleaned = self.clean_subdomain(hostname, domain)
                            if cleaned:
                                subdomains.add(cleaned)
        
        except Exception as e:
            console.print(f"[red]Error querying OTX passive DNS: {e}[/red]")
        
        return subdomains
    
    async def _get_url_list_subdomains(self, domain: str) -> Set[str]:
        """Get subdomains from OTX URL list data"""
        subdomains = set()
        
        url = f"{self.api_url}/indicators/domain/{domain}/url_list"
        headers = {'X-OTX-API-KEY': self.api_key}
        
        try:
            # Get first page of URL list
            response = await self._make_request(
                url=url,
                headers=headers,
                params={'limit': 100}  # Limit to avoid too much data
            )
            
            if response and response.get('data'):
                url_data = response['data']
                
                if 'url_list' in url_data:
                    for url_entry in url_data['url_list']:
                        url_str = url_entry.get('url', '')
                        if url_str:
                            # Extract hostname from URL
                            hostname = self._extract_hostname_from_url(url_str)
                            if hostname and domain in hostname:
                                cleaned = self.clean_subdomain(hostname, domain)
                                if cleaned:
                                    subdomains.add(cleaned)
        
        except Exception as e:
            console.print(f"[red]Error querying OTX URL list: {e}[/red]")
        
        return subdomains
    
    def _extract_hostname_from_url(self, url: str) -> Optional[str]:
        """Extract hostname from URL"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.hostname
        except Exception:
            return None
    
    async def get_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Get domain reputation data from OTX"""
        if not self.api_key:
            return {'error': 'API key required'}
        
        url = f"{self.api_url}/indicators/domain/{domain}/general"
        headers = {'X-OTX-API-KEY': self.api_key}
        
        try:
            response = await self._make_request(
                url=url,
                headers=headers
            )
            
            if response and response.get('data'):
                general_data = response['data']
                
                return {
                    'domain': domain,
                    'reputation': {
                        'whois': general_data.get('whois'),
                        'alexa': general_data.get('alexa'),
                        'base_indicator': general_data.get('base_indicator', {}),
                        'pulse_info': general_data.get('pulse_info', {})
                    }
                }
        
        except Exception as e:
            return {'domain': domain, 'error': str(e)}
    
    async def get_malware_samples(self, domain: str) -> Dict[str, Any]:
        """Get malware samples associated with domain"""
        if not self.api_key:
            return {'error': 'API key required'}
        
        url = f"{self.api_url}/indicators/domain/{domain}/malware"
        headers = {'X-OTX-API-KEY': self.api_key}
        
        try:
            response = await self._make_request(
                url=url,
                headers=headers
            )
            
            if response and response.get('data'):
                malware_data = response['data']
                
                return {
                    'domain': domain,
                    'malware_samples': malware_data.get('data', []),
                    'count': len(malware_data.get('data', []))
                }
        
        except Exception as e:
            return {'domain': domain, 'error': str(e)}
    
    async def _test_source_specific(self) -> Dict[str, Any]:
        """Test OTX connectivity and API key validity"""
        if not self.api_key:
            return {
                'accessible': False,
                'error': 'No API key provided. Set OTX_API_KEY environment variable or provide api_key parameter.'
            }
        
        try:
            # Test API key by making a simple request
            url = f"{self.api_url}/indicators/domain/google.com/general"
            headers = {'X-OTX-API-KEY': self.api_key}
            
            response = await self._make_request(
                url=url,
                headers=headers
            )
            
            if response and response.get('status') == 200:
                return {
                    'accessible': True,
                    'details': {
                        'api_url': self.api_url,
                        'api_key_valid': True,
                        'test_domain': 'google.com',
                        'response_received': bool(response.get('data'))
                    }
                }
            else:
                return {
                    'accessible': False,
                    'error': f'API request failed with status: {response.get("status") if response else "No response"}'
                }
        
        except Exception as e:
            return {
                'accessible': False,
                'error': f'Failed to test OTX API: {str(e)}'
            }
    
    def get_rate_limit_info(self) -> Dict[str, Any]:
        """Get rate limit information for OTX API"""
        return {
            'requests_per_minute': 60,  # Based on OTX documentation
            'requests_per_hour': 1000,
            'requests_per_day': 10000,
            'burst_limit': 10,
            'notes': 'Rate limits may vary based on API key tier'
        }
    
    async def search_pulses(self, query: str, limit: int = 10) -> Dict[str, Any]:
        """Search OTX pulses for indicators related to query"""
        if not self.api_key:
            return {'error': 'API key required'}
        
        url = f"{self.api_url}/search/pulses"
        headers = {'X-OTX-API-KEY': self.api_key}
        params = {
            'q': query,
            'limit': limit
        }
        
        try:
            response = await self._make_request(
                url=url,
                headers=headers,
                params=params
            )
            
            if response and response.get('data'):
                search_data = response['data']
                
                return {
                    'query': query,
                    'results': search_data.get('results', []),
                    'count': search_data.get('count', 0)
                }
        
        except Exception as e:
            return {'query': query, 'error': str(e)}
    
    def is_api_key_required(self) -> bool:
        """Check if API key is required for this source"""
        return True
    
    def get_api_key_url(self) -> str:
        """Get URL to obtain API key"""
        return "https://otx.alienvault.com/api"


if __name__ == "__main__":
    # Test the OTX source
    import asyncio
    import sys
    
    async def test_otx():
        if len(sys.argv) < 2:
            print("Usage: python otx.py <domain>")
            print("Note: Set OTX_API_KEY environment variable or the source will be skipped")
            sys.exit(1)
        
        domain = sys.argv[1]
        
        # Test with API key from environment
        async with OTXSource() as otx:
            print(f"Testing OTX source for: {domain}")
            
            # Test connectivity
            connectivity = await otx.test_connectivity()
            print(f"Connectivity: {connectivity['accessible']} ({connectivity.get('response_time_ms')}ms)")
            
            if connectivity.get('error'):
                print(f"Error: {connectivity['error']}")
            
            if connectivity['accessible']:
                # Get subdomains
                subdomains = await otx.get_subdomains(domain)
                print(f"\nFound {len(subdomains)} subdomains:")
                
                for subdomain in sorted(subdomains)[:20]:  # Show first 20
                    print(f"  {subdomain}")
                
                if len(subdomains) > 20:
                    print(f"  ... and {len(subdomains) - 20} more")
                
                # Get domain reputation
                print(f"\nGetting domain reputation...")
                reputation = await otx.get_domain_reputation(domain)
                
                if 'reputation' in reputation:
                    pulse_count = reputation['reputation'].get('pulse_info', {}).get('count', 0)
                    print(f"Domain appears in {pulse_count} OTX pulses")
                
                # Search pulses
                print(f"\nSearching pulses for {domain}...")
                pulses = await otx.search_pulses(domain, limit=5)
                
                if 'results' in pulses:
                    print(f"Found {pulses['count']} related pulses")
                    for pulse in pulses['results'][:3]:  # Show first 3
                        name = pulse.get('name', 'Unknown')
                        author = pulse.get('author_name', 'Unknown')
                        print(f"  '{name}' by {author}")
            
            # Show rate limit info
            rate_limits = otx.get_rate_limit_info()
            print(f"\nRate limits: {rate_limits['requests_per_hour']} requests/hour")
    
    asyncio.run(test_otx())