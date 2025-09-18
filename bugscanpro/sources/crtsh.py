"""
Certificate Transparency (crt.sh) source for subdomain discovery
Created by @lonefaisal - Made with ♥️ by @lonefaisal
"""

import json
from typing import Set, Dict, Any
from urllib.parse import quote

from rich.console import Console

from .base import BaseSource

console = Console()


class CrtShSource(BaseSource):
    """Certificate Transparency subdomain discovery via crt.sh"""
    
    def __init__(self, timeout: int = 30):
        super().__init__(
            name="crt.sh",
            timeout=timeout,
            max_retries=3,
            user_agent="bug-scan-pro/1.0"
        )
        self.base_url = "https://crt.sh"
        self.api_url = f"{self.base_url}/"
    
    async def get_subdomains(self, domain: str) -> Set[str]:
        """Get subdomains from Certificate Transparency logs via crt.sh"""
        subdomains = set()
        
        # Method 1: JSON API
        json_subdomains = await self._get_subdomains_json_api(domain)
        subdomains.update(json_subdomains)
        
        # Method 2: Search with wildcards
        wildcard_subdomains = await self._get_subdomains_wildcard(domain)
        subdomains.update(wildcard_subdomains)
        
        return subdomains
    
    async def _get_subdomains_json_api(self, domain: str) -> Set[str]:
        """Get subdomains using crt.sh JSON API"""
        subdomains = set()
        
        # Query for the domain and its subdomains
        params = {
            'q': f'%.{domain}',
            'output': 'json'
        }
        
        try:
            response = await self._make_request(
                url=self.api_url,
                params=params
            )
            
            if response and response.get('data'):
                certificates = response['data']
                
                for cert in certificates:
                    # Extract from name_value field
                    name_value = cert.get('name_value', '')
                    if name_value:
                        # name_value can contain multiple names separated by newlines
                        names = name_value.split('\n')
                        for name in names:
                            name = name.strip()
                            if name and domain in name:
                                cleaned = self.clean_subdomain(name, domain)
                                if cleaned:
                                    subdomains.add(cleaned)
                    
                    # Also check common_name
                    common_name = cert.get('common_name')
                    if common_name and domain in common_name:
                        cleaned = self.clean_subdomain(common_name, domain)
                        if cleaned:
                            subdomains.add(cleaned)
            
        except Exception as e:
            console.print(f"[red]Error querying crt.sh JSON API: {e}[/red]")
        
        return subdomains
    
    async def _get_subdomains_wildcard(self, domain: str) -> Set[str]:
        """Get subdomains using wildcard search"""
        subdomains = set()
        
        # Query for wildcard certificates
        params = {
            'q': f'*.{domain}',
            'output': 'json'
        }
        
        try:
            response = await self._make_request(
                url=self.api_url,
                params=params
            )
            
            if response and response.get('data'):
                certificates = response['data']
                
                for cert in certificates:
                    name_value = cert.get('name_value', '')
                    if name_value:
                        names = name_value.split('\n')
                        for name in names:
                            name = name.strip()
                            if name and domain in name:
                                # Remove wildcard prefix if present
                                if name.startswith('*.'):
                                    name = name[2:]
                                
                                cleaned = self.clean_subdomain(name, domain)
                                if cleaned:
                                    subdomains.add(cleaned)
        
        except Exception as e:
            console.print(f"[red]Error querying crt.sh wildcard: {e}[/red]")
        
        return subdomains
    
    async def get_certificate_details(
        self,
        domain: str,
        limit: int = 100
    ) -> Dict[str, Any]:
        """Get detailed certificate information for a domain"""
        params = {
            'q': domain,
            'output': 'json'
        }
        
        try:
            response = await self._make_request(
                url=self.api_url,
                params=params
            )
            
            if response and response.get('data'):
                certificates = response['data'][:limit]  # Limit results
                
                # Process certificate data
                processed_certs = []
                for cert in certificates:
                    processed_cert = {
                        'id': cert.get('id'),
                        'logged_at': cert.get('entry_timestamp'),
                        'not_before': cert.get('not_before'),
                        'not_after': cert.get('not_after'),
                        'common_name': cert.get('common_name'),
                        'issuer_name': cert.get('issuer_name'),
                        'name_value': cert.get('name_value'),
                        'serial_number': cert.get('serial_number')
                    }
                    processed_certs.append(processed_cert)
                
                return {
                    'domain': domain,
                    'total_certificates': len(certificates),
                    'certificates': processed_certs,
                    'unique_subdomains': len(await self.get_subdomains(domain))
                }
            
        except Exception as e:
            console.print(f"[red]Error getting certificate details: {e}[/red]")
        
        return {'domain': domain, 'error': 'Failed to retrieve certificate details'}
    
    async def _test_source_specific(self) -> Dict[str, Any]:
        """Test crt.sh connectivity"""
        try:
            # Test with a known domain
            test_domain = "google.com"
            params = {
                'q': test_domain,
                'output': 'json'
            }
            
            response = await self._make_request(
                url=self.api_url,
                params=params
            )
            
            if response and response.get('status') == 200:
                return {
                    'accessible': True,
                    'details': {
                        'api_url': self.api_url,
                        'test_domain': test_domain,
                        'response_received': bool(response.get('data'))
                    }
                }
            else:
                return {
                    'accessible': False,
                    'error': 'No valid response received'
                }
        
        except Exception as e:
            return {
                'accessible': False,
                'error': str(e)
            }
    
    def get_rate_limit_info(self) -> Dict[str, Any]:
        """Get rate limit information for crt.sh"""
        return {
            'requests_per_minute': None,  # No official limit documented
            'requests_per_hour': None,
            'requests_per_day': None,
            'burst_limit': None,
            'notes': 'crt.sh does not publish official rate limits, use responsibly'
        }
    
    async def search_by_organization(self, org_name: str) -> Set[str]:
        """Search certificates by organization name"""
        subdomains = set()
        
        params = {
            'o': org_name,
            'output': 'json'
        }
        
        try:
            response = await self._make_request(
                url=self.api_url,
                params=params
            )
            
            if response and response.get('data'):
                certificates = response['data']
                
                for cert in certificates:
                    name_value = cert.get('name_value', '')
                    if name_value:
                        names = name_value.split('\n')
                        for name in names:
                            name = name.strip()
                            if name and '.' in name:
                                # Extract domain from the name
                                parts = name.split('.')
                                if len(parts) >= 2:
                                    domain = '.'.join(parts[-2:])
                                    cleaned = self.clean_subdomain(name, domain)
                                    if cleaned:
                                        subdomains.add(cleaned)
        
        except Exception as e:
            console.print(f"[red]Error searching by organization: {e}[/red]")
        
        return subdomains


if __name__ == "__main__":
    # Test the crt.sh source
    import asyncio
    import sys
    
    async def test_crtsh():
        if len(sys.argv) < 2:
            print("Usage: python crtsh.py <domain>")
            sys.exit(1)
        
        domain = sys.argv[1]
        
        async with CrtShSource() as crtsh:
            print(f"Testing crt.sh source for: {domain}")
            
            # Test connectivity
            connectivity = await crtsh.test_connectivity()
            print(f"Connectivity: {connectivity['accessible']} ({connectivity.get('response_time_ms')}ms)")
            
            if connectivity['accessible']:
                # Get subdomains
                subdomains = await crtsh.get_subdomains(domain)
                print(f"\nFound {len(subdomains)} subdomains:")
                
                for subdomain in sorted(subdomains)[:20]:  # Show first 20
                    print(f"  {subdomain}")
                
                if len(subdomains) > 20:
                    print(f"  ... and {len(subdomains) - 20} more")
                
                # Get certificate details
                print(f"\nGetting certificate details...")
                cert_details = await crtsh.get_certificate_details(domain, limit=5)
                
                if 'certificates' in cert_details:
                    print(f"Found {cert_details['total_certificates']} certificates")
                    for cert in cert_details['certificates'][:3]:  # Show first 3
                        cn = cert.get('common_name', 'N/A')
                        issuer = cert.get('issuer_name', 'N/A')[:50]
                        print(f"  CN: {cn} | Issuer: {issuer}")
    
    asyncio.run(test_crtsh())