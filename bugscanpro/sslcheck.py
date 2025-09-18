"""
SSL/TLS certificate checker for Bug Scan Pro
Handles SNI-based certificate inspection and analysis
Created by @lonefaisal - Made with ♥️ by @lonefaisal
"""

import asyncio
import ssl
import socket
import time
from typing import List, Dict, Any, Optional, Union
from datetime import datetime
import OpenSSL.crypto

from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn

from .utils import create_semaphore, is_valid_hostname
from .output import OutputManager

console = Console()


class SSLChecker:
    """SSL/TLS certificate inspection and analysis"""
    
    def __init__(
        self,
        threads: int = 50,
        timeout: int = 10,
        silent: bool = False,
        verify_hostname: bool = False
    ):
        self.threads = threads
        self.timeout = timeout
        self.silent = silent
        self.verify_hostname = verify_hostname
        
        self.semaphore = create_semaphore(threads)
        self.output_manager = OutputManager()
        
        # SSL context for certificate retrieval
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = verify_hostname
        self.ssl_context.verify_mode = ssl.CERT_NONE if not verify_hostname else ssl.CERT_REQUIRED
    
    async def get_certificate_info(
        self,
        hostname: str,
        port: int = 443,
        sni_hostname: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get SSL certificate information for a host"""
        async with self.semaphore:
            start_time = time.time()
            
            try:
                # Use SNI hostname if provided, otherwise use the hostname
                sni_name = sni_hostname or hostname
                
                # Create SSL connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                
                # Wrap socket with SSL
                ssl_sock = self.ssl_context.wrap_socket(
                    sock,
                    server_hostname=sni_name,
                    do_handshake_on_connect=False
                )
                
                # Connect and perform handshake
                ssl_sock.connect((hostname, port))
                ssl_sock.do_handshake()
                
                # Get certificate
                der_cert = ssl_sock.getpeercert_chain()[0] if ssl_sock.getpeercert_chain() else None
                cert_dict = ssl_sock.getpeercert()
                
                ssl_sock.close()
                
                if not cert_dict:
                    return {
                        'host': hostname,
                        'port': port,
                        'sni_hostname': sni_name,
                        'success': False,
                        'error': 'No certificate received',
                        'response_time': round((time.time() - start_time) * 1000, 2)
                    }
                
                # Parse certificate details
                cert_info = await self._parse_certificate(cert_dict, der_cert)
                cert_info.update({
                    'host': hostname,
                    'port': port,
                    'sni_hostname': sni_name,
                    'success': True,
                    'response_time': round((time.time() - start_time) * 1000, 2),
                    'timestamp': int(time.time())
                })
                
                return cert_info
                
            except ssl.SSLError as e:
                return {
                    'host': hostname,
                    'port': port,
                    'sni_hostname': sni_name or hostname,
                    'success': False,
                    'error': f'SSL Error: {str(e)}',
                    'response_time': round((time.time() - start_time) * 1000, 2),
                    'timestamp': int(time.time())
                }
            except socket.timeout:
                return {
                    'host': hostname,
                    'port': port,
                    'sni_hostname': sni_name or hostname,
                    'success': False,
                    'error': 'Connection timeout',
                    'response_time': round((time.time() - start_time) * 1000, 2),
                    'timestamp': int(time.time())
                }
            except Exception as e:
                return {
                    'host': hostname,
                    'port': port,
                    'sni_hostname': sni_name or hostname,
                    'success': False,
                    'error': str(e),
                    'response_time': round((time.time() - start_time) * 1000, 2),
                    'timestamp': int(time.time())
                }
    
    async def _parse_certificate(self, cert_dict: Dict, der_cert=None) -> Dict[str, Any]:
        """Parse certificate information from SSL certificate"""
        try:
            # Basic certificate info
            subject = dict(x[0] for x in cert_dict.get('subject', []))
            issuer = dict(x[0] for x in cert_dict.get('issuer', []))
            
            # Validity dates
            not_before = cert_dict.get('notBefore')
            not_after = cert_dict.get('notAfter')
            
            # Parse dates
            try:
                not_before_dt = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
                not_after_dt = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                
                # Check if certificate is expired or not yet valid
                now = datetime.utcnow()
                is_expired = now > not_after_dt
                is_not_yet_valid = now < not_before_dt
                days_until_expiry = (not_after_dt - now).days
                
            except Exception:
                not_before_dt = not_after_dt = None
                is_expired = is_not_yet_valid = None
                days_until_expiry = None
            
            # Subject Alternative Names (SANs)
            sans = []
            for san_type, san_value in cert_dict.get('subjectAltName', []):
                if san_type == 'DNS':
                    sans.append(san_value)
            
            # Certificate serial number
            serial_number = cert_dict.get('serialNumber')
            
            # Certificate version
            version = cert_dict.get('version', 'Unknown')
            
            # Additional info from DER certificate if available
            signature_algorithm = None
            key_size = None
            
            if der_cert:
                try:
                    # Parse with pyOpenSSL for more details
                    x509_cert = OpenSSL.crypto.load_certificate(
                        OpenSSL.crypto.FILETYPE_ASN1,
                        der_cert
                    )
                    
                    signature_algorithm = x509_cert.get_signature_algorithm().decode('utf-8')
                    
                    # Get public key info
                    pub_key = x509_cert.get_pubkey()
                    key_size = pub_key.bits()
                    
                except Exception:
                    pass
            
            cert_info = {
                'subject': subject,
                'issuer': issuer,
                'subject_common_name': subject.get('commonName'),
                'issuer_common_name': issuer.get('commonName'),
                'serial_number': serial_number,
                'version': version,
                'not_before': not_before,
                'not_after': not_after,
                'is_expired': is_expired,
                'is_not_yet_valid': is_not_yet_valid,
                'days_until_expiry': days_until_expiry,
                'subject_alt_names': sans,
                'san_count': len(sans),
                'signature_algorithm': signature_algorithm,
                'key_size': key_size
            }
            
            return cert_info
            
        except Exception as e:
            return {
                'parse_error': str(e),
                'raw_cert_dict': cert_dict
            }
    
    async def check_ssl_certificates(
        self,
        hosts: List[str],
        port: int = 443,
        sni_hostnames: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Check SSL certificates for multiple hosts"""
        if not hosts:
            return []
        
        if not self.silent:
            console.print(f"[blue]Checking SSL certificates for {len(hosts)} hosts on port {port}...[/blue]")
        
        # Prepare tasks
        tasks = []
        for i, host in enumerate(hosts):
            if is_valid_hostname(host):
                sni_hostname = None
                if sni_hostnames and i < len(sni_hostnames):
                    sni_hostname = sni_hostnames[i]
                
                tasks.append(self.get_certificate_info(host, port, sni_hostname))
        
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
                task = progress.add_task(f"SSL checking (port {port})", total=len(tasks))
                
                for coro in asyncio.as_completed(tasks):
                    result = await coro
                    results.append(result)
                    progress.advance(task)
        else:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            results = [r for r in results if isinstance(r, dict)]
        
        return results
    
    async def load_hosts_from_file(self, file_path: str) -> List[str]:
        """Load hosts from file"""
        hosts = []
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Remove protocol if present
                        if line.startswith(('http://', 'https://')):
                            from urllib.parse import urlparse
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
        """Save SSL certificate check results"""
        if not results:
            console.print("[yellow]No results to save[/yellow]")
            return
        
        # Save TXT format (hostname:port for successful checks)
        if txt_file:
            txt_results = []
            for r in results:
                if r.get('success', False):
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
                success = result.get('success', False)
                
                if success:
                    cn = result.get('subject_common_name', 'N/A')
                    issuer = result.get('issuer_common_name', 'N/A')
                    expires = result.get('not_after', 'N/A')
                    san_count = result.get('san_count', 0)
                    
                    console.print(f"[green]{host}:{port}[/green] - CN: {cn} | Issuer: {issuer} | SANs: {san_count} | Expires: {expires}")
                else:
                    error = result.get('error', 'Unknown error')
                    console.print(f"[red]{host}:{port}[/red] - Error: {error}")
    
    async def analyze_certificate_chain(
        self,
        hostname: str,
        port: int = 443
    ) -> Dict[str, Any]:
        """Analyze the full certificate chain"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            ssl_sock = self.ssl_context.wrap_socket(
                sock,
                server_hostname=hostname,
                do_handshake_on_connect=False
            )
            
            ssl_sock.connect((hostname, port))
            ssl_sock.do_handshake()
            
            # Get certificate chain
            cert_chain = ssl_sock.getpeercert_chain()
            
            if not cert_chain:
                return {
                    'host': hostname,
                    'port': port,
                    'success': False,
                    'error': 'No certificate chain received'
                }
            
            chain_info = {
                'host': hostname,
                'port': port,
                'success': True,
                'chain_length': len(cert_chain),
                'certificates': []
            }
            
            for i, cert_der in enumerate(cert_chain):
                try:
                    x509_cert = OpenSSL.crypto.load_certificate(
                        OpenSSL.crypto.FILETYPE_ASN1,
                        cert_der
                    )
                    
                    subject = x509_cert.get_subject()
                    issuer = x509_cert.get_issuer()
                    
                    cert_info = {
                        'position': i,
                        'subject_cn': subject.commonName if hasattr(subject, 'commonName') else None,
                        'issuer_cn': issuer.commonName if hasattr(issuer, 'commonName') else None,
                        'serial_number': str(x509_cert.get_serial_number()),
                        'signature_algorithm': x509_cert.get_signature_algorithm().decode('utf-8'),
                        'key_size': x509_cert.get_pubkey().bits(),
                        'not_before': x509_cert.get_notBefore().decode('utf-8'),
                        'not_after': x509_cert.get_notAfter().decode('utf-8')
                    }
                    
                    chain_info['certificates'].append(cert_info)
                    
                except Exception as e:
                    chain_info['certificates'].append({
                        'position': i,
                        'error': str(e)
                    })
            
            ssl_sock.close()
            return chain_info
            
        except Exception as e:
            return {
                'host': hostname,
                'port': port,
                'success': False,
                'error': str(e)
            }


if __name__ == "__main__":
    # Test the SSL checker
    import sys
    
    async def test_ssl_checker():
        if len(sys.argv) < 2:
            print("Usage: python sslcheck.py <hostname> [port]")
            sys.exit(1)
        
        hostname = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
        
        checker = SSLChecker(timeout=10)
        
        print(f"Testing SSL certificate for: {hostname}:{port}")
        
        result = await checker.get_certificate_info(hostname, port)
        
        if result.get('success'):
            print(f"Certificate found:")
            print(f"  Subject CN: {result.get('subject_common_name')}")
            print(f"  Issuer: {result.get('issuer_common_name')}")
            print(f"  Expires: {result.get('not_after')}")
            print(f"  SANs: {len(result.get('subject_alt_names', []))}")
            print(f"  Is Expired: {result.get('is_expired')}")
        else:
            print(f"Error: {result.get('error')}")
        
        # Test certificate chain analysis
        print(f"\nAnalyzing certificate chain...")
        chain_result = await checker.analyze_certificate_chain(hostname, port)
        
        if chain_result.get('success'):
            print(f"Chain length: {chain_result.get('chain_length')}")
            for cert in chain_result.get('certificates', []):
                pos = cert.get('position')
                cn = cert.get('subject_cn', 'Unknown')
                print(f"  {pos}: {cn}")
    
    asyncio.run(test_ssl_checker())