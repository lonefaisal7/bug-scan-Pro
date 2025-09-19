"""
Advanced configuration system for Bug Scan Pro
Secure configuration management with encryption support
Created by @lonefaisal - Made with ♥️ by @lonefaisal
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from rich.console import Console

console = Console()


@dataclass
class ScanConfig:
    """Main scanning configuration"""
    max_concurrent: int = 1000
    timeout: int = 10
    retries: int = 2
    user_agent: str = "bug-scan-pro/1.0 - Made with ♥️ by @lonefaisal"
    stealth_profile: str = "polite"  # paranoid, sneaky, polite, aggressive
    ai_enabled: bool = True
    verify_ssl: bool = False
    follow_redirects: bool = True
    
    # DNS settings
    dns_servers: List[str] = None
    dns_timeout: int = 5
    
    # Proxy settings
    proxy_enabled: bool = False
    proxy_rotation: bool = True
    proxy_health_check: bool = True
    
    # Output settings
    default_output_format: str = "txt"
    include_metadata: bool = True
    compress_output: bool = False
    
    def __post_init__(self):
        if self.dns_servers is None:
            self.dns_servers = ['1.1.1.1', '8.8.8.8', '1.0.0.1', '8.8.4.4']


@dataclass
class PluginConfig:
    """Plugin system configuration"""
    plugins_enabled: bool = True
    plugins_directory: str = "plugins"
    auto_load_plugins: bool = True
    plugin_timeout: int = 30


@dataclass
class SecurityConfig:
    """Security and stealth configuration"""
    stealth_mode: bool = False
    randomize_user_agents: bool = True
    decoy_traffic: bool = False
    timing_randomization: bool = True
    
    # Rate limiting
    rate_limit_enabled: bool = True
    max_requests_per_second: int = 100
    burst_limit: int = 10
    
    # Circuit breaker
    circuit_breaker_enabled: bool = True
    failure_threshold: int = 5
    circuit_timeout: int = 60


class SecureConfigManager:
    """Secure configuration manager with encryption"""
    
    def __init__(self, config_dir: str = "~/.bugscanpro"):
        self.config_dir = Path(config_dir).expanduser()
        self.config_dir.mkdir(exist_ok=True)
        
        self.config_file = self.config_dir / "config.json"
        self.encrypted_config_file = self.config_dir / "secure_config.enc"
        self.key_file = self.config_dir / ".key"
        
        # Configuration objects
        self.scan_config = ScanConfig()
        self.plugin_config = PluginConfig()
        self.security_config = SecurityConfig()
        
        # Encryption key
        self._cipher = None
    
    def _get_or_create_key(self) -> bytes:
        """Get or create encryption key"""
        if self.key_file.exists():
            with open(self.key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            # Set restrictive permissions
            self.key_file.chmod(0o600)
            return key
    
    def _get_cipher(self) -> Fernet:
        """Get Fernet cipher for encryption"""
        if not self._cipher:
            key = self._get_or_create_key()
            self._cipher = Fernet(key)
        return self._cipher
    
    def encrypt_sensitive_data(self, data: str) -> str:
        """Encrypt sensitive configuration data"""
        cipher = self._get_cipher()
        encrypted = cipher.encrypt(data.encode())
        return base64.b64encode(encrypted).decode()
    
    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive configuration data"""
        cipher = self._get_cipher()
        encrypted_bytes = base64.b64decode(encrypted_data.encode())
        decrypted = cipher.decrypt(encrypted_bytes)
        return decrypted.decode()
    
    async def load_config(self) -> None:
        """Load configuration from file"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    config_data = json.load(f)
                
                # Load scan config
                if 'scan' in config_data:
                    scan_data = config_data['scan']
                    self.scan_config = ScanConfig(**scan_data)
                
                # Load plugin config
                if 'plugins' in config_data:
                    plugin_data = config_data['plugins']
                    self.plugin_config = PluginConfig(**plugin_data)
                
                # Load security config
                if 'security' in config_data:
                    security_data = config_data['security']
                    self.security_config = SecurityConfig(**security_data)
                
                console.print("[green]✅ Configuration loaded successfully[/green]")
            
            # Load encrypted sensitive data
            if self.encrypted_config_file.exists():
                await self._load_encrypted_config()
                
        except Exception as e:
            console.print(f"[yellow]⚠️ Using default config due to error: {e}[/yellow]")
    
    async def _load_encrypted_config(self) -> None:
        """Load encrypted configuration data"""
        try:
            with open(self.encrypted_config_file, 'r') as f:
                encrypted_data = json.load(f)
            
            # Decrypt sensitive configuration
            for key, value in encrypted_data.items():
                decrypted_value = self.decrypt_sensitive_data(value)
                
                # Store decrypted values as environment variables
                os.environ[f"BUGSCANPRO_{key.upper()}"] = decrypted_value
            
            console.print("[green]🔒 Encrypted configuration loaded[/green]")
            
        except Exception as e:
            console.print(f"[red]❌ Error loading encrypted config: {e}[/red]")
    
    async def save_config(self) -> None:
        """Save current configuration to file"""
        try:
            config_data = {
                'scan': asdict(self.scan_config),
                'plugins': asdict(self.plugin_config),
                'security': asdict(self.security_config),
                'metadata': {
                    'version': '1.0.0',
                    'created_by': '@lonefaisal',
                    'last_updated': time.time()
                }
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            console.print(f"[green]✅ Configuration saved to {self.config_file}[/green]")
            
        except Exception as e:
            console.print(f"[red]❌ Error saving config: {e}[/red]")
    
    def store_sensitive_data(self, key: str, value: str) -> None:
        """Store sensitive data with encryption"""
        try:
            encrypted_value = self.encrypt_sensitive_data(value)
            
            # Load existing encrypted data
            encrypted_config = {}
            if self.encrypted_config_file.exists():
                with open(self.encrypted_config_file, 'r') as f:
                    encrypted_config = json.load(f)
            
            # Add new encrypted value
            encrypted_config[key] = encrypted_value
            
            # Save updated encrypted config
            with open(self.encrypted_config_file, 'w') as f:
                json.dump(encrypted_config, f)
            
            # Set restrictive permissions
            self.encrypted_config_file.chmod(0o600)
            
            console.print(f"[green]🔒 Sensitive data '{key}' encrypted and stored[/green]")
            
        except Exception as e:
            console.print(f"[red]❌ Error storing sensitive data: {e}[/red]")
    
    def get_sensitive_data(self, key: str) -> Optional[str]:
        """Retrieve sensitive data with decryption"""
        try:
            if not self.encrypted_config_file.exists():
                return None
            
            with open(self.encrypted_config_file, 'r') as f:
                encrypted_config = json.load(f)
            
            if key in encrypted_config:
                return self.decrypt_sensitive_data(encrypted_config[key])
            
            return None
            
        except Exception as e:
            console.print(f"[red]❌ Error retrieving sensitive data: {e}[/red]")
            return None
    
    def get_full_config(self) -> Dict[str, Any]:
        """Get complete configuration dictionary"""
        return {
            'scan': asdict(self.scan_config),
            'plugins': asdict(self.plugin_config),
            'security': asdict(self.security_config)
        }
    
    def update_config(self, config_updates: Dict[str, Any]) -> None:
        """Update configuration with new values"""
        if 'scan' in config_updates:
            scan_updates = config_updates['scan']
            for key, value in scan_updates.items():
                if hasattr(self.scan_config, key):
                    setattr(self.scan_config, key, value)
        
        if 'plugins' in config_updates:
            plugin_updates = config_updates['plugins']
            for key, value in plugin_updates.items():
                if hasattr(self.plugin_config, key):
                    setattr(self.plugin_config, key, value)
        
        if 'security' in config_updates:
            security_updates = config_updates['security']
            for key, value in security_updates.items():
                if hasattr(self.security_config, key):
                    setattr(self.security_config, key, value)
    
    def reset_to_defaults(self) -> None:
        """Reset configuration to default values"""
        self.scan_config = ScanConfig()
        self.plugin_config = PluginConfig()
        self.security_config = SecurityConfig()
        
        console.print("[yellow]🔄 Configuration reset to defaults[/yellow]")
    
    def validate_config(self) -> List[str]:
        """Validate current configuration"""
        issues = []
        
        # Validate scan config
        if self.scan_config.max_concurrent < 1 or self.scan_config.max_concurrent > 10000:
            issues.append("max_concurrent must be between 1 and 10000")
        
        if self.scan_config.timeout < 1 or self.scan_config.timeout > 300:
            issues.append("timeout must be between 1 and 300 seconds")
        
        # Validate security config
        if self.security_config.max_requests_per_second < 1:
            issues.append("max_requests_per_second must be at least 1")
        
        # Validate plugin config
        if self.plugin_config.plugins_directory:
            plugins_path = Path(self.plugin_config.plugins_directory)
            if not plugins_path.exists():
                issues.append(f"plugins_directory does not exist: {plugins_path}")
        
        return issues


if __name__ == "__main__":
    # Test the configuration system
    import asyncio
    import time
    
    async def test_config_system():
        # Create config manager
        config = SecureConfigManager()
        
        # Load existing config
        await config.load_config()
        
        print(f"Current scan config: {config.scan_config}")
        
        # Test sensitive data storage
        config.store_sensitive_data('otx_api_key', 'test-api-key-12345')
        config.store_sensitive_data('proxy_auth', 'user:password')
        
        # Test retrieval
        otx_key = config.get_sensitive_data('otx_api_key')
        print(f"Retrieved OTX key: {otx_key}")
        
        # Test config updates
        config.update_config({
            'scan': {'max_concurrent': 500, 'timeout': 15},
            'security': {'stealth_mode': True}
        })
        
        # Validate configuration
        issues = config.validate_config()
        if issues:
            print(f"Configuration issues: {issues}")
        else:
            print("Configuration is valid")
        
        # Save updated config
        await config.save_config()
        
        # Get full config
        full_config = config.get_full_config()
        print(f"Full configuration keys: {list(full_config.keys())}")
    
    asyncio.run(test_config_system())