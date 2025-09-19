"""
Plugin architecture system for Bug Scan Pro
Enables dynamic extension and customization
Created by @lonefaisal - Made with ♥️ by @lonefaisal
"""

import asyncio
import importlib
import inspect
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Callable, Type
from pathlib import Path
import logging
from collections import defaultdict

from rich.console import Console

console = Console()
logger = logging.getLogger(__name__)


class BasePlugin(ABC):
    """Base class for all plugins"""
    
    def __init__(self, name: str, version: str = "1.0.0"):
        self.name = name
        self.version = version
        self.enabled = True
        self.config = {}
    
    @abstractmethod
    def get_hooks(self) -> List[str]:
        """Return list of hook names this plugin handles"""
        pass
    
    @abstractmethod
    async def execute_hook(self, hook_name: str, *args, **kwargs) -> Any:
        """Execute plugin logic for specified hook"""
        pass
    
    def get_metadata(self) -> Dict[str, Any]:
        """Get plugin metadata"""
        return {
            'name': self.name,
            'version': self.version,
            'enabled': self.enabled,
            'hooks': self.get_hooks(),
            'config': self.config
        }
    
    async def initialize(self, config: Dict[str, Any] = None) -> None:
        """Initialize plugin with configuration"""
        if config:
            self.config.update(config)
    
    async def cleanup(self) -> None:
        """Cleanup plugin resources"""
        pass
    
    def __str__(self) -> str:
        return f"{self.name} v{self.version}"


class PluginManager:
    """Dynamic plugin system manager"""
    
    def __init__(self, plugins_directory: Optional[str] = None):
        self.plugins: Dict[str, BasePlugin] = {}
        self.hooks: Dict[str, List[BasePlugin]] = defaultdict(list)
        self.plugins_directory = Path(plugins_directory) if plugins_directory else None
        
        # Built-in hooks
        self.available_hooks = {
            'pre_scan': 'Called before scanning starts',
            'post_scan': 'Called after scanning completes',
            'target_discovered': 'Called when new target is discovered',
            'result_processing': 'Called to process scan results',
            'output_formatting': 'Called to format output',
            'vulnerability_detected': 'Called when vulnerability is found',
            'anomaly_detected': 'Called when anomaly is detected',
            'scan_progress': 'Called during scan progress updates'
        }
    
    def register_plugin(self, plugin: BasePlugin) -> None:
        """Register a plugin"""
        try:
            # Initialize plugin
            asyncio.create_task(plugin.initialize())
            
            self.plugins[plugin.name] = plugin
            
            # Register hooks
            for hook_name in plugin.get_hooks():
                if hook_name in self.available_hooks:
                    self.hooks[hook_name].append(plugin)
                    logger.info(f"Registered plugin {plugin.name} for hook {hook_name}")
                else:
                    logger.warning(f"Unknown hook {hook_name} in plugin {plugin.name}")
            
            console.print(f"[green]✅ Registered plugin: {plugin}[/green]")
            
        except Exception as e:
            console.print(f"[red]❌ Failed to register plugin {plugin.name}: {e}[/red]")
    
    def unregister_plugin(self, plugin_name: str) -> None:
        """Unregister a plugin"""
        if plugin_name in self.plugins:
            plugin = self.plugins[plugin_name]
            
            # Remove from hooks
            for hook_name in plugin.get_hooks():
                if hook_name in self.hooks:
                    self.hooks[hook_name] = [
                        p for p in self.hooks[hook_name] 
                        if p.name != plugin_name
                    ]
            
            # Cleanup plugin
            asyncio.create_task(plugin.cleanup())
            
            del self.plugins[plugin_name]
            console.print(f"[yellow]🗑️ Unregistered plugin: {plugin_name}[/yellow]")
    
    async def execute_hook(
        self,
        hook_name: str,
        *args,
        **kwargs
    ) -> List[Any]:
        """Execute all plugins registered for a hook"""
        if hook_name not in self.hooks:
            return []
        
        results = []
        
        for plugin in self.hooks[hook_name]:
            if not plugin.enabled:
                continue
            
            try:
                result = await plugin.execute_hook(hook_name, *args, **kwargs)
                results.append({
                    'plugin': plugin.name,
                    'result': result,
                    'success': True
                })
                
            except Exception as e:
                logger.error(f"Plugin {plugin.name} failed on hook {hook_name}: {e}")
                results.append({
                    'plugin': plugin.name,
                    'error': str(e),
                    'success': False
                })
        
        return results
    
    async def load_plugins_from_directory(self, directory: str) -> None:
        """Load plugins from directory"""
        plugins_path = Path(directory)
        if not plugins_path.exists():
            console.print(f"[yellow]⚠️ Plugins directory not found: {directory}[/yellow]")
            return
        
        python_files = plugins_path.glob('*.py')
        
        for plugin_file in python_files:
            if plugin_file.name.startswith('_'):
                continue
            
            try:
                await self._load_plugin_from_file(plugin_file)
            except Exception as e:
                console.print(f"[red]❌ Failed to load plugin {plugin_file.name}: {e}[/red]")
    
    async def _load_plugin_from_file(self, plugin_file: Path) -> None:
        """Load a single plugin from file"""
        # Import plugin module
        spec = importlib.util.spec_from_file_location(
            plugin_file.stem, plugin_file
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        # Find plugin classes
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if (issubclass(obj, BasePlugin) and 
                obj != BasePlugin and 
                not obj.__name__.startswith('_')):
                
                # Instantiate and register plugin
                plugin_instance = obj()
                self.register_plugin(plugin_instance)
    
    def list_plugins(self) -> Dict[str, Dict[str, Any]]:
        """List all registered plugins"""
        return {
            name: plugin.get_metadata() 
            for name, plugin in self.plugins.items()
        }
    
    def get_hook_info(self) -> Dict[str, Any]:
        """Get information about available hooks"""
        hook_info = {}
        
        for hook_name, description in self.available_hooks.items():
            plugins = [p.name for p in self.hooks.get(hook_name, [])]
            hook_info[hook_name] = {
                'description': description,
                'registered_plugins': plugins,
                'plugin_count': len(plugins)
            }
        
        return hook_info
    
    async def enable_plugin(self, plugin_name: str) -> None:
        """Enable a plugin"""
        if plugin_name in self.plugins:
            self.plugins[plugin_name].enabled = True
            console.print(f"[green]✅ Enabled plugin: {plugin_name}[/green]")
    
    async def disable_plugin(self, plugin_name: str) -> None:
        """Disable a plugin"""
        if plugin_name in self.plugins:
            self.plugins[plugin_name].enabled = False
            console.print(f"[yellow]⏸️ Disabled plugin: {plugin_name}[/yellow]")


# Example plugins for demonstration
class VulnerabilityDetectorPlugin(BasePlugin):
    """Example plugin for vulnerability detection"""
    
    def __init__(self):
        super().__init__("VulnerabilityDetector", "1.0.0")
        self.vulnerability_patterns = {
            'admin_panel': ['admin', 'administrator', 'panel', 'control'],
            'backup_files': ['backup', 'bak', 'old', 'temp'],
            'dev_environment': ['dev', 'test', 'staging', 'beta']
        }
    
    def get_hooks(self) -> List[str]:
        return ['result_processing', 'vulnerability_detected']
    
    async def execute_hook(self, hook_name: str, *args, **kwargs) -> Any:
        if hook_name == 'result_processing':
            return await self._analyze_for_vulnerabilities(*args, **kwargs)
        elif hook_name == 'vulnerability_detected':
            return await self._handle_vulnerability_detection(*args, **kwargs)
    
    async def _analyze_for_vulnerabilities(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze results for potential vulnerabilities"""
        vulnerabilities = []
        
        for result in results:
            hostname = result.get('host', '')
            
            for vuln_type, patterns in self.vulnerability_patterns.items():
                if any(pattern in hostname.lower() for pattern in patterns):
                    vulnerabilities.append({
                        'type': vuln_type,
                        'target': hostname,
                        'confidence': 0.7,
                        'description': f'Potential {vuln_type.replace("_", " ")} detected'
                    })
        
        return vulnerabilities


class MetricsCollectorPlugin(BasePlugin):
    """Plugin for collecting advanced metrics"""
    
    def __init__(self):
        super().__init__("MetricsCollector", "1.0.0")
        self.metrics_data = []
    
    def get_hooks(self) -> List[str]:
        return ['scan_progress', 'post_scan']
    
    async def execute_hook(self, hook_name: str, *args, **kwargs) -> Any:
        if hook_name == 'scan_progress':
            return await self._collect_progress_metrics(*args, **kwargs)
        elif hook_name == 'post_scan':
            return await self._generate_final_report(*args, **kwargs)
    
    async def _collect_progress_metrics(self, progress_data: Dict[str, Any]) -> None:
        """Collect metrics during scan progress"""
        self.metrics_data.append({
            'timestamp': time.time(),
            'completed': progress_data.get('completed', 0),
            'total': progress_data.get('total', 0),
            'rps': progress_data.get('rps', 0)
        })
    
    async def _generate_final_report(self, scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive metrics report"""
        if not self.metrics_data:
            return {}
        
        max_rps = max(m['rps'] for m in self.metrics_data if m['rps'] > 0)
        avg_rps = sum(m['rps'] for m in self.metrics_data) / len(self.metrics_data)
        
        return {
            'scan_duration': self.metrics_data[-1]['timestamp'] - self.metrics_data[0]['timestamp'],
            'peak_rps': max_rps,
            'average_rps': avg_rps,
            'total_targets': len(scan_results),
            'success_rate': len([r for r in scan_results if r.get('success', False)]) / len(scan_results) * 100
        }


class ExportEnhancerPlugin(BasePlugin):
    """Plugin to enhance output with additional formats"""
    
    def __init__(self):
        super().__init__("ExportEnhancer", "1.0.0")
    
    def get_hooks(self) -> List[str]:
        return ['output_formatting']
    
    async def execute_hook(self, hook_name: str, *args, **kwargs) -> Any:
        if hook_name == 'output_formatting':
            return await self._enhance_output(*args, **kwargs)
    
    async def _enhance_output(self, results: List[Dict[str, Any]], format_type: str) -> Any:
        """Enhance output with additional formats"""
        if format_type == 'excel':
            return await self._export_to_excel(results)
        elif format_type == 'html':
            return await self._export_to_html(results)
        elif format_type == 'pdf':
            return await self._export_to_pdf(results)
        
        return results
    
    async def _export_to_excel(self, results: List[Dict[str, Any]]) -> str:
        """Export results to Excel format"""
        try:
            import pandas as pd
            
            df = pd.DataFrame(results)
            filename = f"scan_results_{int(time.time())}.xlsx"
            df.to_excel(filename, index=False)
            
            return filename
        except ImportError:
            console.print("[yellow]⚠️ Excel export requires pandas and openpyxl[/yellow]")
            return None
    
    async def _export_to_html(self, results: List[Dict[str, Any]]) -> str:
        """Export results to HTML format"""
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Bug Scan Pro Results</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                .success { color: green; }
                .error { color: red; }
            </style>
        </head>
        <body>
            <h1>🔍 Bug Scan Pro Results</h1>
            <p><strong>Generated:</strong> {timestamp}</p>
            <p><strong>Total Results:</strong> {total}</p>
            <p><strong>Made with ❤️ by @lonefaisal</strong></p>
            
            <table>
                <thead>
                    <tr>
                        <th>Target</th>
                        <th>Status</th>
                        <th>Response Time</th>
                        <th>Additional Info</th>
                    </tr>
                </thead>
                <tbody>
        """.format(
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
            total=len(results)
        )
        
        for result in results:
            target = result.get('target', result.get('host', 'Unknown'))
            success = result.get('success', False)
            status_class = 'success' if success else 'error'
            status_text = 'SUCCESS' if success else 'FAILED'
            response_time = result.get('response_time', 0)
            
            additional_info = []
            if result.get('status_code'):
                additional_info.append(f"Status: {result['status_code']}")
            if result.get('server'):
                additional_info.append(f"Server: {result['server']}")
            
            html_content += f"""
                    <tr>
                        <td>{target}</td>
                        <td class="{status_class}">{status_text}</td>
                        <td>{response_time:.2f}ms</td>
                        <td>{'; '.join(additional_info)}</td>
                    </tr>
            """
        
        html_content += """
                </tbody>
            </table>
        </body>
        </html>
        """
        
        filename = f"scan_results_{int(time.time())}.html"
        with open(filename, 'w') as f:
            f.write(html_content)
        
        return filename


if __name__ == "__main__":
    # Test the plugin system
    async def test_plugin_system():
        # Create plugin manager
        manager = PluginManager()
        
        # Register example plugins
        vuln_plugin = VulnerabilityDetectorPlugin()
        metrics_plugin = MetricsCollectorPlugin()
        export_plugin = ExportEnhancerPlugin()
        
        manager.register_plugin(vuln_plugin)
        manager.register_plugin(metrics_plugin)
        manager.register_plugin(export_plugin)
        
        # List registered plugins
        plugins = manager.list_plugins()
        console.print(f"[blue]Registered plugins: {list(plugins.keys())}[/blue]")
        
        # Test hook execution
        sample_results = [
            {'host': 'admin.example.com', 'success': True, 'status_code': 200},
            {'host': 'api.example.com', 'success': True, 'status_code': 200},
            {'host': 'dev.example.com', 'success': False, 'error': 'Timeout'}
        ]
        
        # Execute vulnerability detection
        vuln_results = await manager.execute_hook('result_processing', sample_results)
        console.print(f"[green]Vulnerability detection results: {vuln_results}[/green]")
        
        # Generate metrics report
        metrics_results = await manager.execute_hook('post_scan', sample_results)
        console.print(f"[blue]Metrics report: {metrics_results}[/blue]")
        
        # Test export enhancement
        export_results = await manager.execute_hook('output_formatting', sample_results, 'html')
        console.print(f"[cyan]Export results: {export_results}[/cyan]")
        
        # Show hook information
        hook_info = manager.get_hook_info()
        console.print(f"[magenta]Available hooks: {list(hook_info.keys())}[/magenta]")
    
    asyncio.run(test_plugin_system())