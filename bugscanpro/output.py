"""
Output manager for Bug Scan Pro
Handles various output formats (TXT, JSON, CSV) with append support
Created by @lonefaisal - Made with ♥️ by @lonefaisal
"""

import json
import csv
import asyncio
from typing import List, Dict, Any, Optional
from pathlib import Path
import time

from rich.console import Console

console = Console()


class OutputManager:
    """Manages output to different file formats"""
    
    def __init__(self):
        pass
    
    async def save_txt(
        self,
        results: List[Dict[str, Any]],
        filename: str,
        append: bool = False,
        field: str = 'host'
    ) -> None:
        """Save results to TXT format (one entry per line)"""
        if not results:
            return
        
        mode = 'a' if append else 'w'
        
        try:
            with open(filename, mode, encoding='utf-8') as f:
                for result in results:
                    if isinstance(result, dict):
                        value = result.get(field, str(result))
                        if value:
                            f.write(f"{value}\n")
                    else:
                        f.write(f"{result}\n")
        except Exception as e:
            console.print(f"[red]Error saving TXT file {filename}: {e}[/red]")
            raise
    
    async def save_json(
        self,
        results: List[Dict[str, Any]],
        filename: str,
        append: bool = False,
        indent: int = 2
    ) -> None:
        """Save results to JSON format"""
        if not results:
            return
        
        try:
            if append and Path(filename).exists():
                # Load existing data
                with open(filename, 'r', encoding='utf-8') as f:
                    try:
                        existing_data = json.load(f)
                        if not isinstance(existing_data, list):
                            existing_data = [existing_data]
                    except json.JSONDecodeError:
                        existing_data = []
                
                # Combine with new results
                combined_results = existing_data + results
            else:
                combined_results = results
            
            # Save combined data
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(combined_results, f, indent=indent, ensure_ascii=False, default=str)
                
        except Exception as e:
            console.print(f"[red]Error saving JSON file {filename}: {e}[/red]")
            raise
    
    async def save_csv(
        self,
        results: List[Dict[str, Any]],
        filename: str,
        append: bool = False,
        fieldnames: Optional[List[str]] = None
    ) -> None:
        """Save results to CSV format"""
        if not results:
            return
        
        try:
            # Determine fieldnames from data if not provided
            if not fieldnames:
                all_keys = set()
                for result in results:
                    if isinstance(result, dict):
                        all_keys.update(result.keys())
                fieldnames = sorted(list(all_keys))
            
            mode = 'a' if append else 'w'
            file_exists = Path(filename).exists()
            
            with open(filename, mode, newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                
                # Write header only if not appending or file doesn't exist
                if not append or not file_exists:
                    writer.writeheader()
                
                for result in results:
                    if isinstance(result, dict):
                        # Flatten nested dictionaries and convert complex types to strings
                        flattened_result = self._flatten_dict(result)
                        writer.writerow(flattened_result)
                    
        except Exception as e:
            console.print(f"[red]Error saving CSV file {filename}: {e}[/red]")
            raise
    
    def _flatten_dict(self, d: Dict[str, Any], parent_key: str = '', sep: str = '_') -> Dict[str, str]:
        """Flatten nested dictionaries for CSV output"""
        items = []
        
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                # Convert lists to comma-separated strings
                items.append((new_key, ','.join(str(item) for item in v)))
            else:
                # Convert all values to strings
                items.append((new_key, str(v) if v is not None else ''))
        
        return dict(items)
    
    async def save_xml(
        self,
        results: List[Dict[str, Any]],
        filename: str,
        root_element: str = 'results',
        item_element: str = 'item'
    ) -> None:
        """Save results to XML format"""
        if not results:
            return
        
        try:
            import xml.etree.ElementTree as ET
            from xml.dom import minidom
            
            root = ET.Element(root_element)
            root.set('generated_at', str(int(time.time())))
            root.set('count', str(len(results)))
            
            for result in results:
                item = ET.SubElement(root, item_element)
                self._dict_to_xml(result, item)
            
            # Pretty print XML
            xml_str = ET.tostring(root, encoding='unicode')
            dom = minidom.parseString(xml_str)
            pretty_xml = dom.toprettyxml(indent='  ')
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(pretty_xml)
                
        except ImportError:
            console.print("[yellow]XML support requires xml module (built-in)[/yellow]")
        except Exception as e:
            console.print(f"[red]Error saving XML file {filename}: {e}[/red]")
            raise
    
    def _dict_to_xml(self, d: Dict[str, Any], parent: 'ET.Element') -> None:
        """Convert dictionary to XML elements"""
        for key, value in d.items():
            # Sanitize key name for XML
            clean_key = str(key).replace(' ', '_').replace('-', '_')
            
            if isinstance(value, dict):
                child = ET.SubElement(parent, clean_key)
                self._dict_to_xml(value, child)
            elif isinstance(value, list):
                for item in value:
                    child = ET.SubElement(parent, clean_key)
                    if isinstance(item, dict):
                        self._dict_to_xml(item, child)
                    else:
                        child.text = str(item)
            else:
                child = ET.SubElement(parent, clean_key)
                child.text = str(value) if value is not None else ''
    
    async def save_markdown(
        self,
        results: List[Dict[str, Any]],
        filename: str,
        title: str = "Bug Scan Pro Results",
        include_metadata: bool = True
    ) -> None:
        """Save results to Markdown format"""
        if not results:
            return
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                # Write header
                f.write(f"# {title}\n\n")
                
                if include_metadata:
                    f.write(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
                    f.write(f"**Total Results:** {len(results)}\n")
                    f.write(f"**Generated by:** Bug Scan Pro - Made with ♥️ by @lonefaisal\n\n")
                
                # Write results
                for i, result in enumerate(results, 1):
                    f.write(f"## Result {i}\n\n")
                    
                    if isinstance(result, dict):
                        for key, value in result.items():
                            if isinstance(value, (list, dict)):
                                f.write(f"**{key}:** ```json\n{json.dumps(value, indent=2)}\n```\n\n")
                            else:
                                f.write(f"**{key}:** {value}\n\n")
                    else:
                        f.write(f"{result}\n\n")
                    
                    f.write("---\n\n")
                
        except Exception as e:
            console.print(f"[red]Error saving Markdown file {filename}: {e}[/red]")
            raise
    
    async def save_multiple_formats(
        self,
        results: List[Dict[str, Any]],
        base_filename: str,
        formats: List[str] = None,
        append: bool = False
    ) -> None:
        """Save results in multiple formats with the same base filename"""
        if formats is None:
            formats = ['txt', 'json', 'csv']
        
        base_path = Path(base_filename)
        base_name = base_path.stem
        base_dir = base_path.parent
        
        tasks = []
        
        for fmt in formats:
            filename = base_dir / f"{base_name}.{fmt}"
            
            if fmt == 'txt':
                tasks.append(self.save_txt(results, str(filename), append))
            elif fmt == 'json':
                tasks.append(self.save_json(results, str(filename), append))
            elif fmt == 'csv':
                tasks.append(self.save_csv(results, str(filename), append))
            elif fmt == 'xml':
                tasks.append(self.save_xml(results, str(filename)))
            elif fmt == 'md' or fmt == 'markdown':
                tasks.append(self.save_markdown(results, str(filename)))
        
        # Execute all save operations concurrently
        await asyncio.gather(*tasks, return_exceptions=True)
    
    def get_output_stats(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get statistics about the results"""
        if not results:
            return {'total': 0}
        
        stats = {
            'total': len(results),
            'successful': 0,
            'failed': 0,
            'timestamp': int(time.time())
        }
        
        # Analyze results
        for result in results:
            if isinstance(result, dict):
                # Check for common success indicators
                if any([
                    result.get('resolved', False),
                    result.get('reachable', False),
                    result.get('success', False),
                    result.get('status') == 200
                ]):
                    stats['successful'] += 1
                else:
                    stats['failed'] += 1
        
        return stats


if __name__ == "__main__":
    # Test the output manager
    async def test_output_manager():
        manager = OutputManager()
        
        # Sample data
        test_results = [
            {
                'host': 'example.com',
                'resolved': True,
                'ips': ['93.184.216.34'],
                'http': {'reachable': True, 'status': 200}
            },
            {
                'host': 'test.example.com',
                'resolved': True,
                'ips': ['93.184.216.35'],
                'http': {'reachable': False}
            }
        ]
        
        # Test all formats
        await manager.save_txt(test_results, 'test_output.txt')
        await manager.save_json(test_results, 'test_output.json')
        await manager.save_csv(test_results, 'test_output.csv')
        await manager.save_markdown(test_results, 'test_output.md')
        
        print("Test files created: test_output.{txt,json,csv,md}")
        
        # Print stats
        stats = manager.get_output_stats(test_results)
        print(f"Stats: {stats}")
    
    asyncio.run(test_output_manager())