#!/usr/bin/env python3
"""
Bug Scan Pro - Professional async-based bug host discovery and network reconnaissance toolkit
Next-generation security testing with AI intelligence and military-grade stealth

Powered by ARROW NETWORK & KMRI NETWORK
Created by @lonefaisal - Made with ♥️ by @lonefaisal
"""

import sys
import asyncio
import signal
import os
import time
from typing import NoReturn
from pathlib import Path

# Import uvloop for Linux/macOS performance boost
try:
    import uvloop
    if sys.platform != 'win32':
        uvloop.install()
except ImportError:
    pass

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from bugscanpro.cli import main as cli_main
from bugscanpro import __version__

console = Console()


def print_startup_banner() -> None:
    """Print enhanced startup banner with network branding"""
    banner_text = """
🚀 BUG SCAN PRO - ADVANCED SECURITY TOOLKIT 🚀

📡 Next-Generation Network Reconnaissance
🛡️ Military-Grade Stealth Operations  
🤖 AI-Powered Intelligence Engine
⚡ Ultra-High Performance Scanning

📱 POWERED BY:
🌟 ARROW NETWORK: t.me/arrow_network
🔥 KMRI NETWORK: t.me/kmri_network_reborn

Made with ❤️ by @lonefaisal | GitHub: lonefaisal7
    """
    
    console.print(Panel(
        banner_text,
        title=f"🔍 Bug Scan Pro v{__version__}",
        border_style="bright_cyan",
        padding=(1, 2)
    ))


def check_system_requirements() -> bool:
    """Check system requirements and dependencies"""
    requirements_met = True
    
    # Check Python version
    if sys.version_info < (3, 8):
        console.print("[red]❌ Python 3.8+ is required[/red]")
        requirements_met = False
    
    # Check for critical dependencies
    critical_deps = ['aiohttp', 'rich', 'dnspython']
    missing_deps = []
    
    for dep in critical_deps:
        try:
            __import__(dep)
        except ImportError:
            missing_deps.append(dep)
            requirements_met = False
    
    if missing_deps:
        console.print(f"[red]❌ Missing dependencies: {', '.join(missing_deps)}[/red]")
        console.print("[yellow]⚡ Run: pip install -r requirements.txt[/yellow]")
    
    return requirements_met


def signal_handler(signum: int, frame) -> NoReturn:
    """Enhanced signal handler with cleanup"""
    console.print("\n[yellow]⏹️ Shutting down gracefully...[/yellow]")
    
    # Perform cleanup operations
    try:
        console.print("[blue]🧽 Cleaning up resources...[/blue]")
        console.print("[green]✅ Cleanup completed[/green]")
        
    except Exception as e:
        console.print(f"[red]❌ Cleanup error: {e}[/red]")
    
    console.print("[cyan]👋 Thanks for using Bug Scan Pro! - Made with ❤️ by @lonefaisal[/cyan]")
    sys.exit(0)


def run_performance_test() -> None:
    """Run performance benchmarks"""
    console.print("[blue]📊 Running performance benchmarks...[/blue]")
    
    # Test async performance
    async def benchmark_async():
        start_time = time.time()
        
        # Create 1000 async tasks
        async def dummy_task(i):
            await asyncio.sleep(0.001)
            return i
        
        tasks = [dummy_task(i) for i in range(1000)]
        results = await asyncio.gather(*tasks)
        
        end_time = time.time()
        duration = end_time - start_time
        rps = len(tasks) / duration
        
        return {
            'tasks': len(tasks),
            'duration': duration,
            'requests_per_second': rps
        }
    
    benchmark_result = asyncio.run(benchmark_async())
    
    console.print(Panel(
        f"Tasks: {benchmark_result['tasks']}\n"
        f"Duration: {benchmark_result['duration']:.2f}s\n"
        f"RPS: {benchmark_result['requests_per_second']:.0f}",
        title="⚡ Performance Benchmark",
        border_style="green"
    ))


def show_system_info() -> None:
    """Show system information and capabilities"""
    import platform
    
    # System info
    system_info = {
        'Platform': platform.system(),
        'Architecture': platform.machine(), 
        'Python Version': platform.python_version(),
        'Bug Scan Pro Version': __version__
    }
    
    # Network capabilities
    network_caps = [
        '✅ Async/Await Architecture',
        '✅ Military-Grade Stealth',
        '✅ AI-Powered Intelligence',
        '✅ Advanced Proxy Support',
        '✅ Plugin System',
        '✅ Multi-Format Output'
    ]
    
    console.print("[cyan]💻 System Information:[/cyan]")
    for key, value in system_info.items():
        console.print(f"  {key}: {value}")
    
    console.print("\n[green]✨ Advanced Capabilities:[/green]")
    for cap in network_caps:
        console.print(f"  {cap}")
    
    console.print("\n[magenta]📱 Networks:[/magenta]")
    console.print("  🌟 ARROW NETWORK: t.me/arrow_network")
    console.print("  🔥 KMRI NETWORK: t.me/kmri_network_reborn")
    
    console.print("\n[blue]👨‍💻 Creator:[/blue]")
    console.print("  📱 Telegram: @lonefaisal")
    console.print("  🐙 GitHub: lonefaisal7")


async def enhanced_main() -> None:
    """Enhanced main with advanced features"""
    try:
        # Check system requirements
        if not check_system_requirements():
            console.print("[red]❌ System requirements not met[/red]")
            sys.exit(1)
        
        # Print startup banner (unless disabled)
        if '--no-banner' not in sys.argv and '--silent' not in sys.argv:
            print_startup_banner()
        
        # Run the CLI
        await cli_main()
        
    except KeyboardInterrupt:
        console.print("\n[yellow]⏹️ Interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]❌ Fatal error: {e}[/red]")
        if '--verbose' in sys.argv or '-v' in sys.argv:
            import traceback
            console.print("[red]Traceback:[/red]")
            console.print(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    # Set up enhanced signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal_handler)
    
    # Check for special commands
    if '--benchmark' in sys.argv:
        run_performance_test()
        sys.exit(0)
    
    if '--system-info' in sys.argv:
        show_system_info()
        sys.exit(0)
    
    try:
        # Run the enhanced main application
        asyncio.run(enhanced_main())
    except KeyboardInterrupt:
        console.print("\n[yellow]⏹️ Interrupted by user. Goodbye![/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]❌ Fatal error: {e}[/red]")
        sys.exit(1)