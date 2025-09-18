#!/usr/bin/env python3
"""
Bug Scan Pro - Professional async-based bug host discovery and network reconnaissance toolkit
Created by @lonefaisal - Made with ♥️ by @lonefaisal
"""

import sys
import asyncio
import signal
from typing import NoReturn

# Import uvloop for Linux/macOS performance boost
try:
    import uvloop
    if sys.platform != 'win32':
        uvloop.install()
except ImportError:
    pass

from bugscanpro.cli import main as cli_main
from bugscanpro import __version__


def signal_handler(signum: int, frame) -> NoReturn:
    """Handle Ctrl+C gracefully"""
    print("\n[!] Interrupted by user. Exiting gracefully...")
    sys.exit(0)


def main() -> None:
    """Main entry point for bug-scan-pro"""
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Run the CLI
        asyncio.run(cli_main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting gracefully...")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()