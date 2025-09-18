"""
Passive subdomain discovery sources for Bug Scan Pro
Created by @lonefaisal - Made with ♥️ by @lonefaisal
"""

__all__ = [
    'BaseSource',
    'CrtShSource', 
    'OTXSource'
]

from .base import BaseSource
from .crtsh import CrtShSource
from .otx import OTXSource