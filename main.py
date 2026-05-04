"""
Ransomware Crypto AI - Main entry point
"""

import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent))

from src.cli import cli

if __name__ == '__main__':
    cli()
