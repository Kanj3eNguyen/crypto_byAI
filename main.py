"""
Điểm vào chính của chương trình.
"""

import sys
from pathlib import Path

# Thêm thư mục hiện tại vào đường dẫn import.
sys.path.insert(0, str(Path(__file__).parent))

from src.cli import cli

if __name__ == '__main__':
    cli()
