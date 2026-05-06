"""
Nạp và quản lý cấu hình của dự án.
"""

import os
import yaml
from typing import Dict, Any


class Config:
    """Lớp quản lý cấu hình."""
    
    def __init__(self, config_file: str = None):
        """
        Khởi tạo cấu hình từ file YAML.

        Args:
            config_file: Đường dẫn file YAML. Nếu không truyền, dùng default.yaml.
        """
        if config_file is None:
            config_file = os.path.join(
                os.path.dirname(__file__), 
                "..", 
                "configs", 
                "default.yaml"
            )
        
        self.config_file = config_file
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Đọc cấu hình từ file YAML."""
        if not os.path.exists(self.config_file):
            raise FileNotFoundError(f"Config file not found: {self.config_file}")
        
        with open(self.config_file, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Lấy giá trị cấu hình bằng khóa dạng dấu chấm."""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k, default)
            else:
                return default
        
        return value
    
    def __getitem__(self, key: str):
        """Cho phép truy cập cấu hình theo kiểu dictionary."""
        return self.config[key]
    
    def __repr__(self):
        return f"Config(file={self.config_file})"


# Thể hiện cấu hình dùng chung.
_config = None

def get_config(config_file: str = None) -> Config:
    """Lấy hoặc tạo thể hiện cấu hình dùng chung."""
    global _config
    if _config is None:
        _config = Config(config_file)
    return _config
