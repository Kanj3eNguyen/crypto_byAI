"""
Configuration module for loading and managing project settings
"""

import os
import yaml
from typing import Dict, Any
from pathlib import Path


class Config:
    """Configuration manager for the project"""
    
    def __init__(self, config_file: str = None):
        """
        Initialize configuration from YAML file
        
        Args:
            config_file: Path to YAML config file. If None, uses default.yaml
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
        """Load configuration from YAML file"""
        if not os.path.exists(self.config_file):
            raise FileNotFoundError(f"Config file not found: {self.config_file}")
        
        with open(self.config_file, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key using dot notation"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k, default)
            else:
                return default
        
        return value
    
    def __getitem__(self, key: str):
        """Dictionary-style access"""
        return self.config[key]
    
    def __repr__(self):
        return f"Config(file={self.config_file})"


# Global config instance
_config = None

def get_config(config_file: str = None) -> Config:
    """Get or create global config instance"""
    global _config
    if _config is None:
        _config = Config(config_file)
    return _config
