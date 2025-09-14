#!/usr/bin/env python3
"""
Configuration management for Auto Security Scanner
"""

import os
from pathlib import Path
from typing import Dict, Any


class Config:
    """Configuration management class"""
    
    # Default configuration
    DEFAULT_CONFIG = {
        'scanner': {
            'max_subdomains': 20,
            'timeout': 600,
            'max_workers': 3,
            'output_format': 'json'
        },
        'tools': {
            'porch_pirate': {
                'enabled': True,
                'timeout': 300,
                'search_limit': 50
            },
            'subfinder': {
                'enabled': True,
                'timeout': 300,
                'silent': True
            },
            'nuclei': {
                'enabled': True,
                'timeout': 600,
                'protocols': ['http', 'https'],
                'severity_levels': ['critical', 'high', 'medium', 'low', 'info']
            },
            'osmedeus': {
                'enabled': True,
                'timeout': 2400,
                'workflow': 'general',
                'intensive': False
            },
            'rengine': {
                'enabled': True,
                'timeout': 1800,
                'use_docker': True,
                'max_subdomains': 50
            }
        },
        'output': {
            'base_dir': 'scan_results',
            'include_timestamp': True,
            'compress_results': False,
            'keep_raw_files': True
        },
        'logging': {
            'level': 'INFO',
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            'file_logging': True
        }
    }
    
    def __init__(self, config_file: str = None):
        self.config = self.DEFAULT_CONFIG.copy()
        self.config_file = config_file or os.path.join(Path.home(), '.auto_scanner_config.json')
        self.load_config()
    
    def load_config(self):
        """Load configuration from file if it exists"""
        config_path = Path(self.config_file)
        if config_path.exists():
            try:
                import json
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    self._merge_config(self.config, user_config)
            except Exception as e:
                print(f"Warning: Could not load config file {self.config_file}: {e}")
    
    def save_config(self):
        """Save current configuration to file"""
        try:
            import json
            config_path = Path(self.config_file)
            config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save config file {self.config_file}: {e}")
    
    def _merge_config(self, base: Dict[str, Any], update: Dict[str, Any]):
        """Recursively merge configuration dictionaries"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value
    
    def get(self, key_path: str, default=None):
        """Get configuration value using dot notation (e.g., 'scanner.max_subdomains')"""
        keys = key_path.split('.')
        value = self.config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
    
    def set(self, key_path: str, value):
        """Set configuration value using dot notation"""
        keys = key_path.split('.')
        config = self.config
        
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        config[keys[-1]] = value
    
    def get_tool_config(self, tool_name: str) -> Dict[str, Any]:
        """Get configuration for a specific tool"""
        return self.config.get('tools', {}).get(tool_name, {})
    
    def is_tool_enabled(self, tool_name: str) -> bool:
        """Check if a tool is enabled"""
        return self.get_tool_config(tool_name).get('enabled', True)
