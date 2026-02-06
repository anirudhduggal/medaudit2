"""
Configuration Module for Medaudit 2.0

This module handles loading configuration from JSON files.
All paths are managed centrally via medaudit.paths.

Configuration precedence (highest to lowest):
1. Command line arguments
2. medaudit/config/medaudit.json (inside package)
3. ~/.medaudit.json (user home)
4. ~/.config/medaudit.json (XDG config)
5. Default values

Example:
    from medaudit.config import config
    proxy_cfg = config.get_proxy_config()
    logging_cfg = config.get_logging_config()
"""

import json
from pathlib import Path


class Config:
    """Configuration manager for Medaudit 2.0."""

    DEFAULT_CONFIG = {
        "proxy": {
            "http_host": "localhost",
            "http_port": 8080,
            "hl7_host": "localhost",
            "hl7_port": 2575
        },
        "analysis": {
            "max_hl7_messages": 10,
            "max_pii_instances": 20
        },
        "logging": {
            "enabled": True,
            "log_dir": "logs"
        }
    }

    def __init__(self):
        self.config = self.DEFAULT_CONFIG.copy()
        self._load_config_file()

    def _load_config_file(self):
        """Load configuration from medaudit.json if it exists."""
        # Import here to avoid circular dependency
        from medaudit.utils import get_config_search_paths

        config_paths = get_config_search_paths()

        for config_path in config_paths:
            if config_path.exists():
                try:
                    with open(config_path, 'r') as f:
                        file_config = json.load(f)
                        self._merge_config(file_config)
                        print(f"Loaded configuration from: {config_path}")
                        break
                except (json.JSONDecodeError, IOError) as e:
                    print(f"Warning: Could not load config from {config_path}: {e}")
                    continue

    def _merge_config(self, file_config):
        """Merge file config with defaults."""
        for section, values in file_config.items():
            if section in self.config and isinstance(values, dict):
                self.config[section].update(values)
            else:
                self.config[section] = values

    def get_proxy_config(self):
        """Get proxy configuration."""
        return self.config.get("proxy", {})

    def get_analysis_config(self):
        """Get analysis configuration."""
        return self.config.get("analysis", {})

    def get_logging_config(self):
        """Get logging configuration."""
        return self.config.get("logging", {})

    def create_default_config(self, path=None):
        """Create a default configuration file."""
        if path is None:
            from medaudit.utils import CONFIG_DIR
            path = CONFIG_DIR / "medaudit.json"

        # Create directory if it doesn't exist
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, 'w') as f:
            json.dump(self.DEFAULT_CONFIG, f, indent=2)

        print(f"Created default configuration file: {path}")
        return path

    def get_all(self):
        """Get full configuration dictionary."""
        return self.config.copy()


# Global config instance
config = Config()
