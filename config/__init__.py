"""
Configuration Module for Medaudit 2.0
AI Agent Instructions:
- This module handles loading configuration from JSON files
- Command line arguments override config file values
- Look for medaudit.json in config/ directory or user home
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
        # Search order: repo config/medaudit.json -> cwd medaudit.json (backcompat) -> user home -> XDG
        config_paths = [
            Path.cwd() / "config" / "medaudit.json",  # Preferred repo-level config folder
            Path.cwd() / "medaudit.json",  # Backwards-compatible fallback
            Path.home() / ".medaudit.json",  # User home directory
            Path.home() / ".config" / "medaudit.json"  # XDG config directory
        ]

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

    def get_logging_config(self):
        """Get logging configuration."""
        return self.config.get("logging", {})

    def create_default_config(self, path=None):
        """Create a default configuration file."""
        if path is None:
            path = Path.cwd() / "config" / "medaudit.json"

        # Create directory if it doesn't exist
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, 'w') as f:
            json.dump(self.DEFAULT_CONFIG, f, indent=2)

        print(f"Created default configuration file: {path}")
        return path

# Global config instance
config = Config()
