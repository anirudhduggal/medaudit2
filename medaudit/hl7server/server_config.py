"""
Configuration Module for HL7 Server

This module handles loading and managing configuration for the HL7 mock server.
Configuration can be loaded from:
- hl7server.json in current directory
- ~/.hl7server.json in user home
- ~/.config/hl7server.json in XDG config directory
- Command line arguments override file values
"""

import json
import os
from pathlib import Path
from typing import Optional, Dict, Any


class ServerConfig:
    """Configuration manager for HL7 Server."""

    DEFAULT_CONFIG = {
        "server": {
            "host": "localhost",
            "port": 2575,
            "use_tls": False,
            "cert_file": None,
            "key_file": None,
            "verbose": True
        },
        "logging": {
            "enabled": True,
            "log_dir": "logs/hl7server"
        }
    }

    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize server configuration.

        Args:
            config_file: Optional path to configuration file
        """
        self.config = self.DEFAULT_CONFIG.copy()
        self._load_config_file(config_file)

    def _load_config_file(self, config_file: Optional[str] = None):
        """Load configuration from file if it exists."""
        config_paths = []

        # If specific file provided, use it first
        if config_file:
            config_paths.append(Path(config_file))

        # Standard locations
        config_paths.extend([
            Path.cwd() / "hl7server.json",
            Path.home() / ".hl7server.json",
            Path.home() / ".config" / "hl7server.json"
        ])

        for config_path in config_paths:
            if config_path.exists():
                try:
                    with open(config_path, 'r') as f:
                        file_config = json.load(f)
                        self._merge_config(file_config)
                        print(f"Loaded HL7 Server configuration from: {config_path}")
                        break
                except (json.JSONDecodeError, IOError) as e:
                    print(f"Warning: Could not load config from {config_path}: {e}")
                    continue

    def _merge_config(self, file_config: Dict[str, Any]):
        """Merge file config with defaults."""
        for section, values in file_config.items():
            if section in self.config and isinstance(values, dict):
                self.config[section].update(values)
            else:
                self.config[section] = values

    def get_server_config(self) -> Dict[str, Any]:
        """Get server configuration."""
        return self.config.get("server", {})

    def get_logging_config(self) -> Dict[str, Any]:
        """Get logging configuration."""
        return self.config.get("logging", {})

    def create_default_config(self, path: Optional[str] = None) -> Path:
        """
        Create a default configuration file.

        Args:
            path: Optional path to create config file at (default: ./hl7server.json)

        Returns:
            Path to created configuration file
        """
        if path is None:
            path = Path.cwd() / "hl7server.json"
        else:
            path = Path(path)

        # Create directory if it doesn't exist
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, 'w') as f:
            json.dump(self.DEFAULT_CONFIG, f, indent=2)

        print(f"Created default HL7 Server configuration file: {path}")
        return path

    def show_config(self):
        """Display current configuration."""
        print("\n=== HL7 Server Configuration ===")
        print(json.dumps(self.config, indent=2))
        print("================================\n")

    def get_all_config(self) -> Dict[str, Any]:
        """Get all configuration."""
        return self.config

    def update_config(self, section: str, key: str, value: Any):
        """
        Update a configuration value.

        Args:
            section: Configuration section (e.g., 'server', 'logging')
            key: Configuration key
            value: New value
        """
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = value

    def save_config(self, path: Optional[str] = None):
        """
        Save current configuration to file.

        Args:
            path: Optional path to save config file to
        """
        if path is None:
            path = Path.cwd() / "hl7server.json"
        else:
            path = Path(path)

        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, 'w') as f:
            json.dump(self.config, f, indent=2)

        print(f"Saved HL7 Server configuration to: {path}")
