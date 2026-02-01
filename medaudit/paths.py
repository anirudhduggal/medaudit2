# Medaudit Path Configuration
# Centralized path management for data, config, and logs

"""
Path Configuration Module

This module provides centralized path management for all Medaudit components.
All paths are relative to the medaudit package directory to keep data organized.

Directory Structure (inside medaudit/):
    medaudit/
    ├── data/
    │   ├── medaudit.db          # SQLite database
    │   └── artifacts/           # Project artifacts (PCAPs, exports)
    │       └── projects/
    │           └── {project_id}/
    │               └── pcaps/
    ├── config/
    │   └── medaudit.json        # Configuration file
    └── logs/
        └── YYYY-MM-DD/          # Date-organized logs
            ├── connections.jsonl
            ├── server_events.jsonl
            └── hl7_messages.jsonl
"""

import os
from pathlib import Path
from typing import Optional

# Get the medaudit package directory
PACKAGE_DIR = Path(__file__).parent

# Base directories inside the medaudit package
DATA_DIR = PACKAGE_DIR / "data"
CONFIG_DIR = PACKAGE_DIR / "config"
LOGS_DIR = PACKAGE_DIR / "logs"

# Specific paths
DATABASE_PATH = DATA_DIR / "medaudit.db"
ARTIFACTS_DIR = DATA_DIR / "artifacts"
PROJECTS_ARTIFACTS_DIR = ARTIFACTS_DIR / "projects"
CONFIG_FILE = CONFIG_DIR / "medaudit.json"


def ensure_directories():
    """Create all required directories if they don't exist."""
    directories = [
        DATA_DIR,
        ARTIFACTS_DIR,
        PROJECTS_ARTIFACTS_DIR,
        CONFIG_DIR,
        LOGS_DIR,
    ]
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)


def get_data_dir() -> Path:
    """Get the data directory path, creating it if needed."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return DATA_DIR


def get_config_dir() -> Path:
    """Get the config directory path, creating it if needed."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    return CONFIG_DIR


def get_logs_dir() -> Path:
    """Get the logs directory path, creating it if needed."""
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    return LOGS_DIR


def get_database_path() -> Path:
    """Get the database file path, creating parent directories if needed."""
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    return DATABASE_PATH


def get_artifacts_dir() -> Path:
    """Get the artifacts directory path, creating it if needed."""
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    return ARTIFACTS_DIR


def get_project_artifacts_dir(project_id: str) -> Path:
    """
    Get the artifacts directory for a specific project.
    
    Args:
        project_id: The project UUID
        
    Returns:
        Path to the project's artifacts directory
    """
    project_dir = PROJECTS_ARTIFACTS_DIR / project_id
    project_dir.mkdir(parents=True, exist_ok=True)
    return project_dir


def get_project_pcaps_dir(project_id: str) -> Path:
    """
    Get the PCAP directory for a specific project.
    
    Args:
        project_id: The project UUID
        
    Returns:
        Path to the project's PCAP directory
    """
    pcaps_dir = get_project_artifacts_dir(project_id) / "pcaps"
    pcaps_dir.mkdir(parents=True, exist_ok=True)
    return pcaps_dir


def get_config_file() -> Path:
    """Get the config file path."""
    return CONFIG_FILE


def get_config_search_paths() -> list:
    """
    Get the list of paths to search for configuration files.
    
    Order of precedence:
    1. medaudit/config/medaudit.json (package-level, preferred)
    2. ./config/medaudit.json (repo-level fallback)
    3. ./medaudit.json (backwards-compatible)
    4. ~/.medaudit.json (user home)
    5. ~/.config/medaudit.json (XDG config)
    
    Returns:
        List of Path objects to search
    """
    return [
        CONFIG_FILE,  # Package-level (preferred)
        Path.cwd() / "config" / "medaudit.json",  # Repo-level
        Path.cwd() / "medaudit.json",  # Backwards-compatible
        Path.home() / ".medaudit.json",  # User home
        Path.home() / ".config" / "medaudit.json",  # XDG config
    ]


# Initialize directories on module import
ensure_directories()
