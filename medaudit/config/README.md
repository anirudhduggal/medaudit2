# Medaudit Configuration Directory

This directory contains configuration files:

- `medaudit.json` - Main application configuration
- `hl7server.json` - HL7 server configuration

Configuration is searched in this order:
1. `medaudit/config/` (package config - this directory)
2. Working directory (backwards compatible)
3. `~/.medaudit.json` (user home)
4. `~/.config/medaudit.json` (XDG config)
