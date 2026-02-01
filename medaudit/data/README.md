# Medaudit Data Directory

This directory contains runtime data for the medaudit application:

- `medaudit.db` - SQLite database for projects, users, analyses
- `artifacts/` - Project artifacts (uploaded PCAPs, exports, etc.)
  - `projects/{project_id}/pcaps/` - PCAP files per project

This directory is auto-created and should be git-ignored in production.
