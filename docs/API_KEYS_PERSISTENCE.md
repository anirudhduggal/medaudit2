# AI API Keys Persistence - Implementation Guide

**Date**: February 17, 2026  
**Issue**: API keys configured in the web UI were not persisting across server restarts

## Problem

Previously, AI provider API keys were stored only in memory (`_providers` global dict) in the AI API module. This meant:
- ✗ Keys were lost when the web server restarted
- ✗ Users had to reconfigure API keys each time the server started
- ✗ No per-project API key management

## Solution

Implemented **persistent, per-project API key storage** in the SQLite database.

---

## Architecture Changes

### 1. New Database Table: `AICredential`
```python
class AICredential(Base):
    __tablename__ = "ai_credentials"
    
    # Fields
    - id: UUID (primary key)
    - project_id: ForeignKey(projects.id)
    - provider: str (anthropic, openai, gemini, ollama, etc.)
    - api_key: str (encrypted in storage)
    - base_url: str (optional, for custom endpoints)
    - default_model: str (user's preferred model)
    - is_active: bool (currently selected provider)
    - created_at, updated_at, last_validated: DateTime
    - validation_error: str (for diagnostics)
```

**Location**: `medaudit/web/database.py`

### 2. Project-Credential Relationship
```python
# In Project model:
ai_credentials = relationship("AICredential", back_populates="project", cascade="all, delete-orphan")

# In AICredential model:
project = relationship("Project", back_populates="ai_credentials", cascade="all, delete-orphan")
```

---

## New API Endpoints

Three new endpoints for managing per-project AI credentials:

### Save Project Credential
```
POST /api/ai/projects/{project_id}/ai-credentials
Body: {
  "provider": "openai",
  "api_key": "sk-...",
  "base_url": null,  // optional
  "default_model": "gpt-4o"
}
Response: {
  "success": true,
  "provider": "openai",
  "models": [...],
  "default_model": "gpt-4o",
  "saved_to_project": true
}
```

### Get Project Credentials
```
GET /api/ai/projects/{project_id}/ai-credentials
Response: {
  "project_id": "...",
  "credentials": [
    {
      "provider": "openai",
      "default_model": "gpt-4o",
      "is_active": true,
      "last_validated": "2026-02-17T10:30:00",
      // Note: api_key is NOT returned for security
    }
  ],
  "active_provider": "openai"
}
```

### Delete Project Credential
```
DELETE /api/ai/projects/{project_id}/ai-credentials/{provider}
Response: {
  "success": true,
  "message": "Credential for openai deleted"
}
```

---

## Credential Loading Flow

### On Chat Request
When a user sends a message in a project:

1. **Check In-Memory**: Are credentials configured in `_providers` dict?
2. **If Empty**: Call `_load_project_credentials(project_id, db)`
3. **Database Restore**: Load all credentials for the project from database
4. **Validation**: Verify each credential is still valid
5. **Activate**: Set the `is_active=true` credential as active
6. **Use**: Proceed with chat using loaded credentials

### Function: `_load_project_credentials(project_id, db)`
```python
def _load_project_credentials(project_id: str, db: Session) -> bool:
    """Load AI credentials for a project from the database."""
    # Query AICredential records for the project
    # Validate each credential's API key
    # Restore to _providers dict
    # Set active provider
    # Return True if at least one credential loaded
```

---

## Security Considerations

### API Key Storage
- ✓ Keys stored in SQLite database (same security as project config)
- ✓ Keys are **NOT** exposed in API responses (unless explicitly requested)
- ✓ Keys validated before storage
- ✓ Per-project isolation (users can only access their own projects' keys)

### Access Control
- ✓ All endpoints require authentication (`@require_auth`)
- ✓ Project ownership enforced (`Project.owner_id == user.id`)
- ✓ Keys deleted when project is deleted (cascade delete)

### Masked Return Values
When credentials are returned in responses, keys are masked:
```
"api_key_masked": "sk-...a7f3b2e1"  // Last 8 chars only
```

---

## Git Ignore Updates

Enhanced `.gitignore` to ensure no databases are committed:

```ignore
# Database files (SQLite)
medaudit/data/medaudit.db
medaudit/data/*.db
medaudit/data/medaudit.db-*
*.db
*.sqlite
*.sqlite3
```

---

## Migration Guide

### For Users
1. **When server restarts**: Keys are automatically loaded from database
2. **To save a new key**: Use Settings tab or API endpoint
3. **To use per-project keys**: Configure credentials per project, then use

### For Developers
When making changes to AI credential handling:

1. **Loading**: Call `_load_project_credentials()` when needed
2. **Saving**: Use `POST /api/ai/projects/{id}/ai-credentials`
3. **Verifying**: Check `AICredential` table in database
4. **Testing**: Create test projects, save keys, restart server, verify load

---

## Testing the Fix

```bash
# 1. Start the server
python -m medaudit web --port 8080

# 2. Create a project (or use existing)
# 3. Configure an AI provider via Settings
# 4. Send a chat message (loads credentials)
# 5. Verify message succeeds
# 6. Restart the server (Ctrl+C then restart)
# 7. Go to same project, send chat message
# 8. Verify credentials are still loaded (no 401 error)
```

**Expected result**: Credentials persist across server restarts, no reconfiguration needed.

---

## Files Modified

| File | Changes |
|------|---------|
| `medaudit/web/database.py` | Added `AICredential` table + relationship |
| `medaudit/web/ai_api.py` | Added 3 endpoints + credential loading function |
| `.gitignore` | Enhanced database file exclusions |

---

## Backward Compatibility

✓ **Fully backward compatible**
- Old in-memory provider config still works
- Credentials can exist in both memory and database
- Database credentials are loaded when needed
- No breaking changes to existing API

---

## Known Limitations

- Credentials must be saved per-project (not global at this time)
- Credentials are NOT encrypted in database (can be enhanced with AES encryption)
- No credentials history/audit trail (can be added as follow-up)

---

## Future Enhancements

1. **Encryption**: Encrypt API keys at rest using AES-256
2. **Audit Trail**: Log all credential access/changes
3. **Key Rotation**: Auto-rotate old keys, prompt for refresh
4. **Global Credentials**: Share credentials across projects (with permissions)
5. **SSO Integration**: Use OAuth/SAML for AI provider tokens
