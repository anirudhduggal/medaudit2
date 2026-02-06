# Default Admin Credentials

## Quick Start

When you start the Medaudit 2.0 web server for the first time, a default admin account is automatically created:

```
Username: admin
Password: admin123
```

## Starting the Web Server

```bash
# Start with default credentials (username: admin, password: admin123)
python3 -m medaudit web

# Or specify host and port
python3 -m medaudit web --host 0.0.0.0 --port 8080
```

Access the web UI at: **http://localhost:8080**

## Security Recommendations

⚠️ **WARNING**: The default password `admin123` is intended for development and testing only.

### For Production Use

Always change the default password using one of these methods:

#### Option 1: Set a Custom Password
```bash
python3 -m medaudit web --password "YourSecurePassword123!"
```

#### Option 2: Generate a Random Secure Password
```bash
python3 -m medaudit web --generate-password
```

This will generate a cryptographically secure 20-character random password and display it on startup.

## Password Management

### Changing the Admin Password

To change the admin password after the first setup:

1. **Via CLI** (recommended):
   ```bash
   python3 -m medaudit web --password "NewSecurePassword"
   ```

2. **Via Web UI**:
   - Log in with current credentials
   - Navigate to profile settings (if implemented)
   - Update password through the interface

### Password Requirements

For custom passwords, we recommend:
- Minimum 12 characters
- Mix of uppercase, lowercase, numbers, and special characters
- Avoid common words or patterns
- Use a password manager

## Technical Details

### Database Storage

- User credentials are stored in: `medaudit/data/medaudit.db`
- Passwords are hashed using **PBKDF2-SHA256** with 600,000 iterations
- Salt is randomly generated (32 bytes) for each password
- Constant-time comparison prevents timing attacks

### Default Admin Account

The admin account is automatically created with:
- **Username**: `admin` (cannot be changed)
- **Email**: `admin@medaudit.local`
- **Full Name**: `Administrator`
- **Admin Rights**: `True`
- **Active**: `True`

### Session Management

- Sessions expire after 24 hours of inactivity
- Session tokens are 48-byte URL-safe random values
- Stored securely in database with expiration tracking

## Authentication Flow

```
1. User visits /login
2. Enters username: "admin" and password: "admin123"
3. Server validates credentials using PBKDF2 hash comparison
4. On success:
   - Creates session token
   - Sets secure HTTP-only cookie
   - Redirects to /dashboard
5. Subsequent requests use session token for authentication
```

## Rate Limiting

Login attempts are rate-limited to prevent brute force attacks:
- **Max Attempts**: 5 per 5-minute window
- **Lockout Duration**: 15 minutes after exceeding limit
- Rate limiting is per IP address

## API Access

### Authentication Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/login` | POST | Login with username/password |
| `/auth/register` | POST | Create new user account |
| `/auth/logout` | POST | End session |
| `/auth/me` | GET | Get current user info |
| `/auth/check` | GET | Check authentication status |

### Example API Login

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

Response:
```json
{
  "message": "Login successful",
  "user": {
    "id": "...",
    "username": "admin",
    "email": "admin@medaudit.local",
    "full_name": "Administrator",
    "is_admin": true,
    "is_active": true
  }
}
```

## Troubleshooting

### Can't Log In with Default Credentials

If `admin/admin123` doesn't work:

1. **Check if custom password was set**:
   - Review terminal output from server startup
   - Look for "Admin Password:" message

2. **Reset admin password**:
   ```bash
   # Stop the server
   # Restart with new password
   python3 -m medaudit web --password "NewPassword123"
   ```

3. **Database corruption**:
   ```bash
   # Backup existing database
   cp medaudit/data/medaudit.db medaudit/data/medaudit.db.backup
   
   # Remove database (WARNING: deletes all data)
   rm medaudit/data/medaudit.db
   
   # Restart server (will recreate with defaults)
   python3 -m medaudit web
   ```

### Session Expires Too Quickly

Session duration is set to 24 hours. To modify, edit `medaudit/web/auth.py`:

```python
SESSION_DURATION_HOURS = 24  # Change this value
```

### Rate Limit Lockout

If you're locked out due to failed attempts:

1. **Wait 15 minutes** for lockout to expire
2. Or restart the server (clears in-memory rate limits)
3. Rate limits are per IP address

## Development vs Production

### Development (Default)

```bash
python3 -m medaudit web
```
- Default credentials: `admin/admin123`
- Runs on `localhost:8080`
- HTTP only (no TLS)
- Suitable for local testing

### Production

```bash
python3 -m medaudit web \
  --host 0.0.0.0 \
  --port 443 \
  --generate-password
```

Additional security measures:
- Use reverse proxy (nginx, Apache) with TLS
- Set `MEDAUDIT_SECURE_COOKIES=1` environment variable
- Configure firewall rules
- Use strong generated password
- Regular security updates
- Monitor access logs

## Environment Variables

```bash
# Force secure cookies (requires HTTPS)
export MEDAUDIT_SECURE_COOKIES=1

# Start server
python3 -m medaudit web
```

## Security Best Practices

1. ✅ **Always change default password in production**
2. ✅ **Use TLS/HTTPS for production deployments**
3. ✅ **Enable rate limiting (enabled by default)**
4. ✅ **Monitor authentication logs**
5. ✅ **Use strong, unique passwords**
6. ✅ **Keep software updated**
7. ✅ **Restrict network access to trusted IPs**
8. ✅ **Regular security audits**

## References

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [PBKDF2 Specification](https://www.rfc-editor.org/rfc/rfc2898)

---

**Last Updated**: February 5, 2026
**Version**: 2.0.0
