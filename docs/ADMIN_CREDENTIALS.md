# Admin Credentials

## Quick Start

When you start the Medaudit 2.0 web server, an admin account is automatically created or updated. For security, Medaudit **always generates a random secure password** if you do not provide one.

### First Run
1. Start the server: `python -m medaudit web`
2. Look at the terminal output for the generated password.
3. Access the web UI at `http://localhost:8080`.
4. Log in with:
   - **Username**: `admin`
   - **Password**: (The generated password from your terminal)

---

## Starting the Web Server

### Option 1: Automatic Generation (Default)
```bash
python3 -m medaudit web
```
This generates a cryptographically secure 20-character random password and displays it on startup.

### Option 2: Set a Custom Password
```bash
python3 -m medaudit web --password "YourSecurePassword123!"
```
This sets the admin password to your specific value.

---

## Security Recommendations

⚠️ **CRITICAL**: The generated password is displayed only on startup. If you forget it, you will need to reset it via the CLI by restarting with a new `--password` or by deleting the database.

### For Production Use
Always use either a strong custom password or the automatically generated one.

### Password Requirements
For custom passwords, we recommend:
- Minimum 12 characters
- Mix of uppercase, lowercase, numbers, and special characters
- Avoid common words or patterns
- Use a password manager

---

## Technical Details

### Database Storage
- User credentials are stored in: `medaudit/data/medaudit.db`
- Passwords are hashed using **PBKDF2-SHA256** with 600,000 iterations
- Salt is randomly generated (32 bytes) for each password
- Constant-time comparison prevents timing attacks

### Admin Account Properties
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

---

## Rate Limiting
Login attempts are rate-limited to prevent brute force attacks:
- **Max Attempts**: 5 per 5-minute window
- **Lockout Duration**: 15 minutes after exceeding limit
- Rate limiting is per IP address

---

## Troubleshooting

### Forgotten Password
If you lose your password:
1. **Restart with a new one**:
   ```bash
   python3 -m medaudit web --password "NewTemporaryPassword"
   ```
2. **Reset the entire database** (WARNING: deletes all data):
   ```bash
   rm medaudit/data/medaudit.db
   python3 -m medaudit web
   ```

---

**Last Updated**: April 2026
**Version**: 2.0.1
