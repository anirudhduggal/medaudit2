"""
Authentication module for Medaudit Web Application.
Handles admin login and session management.
"""

import os
import time
import threading
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional, Dict, Tuple
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .database import get_db, User, UserSession, get_db_manager

router = APIRouter(prefix="/auth", tags=["authentication"])

# Session duration
SESSION_DURATION_HOURS = 24

# Store admin password for display (set during init)
_admin_password_display: Optional[str] = None

# =============================================================================
# Rate Limiting for Login Attempts
# =============================================================================

# Rate limiting configuration
RATE_LIMIT_WINDOW_SECONDS = 300  # 5 minutes
RATE_LIMIT_MAX_ATTEMPTS = 5      # Max attempts per window
RATE_LIMIT_LOCKOUT_SECONDS = 900 # 15 minute lockout after exceeding

# In-memory rate limiting store: {ip: (attempt_count, window_start, lockout_until)}
_login_attempts: Dict[str, Tuple[int, float, float]] = defaultdict(lambda: (0, 0.0, 0.0))
_rate_limit_lock = threading.Lock()


def _get_client_ip(request: Request) -> str:
    """Get client IP address from request, handling proxies."""
    # Check X-Forwarded-For header (if behind proxy)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Take the first IP (original client)
        return forwarded.split(",")[0].strip()
    
    # Fall back to direct client IP
    if request.client:
        return request.client.host
    return "unknown"


def _check_rate_limit(ip: str) -> Tuple[bool, Optional[int]]:
    """
    Check if IP is rate limited.
    
    Returns: (is_allowed, seconds_until_unlock or None)
    """
    now = time.time()
    
    with _rate_limit_lock:
        count, window_start, lockout_until = _login_attempts[ip]
        
        # Check if currently locked out
        if lockout_until > now:
            return False, int(lockout_until - now)
        
        # Check if window has expired (reset counter)
        if now - window_start > RATE_LIMIT_WINDOW_SECONDS:
            _login_attempts[ip] = (0, now, 0.0)
            return True, None
        
        # Check if under limit
        if count < RATE_LIMIT_MAX_ATTEMPTS:
            return True, None
        
        # Over limit - apply lockout
        lockout_until = now + RATE_LIMIT_LOCKOUT_SECONDS
        _login_attempts[ip] = (count, window_start, lockout_until)
        return False, RATE_LIMIT_LOCKOUT_SECONDS


def _record_login_attempt(ip: str, success: bool):
    """Record a login attempt for rate limiting."""
    now = time.time()
    
    with _rate_limit_lock:
        count, window_start, lockout_until = _login_attempts[ip]
        
        if success:
            # Reset on successful login
            _login_attempts[ip] = (0, 0.0, 0.0)
        else:
            # Increment failed attempts
            if now - window_start > RATE_LIMIT_WINDOW_SECONDS:
                # New window
                _login_attempts[ip] = (1, now, lockout_until)
            else:
                _login_attempts[ip] = (count + 1, window_start, lockout_until)


# =============================================================================
# Cookie Security Configuration
# =============================================================================

def _is_secure_context() -> bool:
    """
    Determine if we should use secure cookies.
    Returns True if HTTPS or if MEDAUDIT_SECURE_COOKIES env var is set.
    """
    # Allow forcing secure cookies via environment variable
    if os.environ.get("MEDAUDIT_SECURE_COOKIES", "").lower() in ("1", "true", "yes"):
        return True
    # In production, you'd also check the request scheme, but for local dev we default to False
    return False


class LoginRequest(BaseModel):
    """Login request schema."""
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    """Password change request schema."""
    current_password: str
    new_password: str


class CreateUserRequest(BaseModel):
    """Admin user creation request schema (localhost only)."""
    username: str
    password: str
    full_name: Optional[str] = None
    is_admin: bool = False


def get_session_token(request: Request) -> Optional[str]:
    """Extract session token from cookie or header."""
    # Try cookie first
    token = request.cookies.get("session_token")
    if token:
        return token
    
    # Try Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header[7:]
    
    return None


def get_current_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    """Get current authenticated user from session."""
    token = get_session_token(request)
    if not token:
        return None
    
    session = db.query(UserSession).filter(
        UserSession.token == token,
        UserSession.is_active == True
    ).first()
    
    if not session or not session.is_valid():
        # Clean up invalid session
        if session:
            session.is_active = False
            db.commit()
        return None
    
    return session.user


def require_auth(request: Request, db: Session = Depends(get_db)) -> User:
    """Require authentication - raises 401 if not authenticated."""
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


@router.post("/login")
async def login(
    login_request: LoginRequest, 
    request: Request,
    response: Response, 
    db: Session = Depends(get_db)
):
    """Authenticate admin user and create session."""
    # Get client IP for rate limiting
    client_ip = _get_client_ip(request)
    
    # Check rate limiting
    is_allowed, lockout_seconds = _check_rate_limit(client_ip)
    if not is_allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Too many login attempts. Try again in {lockout_seconds} seconds.",
            headers={"Retry-After": str(lockout_seconds)}
        )
    
    # Find user by username or email
    user = db.query(User).filter(
        (User.username == login_request.username) | (User.email == login_request.username)
    ).first()
    
    if not user or not user.verify_password(login_request.password):
        # Record failed attempt
        _record_login_attempt(client_ip, success=False)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not user.is_active:
        _record_login_attempt(client_ip, success=False)
        raise HTTPException(status_code=401, detail="Account is disabled")
    
    # Record successful login (resets rate limit)
    _record_login_attempt(client_ip, success=True)
    
    # Invalidate all previous sessions for this user (single session only)
    db.query(UserSession).filter(
        UserSession.user_id == user.id,
        UserSession.is_active == True
    ).update({"is_active": False})
    
    # Create new session
    session = UserSession(
        user_id=user.id,
        token=UserSession.create_token(),
        expires_at=datetime.utcnow() + timedelta(hours=SESSION_DURATION_HOURS)
    )
    db.add(session)
    
    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()
    
    # Set cookie with security flags
    response.set_cookie(
        key="session_token",
        value=session.token,
        httponly=True,
        secure=_is_secure_context(),  # Only send over HTTPS when in secure mode
        max_age=SESSION_DURATION_HOURS * 3600,
        samesite="lax"
    )
    
    # Check if this is the first login (password not yet changed from default)
    if user.password_changed_at is None:
        # Force password change on first login
        return {
            "success": True,
            "user": user.to_dict(),
            "redirect": "/change-password-first-login"
        }
    
    # SECURITY: Do not return token in response body - only in httpOnly cookie
    return {
        "success": True,
        "user": user.to_dict(),
        "redirect": "/dashboard"
    }


@router.post("/logout")
async def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    """Logout and completely revoke session."""
    token = get_session_token(request)
    if token:
        # Find and deactivate the session
        session = db.query(UserSession).filter(UserSession.token == token).first()
        if session:
            session.is_active = False
            db.commit()
    
    # Clear the cookie
    response.delete_cookie("session_token", path="/")
    return {"success": True, "message": "Logged out successfully"}


@router.get("/me")
async def get_me(user: User = Depends(require_auth)):
    """Get current user info."""
    return {"user": user.to_dict()}


@router.get("/check")
async def check_auth(request: Request, db: Session = Depends(get_db)):
    """Check if user is authenticated."""
    user = get_current_user(request, db)
    if user:
        return {"authenticated": True, "user": user.to_dict()}
    return {"authenticated": False}


@router.post("/change-password")
async def change_password(
    request: ChangePasswordRequest,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Change current user's password."""
    # Verify current password
    if not user.verify_password(request.current_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    # Validate new password strength
    if len(request.new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters")
    
    # Update password and mark as changed
    user.set_password(request.new_password)
    user.password_changed_at = datetime.utcnow()
    db.commit()
    
    return {
        "success": True,
        "message": "Password changed successfully"
    }


@router.post("/create-user")
async def create_user(
    request_data: CreateUserRequest,
    http_request: Request,
    db: Session = Depends(get_db)
):
    """Create user account - only accessible from localhost."""
    client_ip = _get_client_ip(http_request)
    
    # Only allow from localhost
    if client_ip not in ['127.0.0.1', '::1', 'localhost']:
        raise HTTPException(
            status_code=403, 
            detail="User creation is only allowed from localhost"
        )
    
    # Check if username already exists
    existing_user = db.query(User).filter(
        User.username == request_data.username
    ).first()
    
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken")
    
    # Validate password strength
    if len(request_data.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    
    # Create new user
    new_user = User(
        username=request_data.username,
        email=f"{request_data.username}@medaudit.local",
        full_name=request_data.full_name,
        is_active=True,
        is_admin=request_data.is_admin
    )
    new_user.set_password(request_data.password)
    
    db.add(new_user)
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail=f"Username '{request_data.username}' conflicts with an existing account. Please choose a different username."
        )
    db.refresh(new_user)
    
    return {
        "success": True,
        "user": new_user.to_dict(),
        "message": f"User '{request_data.username}' created successfully"
    }


def init_auth(db: Session, password: str = None, generate_random: bool = False):
    """Initialize authentication - create/update admin with specified password."""
    global _admin_password_display
    db_manager = get_db_manager()
    admin, pwd = db_manager.create_or_update_admin(db, password=password, generate_random=generate_random)
    _admin_password_display = pwd
    return admin, pwd


def get_admin_password_display() -> Optional[str]:
    """Get the admin password that was set during initialization."""
    return _admin_password_display
