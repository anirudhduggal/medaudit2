"""
Authentication module for Medaudit Web Application.
Handles user login, registration, and session management.
"""

from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, EmailStr, validator
from sqlalchemy.orm import Session

from .database import get_db, User, UserSession, get_db_manager

router = APIRouter(prefix="/auth", tags=["authentication"])

# Session duration
SESSION_DURATION_HOURS = 24


class LoginRequest(BaseModel):
    """Login request schema."""
    username: str
    password: str


class RegisterRequest(BaseModel):
    """Registration request schema."""
    username: str
    email: str
    password: str
    full_name: Optional[str] = None

    @validator('username')
    def username_valid(cls, v):
        if len(v) < 3:
            raise ValueError('Username must be at least 3 characters')
        if not v.isalnum() and '_' not in v:
            raise ValueError('Username can only contain letters, numbers, and underscores')
        return v.lower()

    @validator('password')
    def password_valid(cls, v):
        if len(v) < 6:
            raise ValueError('Password must be at least 6 characters')
        return v


class UserResponse(BaseModel):
    """User response schema."""
    id: str
    username: str
    email: str
    full_name: Optional[str]
    is_admin: bool


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
        return None
    
    return session.user


def require_auth(request: Request, db: Session = Depends(get_db)) -> User:
    """Require authentication - raises 401 if not authenticated."""
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def require_admin(request: Request, db: Session = Depends(get_db)) -> User:
    """Require admin authentication."""
    user = require_auth(request, db)
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


@router.post("/login")
async def login(request: LoginRequest, response: Response, db: Session = Depends(get_db)):
    """Authenticate user and create session."""
    # Find user
    user = db.query(User).filter(
        (User.username == request.username.lower()) | 
        (User.email == request.username.lower())
    ).first()
    
    if not user or not user.verify_password(request.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    if not user.is_active:
        raise HTTPException(status_code=401, detail="Account is disabled")
    
    # Create session
    session = UserSession(
        user_id=user.id,
        token=UserSession.create_token(),
        expires_at=datetime.utcnow() + timedelta(hours=SESSION_DURATION_HOURS)
    )
    db.add(session)
    
    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()
    
    # Set cookie
    response.set_cookie(
        key="session_token",
        value=session.token,
        httponly=True,
        max_age=SESSION_DURATION_HOURS * 3600,
        samesite="lax"
    )
    
    return {
        "success": True,
        "user": user.to_dict(),
        "token": session.token
    }


@router.post("/register")
async def register(request: RegisterRequest, response: Response, db: Session = Depends(get_db)):
    """Register a new user."""
    # Check if username exists
    if db.query(User).filter(User.username == request.username.lower()).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Check if email exists
    if db.query(User).filter(User.email == request.email.lower()).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    user = User(
        username=request.username.lower(),
        email=request.email.lower(),
        full_name=request.full_name
    )
    user.set_password(request.password)
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Auto-login after registration
    session = UserSession(
        user_id=user.id,
        token=UserSession.create_token(),
        expires_at=datetime.utcnow() + timedelta(hours=SESSION_DURATION_HOURS)
    )
    db.add(session)
    db.commit()
    
    response.set_cookie(
        key="session_token",
        value=session.token,
        httponly=True,
        max_age=SESSION_DURATION_HOURS * 3600,
        samesite="lax"
    )
    
    return {
        "success": True,
        "user": user.to_dict(),
        "token": session.token
    }


@router.post("/logout")
async def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    """Logout and invalidate session."""
    token = get_session_token(request)
    if token:
        session = db.query(UserSession).filter(UserSession.token == token).first()
        if session:
            session.is_active = False
            db.commit()
    
    response.delete_cookie("session_token")
    return {"success": True}


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


# Initialize default admin on startup
def init_auth(db: Session):
    """Initialize authentication - create default admin if needed."""
    db_manager = get_db_manager()
    db_manager.create_default_admin(db)
