"""
Medaudit Web Application
FastAPI-based web interface for security auditing of medical devices.
"""

import os
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
import uvicorn

# Import routers
from .auth import router as auth_router, get_current_user, init_auth, get_admin_password_display
from .projects import router as projects_router
from .client_api import router as client_router
from .fuzzer_api import router as fuzzer_router
from .traffic_api import router as traffic_router
from .server_api import router as server_router
from .proxy_api import router as proxy_router
from .ai_api import router as ai_router
from .database import get_db_manager, get_db

# Get the directory where this file is located
BASE_DIR = Path(__file__).parent

# Store password config for startup
_password_config = {"password": None, "generate_random": False}


# =============================================================================
# Security Headers Middleware
# =============================================================================

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all responses.
    
    Headers added:
    - X-Content-Type-Options: Prevent MIME-type sniffing
    - X-Frame-Options: Prevent clickjacking
    - X-XSS-Protection: Enable XSS filtering (legacy browsers)
    - Referrer-Policy: Control referrer information
    - Content-Security-Policy: Restrict resource loading
    - Permissions-Policy: Restrict browser features
    """
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Prevent MIME-type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        
        # XSS protection for legacy browsers
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Control referrer information
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Content Security Policy
        # Allow self for scripts/styles, inline for our templates, and CDN for Bootstrap/icons
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        response.headers["Content-Security-Policy"] = csp
        
        # Restrict browser features
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=()"
        )
        
        return response


app = FastAPI(
    title="Medaudit 2.0",
    description="Medical Device Security Analysis Platform",
    version="2.0.0"
)

# Add security headers middleware
app.add_middleware(SecurityHeadersMiddleware)

# Mount static files
static_dir = BASE_DIR / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Setup templates
templates_dir = BASE_DIR / "templates"
templates_dir.mkdir(exist_ok=True)
templates = Jinja2Templates(directory=str(templates_dir))

# Include API routers
app.include_router(auth_router)
app.include_router(projects_router)
app.include_router(client_router)
app.include_router(fuzzer_router)
app.include_router(traffic_router)
app.include_router(server_router)
app.include_router(proxy_router)
app.include_router(ai_router)


@app.on_event("startup")
async def startup_event():
    """Initialize database tables on startup."""
    # Only create tables - admin is already initialized in start_web_server
    db_manager = get_db_manager()
    db_manager.create_tables()


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Root route - redirect to login or dashboard."""
    from .auth import get_session_token
    from .database import get_db_manager
    
    token = get_session_token(request)
    if token:
        # Check if session is valid
        db = get_db_manager().get_session()
        from .database import UserSession
        session = db.query(UserSession).filter(
            UserSession.token == token,
            UserSession.is_active == True
        ).first()
        db.close()
        
        if session and session.is_valid():
            return RedirectResponse(url="/dashboard", status_code=302)
    
    return RedirectResponse(url="/login", status_code=302)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Serve the login page."""
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/change-password-first-login", response_class=HTMLResponse)
async def change_password_first_login_page(request: Request):
    """Serve the forced first-login password change page."""
    return templates.TemplateResponse("change_password_first_login.html", {"request": request})


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    """Serve the main dashboard."""
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/project/{project_id}", response_class=HTMLResponse)
async def project_page(request: Request, project_id: str):
    """Serve the project view page."""
    return templates.TemplateResponse("project.html", {
        "request": request,
        "project_id": project_id
    })


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "medaudit-web", "version": "2.0.0"}


def start_web_server(
    host: str = "0.0.0.0", 
    port: int = 8080,
    admin_password: Optional[str] = None,
    generate_password: bool = False
):
    """
    Start the web server.
    
    Args:
        host: Host to bind to
        port: Port to listen on
        admin_password: Custom password for admin account
        generate_password: If True, generate a random secure password
    """
    global _password_config
    _password_config = {
        "password": admin_password,
        "generate_random": generate_password
    }
    
    # Initialize database and admin before starting
    db_manager = get_db_manager()
    db_manager.create_tables()
    
    db = db_manager.get_session()
    try:
        admin, password = init_auth(
            db,
            password=admin_password,
            generate_random=generate_password
        )
    finally:
        db.close()
    
    # SECURITY: Mask password for display (show only first 4 and last 2 chars)
    if len(password) > 8:
        masked_password = password[:4] + "*" * (len(password) - 6) + password[-2:]
    else:
        masked_password = password[:2] + "*" * (len(password) - 2)
    
    # Display startup message
    print(f"""
╔═══════════════════════════════════════════════════════════╗
║             MEDAUDIT 2.0 - Security Audit Platform        ║
╠═══════════════════════════════════════════════════════════╣
║  Web UI:     http://{host}:{port:<5}                          ║
║  API Docs:   http://{host}:{port:<5}/docs                     ║
║                                                           ║
║  Default Admin Credentials:                               ║
║    Username: admin                                        ║
║    Password: {masked_password:<44}║
║                                                           ║
║  NOTE: Change default password for production use!        ║
║  Use --password or --generate-password flags on startup.  ║
╚═══════════════════════════════════════════════════════════╝
""")
    
    # Print full password once (to stderr to avoid log capture)
    import sys
    print(f"\n  [!] Admin Password: {password}\n", file=sys.stderr)
    
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    start_web_server()
