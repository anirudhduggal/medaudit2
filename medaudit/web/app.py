"""
Medaudit Web Application
FastAPI-based web interface for security auditing of medical devices.
"""

import os
from pathlib import Path
from fastapi import FastAPI, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn

# Import routers
from .auth import router as auth_router, get_current_user, init_auth
from .projects import router as projects_router
from .client_api import router as client_router
from .fuzzer_api import router as fuzzer_router
from .traffic_api import router as traffic_router
from .server_api import router as server_router
from .export_api import router as export_router
from .database import get_db_manager, get_db

# Get the directory where this file is located
BASE_DIR = Path(__file__).parent

app = FastAPI(
    title="Medaudit 2.0",
    description="Medical Device Security Analysis Platform",
    version="2.0.0"
)

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
app.include_router(export_router)


@app.on_event("startup")
async def startup_event():
    """Initialize database and create default admin on startup."""
    db_manager = get_db_manager()
    db_manager.create_tables()
    
    # Create default admin
    db = db_manager.get_session()
    try:
        init_auth(db)
    finally:
        db.close()


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


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    """Serve the registration page."""
    return templates.TemplateResponse("register.html", {"request": request})


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


def start_web_server(host: str = "0.0.0.0", port: int = 8080):
    """Start the web server."""
    print(f"""
╔═══════════════════════════════════════════════════════════╗
║             MEDAUDIT 2.0 - Security Audit Platform        ║
╠═══════════════════════════════════════════════════════════╣
║  Web UI:     http://{host}:{port}                            
║  API Docs:   http://{host}:{port}/docs                       
║                                                           ║
║  Default Login:  admin / admin123                         ║
║  (Please change the password after first login)          ║
╚═══════════════════════════════════════════════════════════╝
""")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    start_web_server()
