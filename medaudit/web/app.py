"""
Medaudit Web Application
FastAPI-based web interface for PCAP analysis and HL7 traffic inspection.
"""

import os
import tempfile
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn

from .analyzer import analyze_pcap_detailed

# Get the directory where this file is located
BASE_DIR = Path(__file__).parent

app = FastAPI(
    title="Medaudit 2.0",
    description="Medical Device Security Analysis Tool",
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


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Serve the main page."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/analyze")
async def analyze_pcap(file: UploadFile = File(...)):
    """
    Analyze an uploaded PCAP file.
    
    Returns:
        JSON with encryption status, HL7 messages, and PII findings.
    """
    # Validate file extension
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    
    valid_extensions = ['.pcap', '.pcapng', '.cap']
    file_ext = Path(file.filename).suffix.lower()
    if file_ext not in valid_extensions:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid file type. Accepted types: {', '.join(valid_extensions)}"
        )
    
    # Save uploaded file to temp location
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as tmp:
            content = await file.read()
            tmp.write(content)
            tmp_path = tmp.name
        
        # Analyze the PCAP file
        results = analyze_pcap_detailed(tmp_path)
        
        return JSONResponse(content=results)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    
    finally:
        # Cleanup temp file
        if 'tmp_path' in locals() and os.path.exists(tmp_path):
            os.unlink(tmp_path)


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "medaudit-web"}


def start_web_server(host: str = "0.0.0.0", port: int = 8080):
    """Start the web server."""
    print(f"Starting Medaudit Web UI at http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    start_web_server()
