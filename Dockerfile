# =============================================================================
# Medaudit 2.0 - Multi-architecture Docker Image
# Supports: linux/amd64 (Intel/AMD) and linux/arm64 (Apple Silicon, AWS Graviton)
# =============================================================================

FROM python:3.11-slim AS base

# Metadata
LABEL maintainer="securient"
LABEL org.opencontainers.image.source="https://github.com/securient/medaudit2"
LABEL org.opencontainers.image.description="Medical Device Security Audit Platform"

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies required by scapy, pyshark, and spacy
RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    libpcap-dev \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r medaudit && useradd -r -g medaudit -d /app -s /sbin/nologin medaudit

WORKDIR /app

# ---------- Dependency installation (cached layer) ----------
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download spacy model
RUN python -m spacy download en_core_web_lg

# ---------- Application code ----------
COPY . .

# Create runtime directories and set ownership
RUN mkdir -p medaudit/data medaudit/logs medaudit/config \
    && chown -R medaudit:medaudit /app

# Switch to non-root user
USER medaudit

# Expose default web UI port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/api/health')" || exit 1

# Default command: start web UI with auto-generated password
ENTRYPOINT ["python", "-m", "medaudit", "web"]
CMD ["--host", "0.0.0.0", "--port", "8080", "--generate-password"]
