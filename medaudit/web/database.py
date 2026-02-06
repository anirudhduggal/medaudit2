"""
Database Models for Medaudit Web Application
Uses SQLAlchemy with SQLite for data persistence.
"""

import os
import uuid
from datetime import datetime, timedelta
from typing import Optional, List
from pathlib import Path

from sqlalchemy import create_engine, Column, String, DateTime, Boolean, Text, Integer, ForeignKey, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
import hashlib
import secrets
import hmac

# Import centralized paths
from medaudit.paths import get_database_path, DATABASE_PATH

# Password hashing configuration using PBKDF2 (standard library, secure)
PBKDF2_ITERATIONS = 600000  # OWASP recommended minimum for PBKDF2-SHA256
PBKDF2_HASH_NAME = 'sha256'
SALT_LENGTH = 32  # 256 bits


def hash_password(password: str) -> str:
    """
    Hash a password using PBKDF2-SHA256 with secure parameters.
    
    Returns format: iterations$salt$hash (all hex encoded)
    """
    salt = secrets.token_bytes(SALT_LENGTH)
    password_hash = hashlib.pbkdf2_hmac(
        PBKDF2_HASH_NAME,
        password.encode('utf-8'),
        salt,
        PBKDF2_ITERATIONS
    )
    return f"{PBKDF2_ITERATIONS}${salt.hex()}${password_hash.hex()}"


def verify_password(password: str, hashed: str) -> bool:
    """
    Verify a password against a PBKDF2 hash.
    Uses constant-time comparison to prevent timing attacks.
    """
    try:
        parts = hashed.split('$')
        if len(parts) != 3:
            return False
        
        iterations = int(parts[0])
        salt = bytes.fromhex(parts[1])
        stored_hash = bytes.fromhex(parts[2])
        
        # Compute hash of provided password
        computed_hash = hashlib.pbkdf2_hmac(
            PBKDF2_HASH_NAME,
            password.encode('utf-8'),
            salt,
            iterations
        )
        
        # Constant-time comparison to prevent timing attacks
        return hmac.compare_digest(computed_hash, stored_hash)
    except (ValueError, TypeError):
        return False

# Database setup
Base = declarative_base()

# Default database path (from centralized paths module)
DEFAULT_DB_PATH = DATABASE_PATH


def get_database_url(db_path: Optional[Path] = None) -> str:
    """Get database URL, creating directory if needed."""
    if db_path is None:
        db_path = get_database_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{db_path}"


class User(Base):
    """User model for authentication."""
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(100), nullable=True)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

    # Relationships
    projects = relationship("Project", back_populates="owner", cascade="all, delete-orphan")
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")

    def set_password(self, password: str):
        """Hash and set the password."""
        self.password_hash = hash_password(password)

    def verify_password(self, password: str) -> bool:
        """Verify a password against the hash."""
        return verify_password(password, self.password_hash)

    def to_dict(self):
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "is_active": self.is_active,
            "is_admin": self.is_admin,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None
        }


class UserSession(Base):
    """User session for token-based authentication."""
    __tablename__ = "user_sessions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    token = Column(String(64), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True)

    # Relationships
    user = relationship("User", back_populates="sessions")

    @classmethod
    def create_token(cls) -> str:
        """Generate a secure session token."""
        return secrets.token_urlsafe(48)

    def is_valid(self) -> bool:
        """Check if session is still valid."""
        return self.is_active and datetime.utcnow() < self.expires_at


class Project(Base):
    """Project/Workspace for security audits."""
    __tablename__ = "projects"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    owner_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    
    # Engagement details
    engagement_start = Column(DateTime, nullable=True)
    engagement_end = Column(DateTime, nullable=True)
    
    # Project status
    status = Column(String(20), default="active")  # active, completed, archived
    
    # Settings stored as JSON
    settings = Column(JSON, default=dict)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    owner = relationship("User", back_populates="projects")
    pcap_analyses = relationship("PcapAnalysis", back_populates="project", cascade="all, delete-orphan")
    client_sessions = relationship("ClientSession", back_populates="project", cascade="all, delete-orphan")
    fuzzing_jobs = relationship("FuzzingJob", back_populates="project", cascade="all, delete-orphan")
    server_instances = relationship("ServerInstance", back_populates="project", cascade="all, delete-orphan")

    def get_artifacts_path(self, base_path: Path) -> Path:
        """Get the path for project artifacts."""
        path = base_path / "projects" / self.id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def to_dict(self):
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "owner_id": self.owner_id,
            "engagement_start": self.engagement_start.isoformat() if self.engagement_start else None,
            "engagement_end": self.engagement_end.isoformat() if self.engagement_end else None,
            "status": self.status,
            "settings": self.settings or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "pcap_count": len(self.pcap_analyses) if self.pcap_analyses else 0,
            "fuzzing_jobs_count": len(self.fuzzing_jobs) if self.fuzzing_jobs else 0
        }


class PcapAnalysis(Base):
    """Stored PCAP analysis results."""
    __tablename__ = "pcap_analyses"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=False)
    filename = Column(String(255), nullable=False)
    file_path = Column(String(500), nullable=True)  # Path to stored PCAP
    file_size = Column(Integer, nullable=True)
    
    # Analysis results stored as JSON
    results = Column(JSON, nullable=True)
    
    # Summary fields for quick access
    total_packets = Column(Integer, default=0)
    hl7_message_count = Column(Integer, default=0)
    pii_count = Column(Integer, default=0)
    encryption_status = Column(String(50), nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    project = relationship("Project", back_populates="pcap_analyses")

    def to_dict(self):
        return {
            "id": self.id,
            "project_id": self.project_id,
            "filename": self.filename,
            "file_size": self.file_size,
            "total_packets": self.total_packets,
            "hl7_message_count": self.hl7_message_count,
            "pii_count": self.pii_count,
            "encryption_status": self.encryption_status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "results": self.results
        }


class ClientSession(Base):
    """HL7 Client session for manual interaction with devices."""
    __tablename__ = "client_sessions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=False)
    
    # Target device
    target_host = Column(String(255), nullable=False)
    target_port = Column(Integer, default=2575)
    use_tls = Column(Boolean, default=False)
    
    # Session status
    status = Column(String(20), default="disconnected")  # connected, disconnected, error
    
    # Message history stored as JSON array
    message_history = Column(JSON, default=list)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    project = relationship("Project", back_populates="client_sessions")

    def add_message(self, direction: str, message: str, response: str = None, error: str = None):
        """Add a message to history."""
        history = self.message_history or []
        history.append({
            "timestamp": datetime.utcnow().isoformat(),
            "direction": direction,  # "sent" or "received"
            "message": message[:2000],  # Truncate long messages
            "response": response[:2000] if response else None,
            "error": error
        })
        # Keep last 500 messages
        self.message_history = history[-500:]

    def to_dict(self):
        return {
            "id": self.id,
            "project_id": self.project_id,
            "target_host": self.target_host,
            "target_port": self.target_port,
            "use_tls": self.use_tls,
            "status": self.status,
            "message_count": len(self.message_history) if self.message_history else 0,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class FuzzingJob(Base):
    """Fuzzing job configuration and results."""
    __tablename__ = "fuzzing_jobs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=False)
    name = Column(String(100), nullable=False)
    
    # Target
    target_host = Column(String(255), nullable=False)
    target_port = Column(Integer, default=2575)
    use_tls = Column(Boolean, default=False)
    
    # Fuzzing configuration (YAML/JSON stored as text)
    config_format = Column(String(10), default="yaml")  # yaml or json
    config_content = Column(Text, nullable=True)
    
    # Status and progress
    status = Column(String(20), default="pending")  # pending, running, paused, completed, error
    progress = Column(Integer, default=0)  # 0-100
    total_requests = Column(Integer, default=0)
    successful_requests = Column(Integer, default=0)
    error_requests = Column(Integer, default=0)
    interesting_findings = Column(Integer, default=0)
    
    # Results stored as JSON
    results = Column(JSON, default=list)
    findings = Column(JSON, default=list)
    
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    project = relationship("Project", back_populates="fuzzing_jobs")

    def to_dict(self):
        return {
            "id": self.id,
            "project_id": self.project_id,
            "name": self.name,
            "target_host": self.target_host,
            "target_port": self.target_port,
            "use_tls": self.use_tls,
            "config_format": self.config_format,
            "status": self.status,
            "progress": self.progress,
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "error_requests": self.error_requests,
            "interesting_findings": self.interesting_findings,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class ServerInstance(Base):
    """Mock HL7 server instance configuration."""
    __tablename__ = "server_instances"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=False)
    name = Column(String(100), nullable=False)
    
    # Server configuration
    host = Column(String(255), default="0.0.0.0")
    port = Column(Integer, default=2575)
    use_tls = Column(Boolean, default=False)
    cert_path = Column(String(500), nullable=True)
    key_path = Column(String(500), nullable=True)
    
    # Status
    status = Column(String(20), default="stopped")  # stopped, running, error
    pid = Column(Integer, nullable=True)  # Process ID when running
    
    # Message log stored as JSON
    message_log = Column(JSON, default=list)
    total_connections = Column(Integer, default=0)
    total_messages = Column(Integer, default=0)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)

    # Relationships
    project = relationship("Project", back_populates="server_instances")

    def add_message_log(self, event_type: str, data: dict):
        """Add an entry to the message log."""
        log = self.message_log or []
        log.append({
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "data": data
        })
        # Keep last 1000 entries
        self.message_log = log[-1000:]

    def to_dict(self, include_logs: bool = False):
        result = {
            "id": self.id,
            "project_id": self.project_id,
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "use_tls": self.use_tls,
            "status": self.status,
            "total_connections": self.total_connections,
            "total_messages": self.total_messages,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None
        }
        if include_logs:
            result["message_log"] = self.message_log or []
        return result


# Database session management
class DatabaseManager:
    """Manages database connections and sessions."""
    
    def __init__(self, db_path: Optional[Path] = None):
        self.db_url = get_database_url(db_path)
        self.engine = create_engine(self.db_url, echo=False)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        
    def create_tables(self):
        """Create all tables."""
        Base.metadata.create_all(bind=self.engine)
        
    def get_session(self) -> Session:
        """Get a new database session."""
        return self.SessionLocal()
    
    def create_or_update_admin(self, session: Session, password: str = None, generate_random: bool = False):
        """
        Create or update admin user with specified password.
        
        Security: No default password. Must either provide a password or set generate_random=True.
        """
        import secrets
        import string
        
        # Generate random password if requested or if no password provided
        # SECURITY: Never use a weak default password
        if generate_random or password is None:
            # Generate a cryptographically secure random password
            # 20 chars from alphanumeric + special = ~130 bits of entropy
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
            password = ''.join(secrets.choice(alphabet) for _ in range(20))
        
        admin = session.query(User).filter(User.username == "admin").first()
        
        if admin is None:
            admin = User(
                username="admin",
                email="admin@medaudit.local",
                full_name="Administrator",
                is_admin=True
            )
            session.add(admin)
        
        admin.set_password(password)
        session.commit()
        session.refresh(admin)  # Ensure changes are persisted
        
        return admin, password


# Global database manager instance
_db_manager: Optional[DatabaseManager] = None


def get_db_manager() -> DatabaseManager:
    """Get or create the database manager."""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
        _db_manager.create_tables()
    return _db_manager


def get_db() -> Session:
    """Get a database session (for use as dependency)."""
    db = get_db_manager().get_session()
    try:
        yield db
    finally:
        db.close()
