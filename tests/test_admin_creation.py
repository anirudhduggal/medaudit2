#!/usr/bin/env python3
"""
Test script to verify default admin user creation.
"""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

# Import only the database module directly (avoid importing web app dependencies)
from medaudit.web import database

def test_admin_creation():
    """Test that admin user is created with correct credentials."""
    
    # Use a test database path
    test_db_path = Path(__file__).parent / "test_admin.db"
    
    # Remove existing test database
    if test_db_path.exists():
        test_db_path.unlink()
        print(f"✓ Removed existing test database")
    
    # Create database manager with test database
    db_manager = database.DatabaseManager(db_path=test_db_path)
    db_manager.create_tables()
    print(f"✓ Created database tables")
    
    # Create admin with default credentials
    session = db_manager.get_session()
    try:
        admin, password = db_manager.create_or_update_admin(session)
        print(f"✓ Created admin user")
        print(f"  - Username: {admin.username}")
        print(f"  - Password: {password}")
        print(f"  - Is Admin: {admin.is_admin}")
        print(f"  - Email: {admin.email}")
        
        # Verify credentials
        assert admin.username == "admin", f"Expected username 'admin', got '{admin.username}'"
        assert password == "admin123", f"Expected password 'admin123', got '{password}'"
        assert admin.is_admin == True, f"Expected is_admin=True, got {admin.is_admin}"
        
        # Test password verification
        assert admin.verify_password("admin123"), "Password verification failed!"
        assert not admin.verify_password("wrongpassword"), "Password verification should fail for wrong password"
        
        print(f"\n✓ All tests passed!")
        print(f"\n✅ Default admin credentials:")
        print(f"   Username: admin")
        print(f"   Password: admin123")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        session.close()
        # Cleanup test database
        if test_db_path.exists():
            test_db_path.unlink()
            print(f"\n✓ Cleaned up test database")

if __name__ == "__main__":
    success = test_admin_creation()
    sys.exit(0 if success else 1)
