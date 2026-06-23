#!/usr/bin/env python3
"""
Test script to verify default admin user creation.
"""

import sys
import os
import tempfile
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

# Import only the database module directly (avoid importing web app dependencies)
from medaudit.web import database

def test_admin_creation():
    """Test that admin user is created with correct credentials."""
    
    # Use a temp directory so we always have write permission
    with tempfile.TemporaryDirectory() as tmp_dir:
        test_db_path = Path(tmp_dir) / "test_admin.db"

        # Create database manager with test database
        db_manager = database.DatabaseManager(db_path=test_db_path)
        db_manager.create_tables()
        print(f"✓ Created database tables")
        
        # Create admin with an explicit known password
        test_password = "TestAdminPass456!"
        session = db_manager.get_session()
        try:
            admin, returned_password = db_manager.create_or_update_admin(session, password=test_password)
            print(f"✓ Created admin user")
            print(f"  - Username: {admin.username}")
            print(f"  - Is Admin: {admin.is_admin}")
            print(f"  - Email: {admin.email}")
            
            # Verify structure
            assert admin.username == "admin", f"Expected username 'admin', got '{admin.username}'"
            assert returned_password == test_password, \
                f"Expected returned_password to match input '{test_password}', got '{returned_password}'"
            assert admin.is_admin == True, f"Expected is_admin=True, got {admin.is_admin}"
            
            # Test password verification
            assert admin.verify_password(test_password), "Password verification failed!"
            assert not admin.verify_password("wrongpassword"), \
                "Password verification should fail for wrong password"
            
            # Test random password generation (no explicit password passed)
            admin2, random_pwd = db_manager.create_or_update_admin(session, generate_random=True)
            assert len(random_pwd) >= 16, f"Generated password too short: {len(random_pwd)} chars"
            assert admin2.verify_password(random_pwd), "Random password verification failed!"
            
            print(f"\n✓ All tests passed!")
            return True
            
        except Exception as e:
            print(f"\n❌ Test failed: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            session.close()
            # Explicitly dispose the engine to release the SQLite file lock on Windows
            db_manager.engine.dispose()

if __name__ == "__main__":
    success = test_admin_creation()
    sys.exit(0 if success else 1)
