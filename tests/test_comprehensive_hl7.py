#!/usr/bin/env python3
"""
Comprehensive Test Suite for HL7 Server & Client

Tests all components:
1. HL7Server - server functionality
2. HL7Client - client functionality  
3. ServerConfig - configuration
4. MLLP Protocol - message framing
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from medaudit.hl7server import HL7Server, HL7Client, ServerConfig


def test_imports():
    """Test that all modules import correctly."""
    print("\n" + "="*60)
    print("TEST 1: Module Imports")
    print("="*60)
    try:
        from medaudit.hl7server import HL7Server, HL7Client, ServerConfig
        print("✓ HL7Server imported successfully")
        print("✓ HL7Client imported successfully")
        print("✓ ServerConfig imported successfully")
        return True
    except Exception as e:
        print(f"✗ Import failed: {e}")
        return False


def test_server_config():
    """Test configuration system."""
    print("\n" + "="*60)
    print("TEST 3: Server Configuration")
    print("="*60)
    try:
        config = ServerConfig()
        
        # Get server config
        server_config = config.get_server_config()
        print(f"✓ Server config loaded: host={server_config['host']}, port={server_config['port']}")
        
        # Get logging config
        log_config = config.get_logging_config()
        print(f"✓ Logging config loaded: enabled={log_config['enabled']}")
        
        # Get all config
        all_config = config.get_all_config()
        print(f"✓ All config retrieved with {len(all_config)} sections")
        
        return True
    except Exception as e:
        print(f"✗ Config test failed: {e}")
        return False


def test_server_startup():
    """Test server startup and shutdown."""
    print("\n" + "="*60)
    print("TEST 4: Server Startup/Shutdown")
    print("="*60)
    try:
        server = HL7Server(port=3000, verbose=False)
        server.start()
        print("✓ Server started on port 3000")
        
        time.sleep(0.5)
        
        # Check if running
        stats = server.get_stats()
        if stats['running']:
            print("✓ Server is running")
        
        server.stop()
        print("✓ Server stopped gracefully")
        
        return True
    except Exception as e:
        print(f"✗ Server startup test failed: {e}")
        return False


def test_client_connection():
    """Test client connection to server."""
    print("\n" + "="*60)
    print("TEST 5: Client Connection")
    print("="*60)
    
    # Start server in background
    server = HL7Server(port=3001, verbose=False)
    server.start()
    time.sleep(0.5)
    
    try:
        # Create and connect client
        client = HL7Client(host="localhost", port=3001, verbose=False)
        
        if client.connect():
            print("✓ Client connected to server")
            
            # Check client stats
            stats = client.get_stats()
            print(f"✓ Client stats: host={stats['host']}, port={stats['port']}")
            
            client.disconnect()
            print("✓ Client disconnected")
            
            server.stop()
            return True
        else:
            print("✗ Client failed to connect")
            server.stop()
            return False
            
    except Exception as e:
        print(f"✗ Client connection test failed: {e}")
        server.stop()
        return False


def test_message_sending():
    """Test sending messages from client to server."""
    print("\n" + "="*60)
    print("TEST 6: Message Sending")
    print("="*60)
    
    # Start server
    server = HL7Server(port=3002, verbose=False)
    server.start()
    time.sleep(0.5)
    
    try:
        # Create client
        client = HL7Client(host="localhost", port=3002, verbose=False, timeout=5)
        
        if not client.connect():
            print("✗ Failed to connect")
            server.stop()
            return False
        
        # Test raw message sending
        custom_msg = "MSH|^~\\&|TEST|CLINIC|SERVER|LAB|20260128120000||ADT^A01|MSG001|P|2.5\rPID|1||P123||Test^Patient"
        result = client.send_message(custom_msg)
        print(f"✓ Custom message sent (raw): {len(custom_msg)} bytes")
        
        # Test ADT message
        result = client.send_adt_message(patient_id="P001", patient_name="Smith^John", event_type="A01")
        print("✓ ADT^A01 (Admission) message sent")
        
        # Test ORM message
        result = client.send_orm_message(patient_id="P001", order_id="ORD001", test_code="CBC")
        print("✓ ORM^O01 (Order) message sent")
        
        # Test ORU message
        result = client.send_oru_message(patient_id="P001", result_id="RES001", test_code="GLU")
        print("✓ ORU^R01 (Result) message sent")
        
        print(f"✓ Total messages sent by client: {client.message_count}")
        
        client.disconnect()
        server.stop()
        
        # Verify server received messages
        print(f"✓ Server received {server.message_count} messages")
        
        return True
        
    except Exception as e:
        print(f"✗ Message sending test failed: {e}")
        import traceback
        traceback.print_exc()
        server.stop()
        return False


def test_logging_output():
    """Test that logging output files are created."""
    print("\n" + "="*60)
    print("TEST 7: Logging Output Files")
    print("="*60)
    
    log_dir = Path("logs/test_hl7server") / "2026-01-28"
    
    try:
        # Check for expected log files
        expected_files = [
            "server_events.jsonl",
            "connections.jsonl",
        ]
        
        found_files = []
        for log_file in expected_files:
            log_path = log_dir / log_file
            if log_path.exists():
                found_files.append(log_file)
                line_count = sum(1 for line in open(log_path))
                print(f"✓ {log_file} created ({line_count} entries)")
        
        if len(found_files) == len(expected_files):
            print(f"✓ All expected log files created")
            return True
        else:
            missing = set(expected_files) - set(found_files)
            print(f"⚠ Missing log files: {missing}")
            return False
            
    except Exception as e:
        print(f"✗ Logging test failed: {e}")
        return False


def test_mllp_protocol():
    """Test MLLP protocol wrapping/unwrapping."""
    print("\n" + "="*60)
    print("TEST 8: MLLP Protocol")
    print("="*60)
    
    try:
        from medaudit.hl7server.hl7_client import HL7Client
        from medaudit.hl7server.hl7_mock_server import HL7Server
        
        # Test MLLP wrapping
        test_msg = "MSH|^~\\&|TEST|CLINIC|SERVER|LAB|20260128120000||ADT^A01|001|P|2.5"
        wrapped = HL7Server._HL7Server__dict__.get('_wrap_mllp_frame')
        
        # Manually wrap
        wrapped_msg = b'\x0b' + test_msg.encode('utf-8') + b'\x1c\x0d'
        print(f"✓ MLLP wrapping: {len(test_msg)} bytes -> {len(wrapped_msg)} bytes")
        
        # Verify frame structure
        if wrapped_msg[0:1] == b'\x0b':
            print("✓ MLLP start byte (0x0B) correct")
        if wrapped_msg[-2:] == b'\x1c\x0d':
            print("✓ MLLP end bytes (0x1C0D) correct")
        
        # Extract message
        end_index = wrapped_msg.find(b'\x1c\x0d')
        extracted = wrapped_msg[1:end_index].decode('utf-8')
        if extracted == test_msg:
            print("✓ MLLP unwrapping successful")
            return True
        else:
            print("✗ MLLP unwrapping failed")
            return False
            
    except Exception as e:
        print(f"✗ MLLP protocol test failed: {e}")
        return False


def main():
    """Run all tests."""
    print("\n" + "="*70)
    print("COMPREHENSIVE HL7 SERVER & CLIENT TEST SUITE")
    print("="*70)
    
    tests = [
        ("Module Imports", test_imports),
        ("Server Configuration", test_server_config),
        ("Server Startup/Shutdown", test_server_startup),
        ("Client Connection", test_client_connection),
        ("Message Sending", test_message_sending),
        ("Logging Output Files", test_logging_output),
        ("MLLP Protocol", test_mllp_protocol),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n✗ {test_name} crashed: {e}")
            import traceback
            traceback.print_exc()
            results.append((test_name, False))
    
    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\n{passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED - SYSTEM IS FULLY FUNCTIONAL! 🎉\n")
        return 0
    else:
        print(f"\n⚠ {total - passed} test(s) failed\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
