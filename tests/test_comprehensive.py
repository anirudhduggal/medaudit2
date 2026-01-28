#!/usr/bin/env python3
"""Comprehensive test suite for Medaudit 2.0 project"""

import sys
from pathlib import Path

def test_imports():
    """Test that all modules can be imported"""
    print("\n" + "="*60)
    print("TEST 1: Module Imports")
    print("="*60)
    
    try:
        import medaudit
        print("✓ medaudit")
        
        import medaudit.config
        print("✓ medaudit.config")
        
        import medaudit.logging
        print("✓ medaudit.logging")
        
        import medaudit.analysis
        print("✓ medaudit.analysis")
        
        import medaudit.analysis.traffic
        print("✓ medaudit.analysis.traffic")
        
        import medaudit.analysis.pii
        print("✓ medaudit.analysis.pii")
        
        import medaudit.proxy
        print("✓ medaudit.proxy")
        
        return True
    except ImportError as e:
        print(f"✗ Import failed: {e}")
        return False

def test_config():
    """Test configuration loading"""
    print("\n" + "="*60)
    print("TEST 2: Configuration System")
    print("="*60)
    
    try:
        from medaudit.config import config
        
        # Check proxy config
        proxy_config = config.get_proxy_config()
        assert "http_port" in proxy_config
        assert "hl7_host" in proxy_config
        assert "hl7_port" in proxy_config
        print(f"✓ Proxy config loaded: port={proxy_config['http_port']}")
        
        # Check logging config
        logging_config = config.get_logging_config()
        assert "enabled" in logging_config
        assert "log_dir" in logging_config
        print(f"✓ Logging config loaded: enabled={logging_config['enabled']}, log_dir={logging_config['log_dir']}")
        
        # Check full config structure
        assert "analysis" in config.config
        print(f"✓ Full configuration valid: {len(config.config)} sections")
        
        return True
    except Exception as e:
        print(f"✗ Config test failed: {e}")
        return False

def test_logging():
    """Test logging system"""
    print("\n" + "="*60)
    print("TEST 3: Logging System")
    print("="*60)
    
    try:
        from medaudit.logging import ProxyLogger
        from pathlib import Path
        import json
        
        # Create logger with test directory
        test_log_dir = Path('test_logs_comprehensive')
        logger = ProxyLogger(str(test_log_dir))
        
        # Log HTTP request
        logger.log_http_request(
            method='POST',
            path='/test',
            headers={'Content-Type': 'text/plain'},
            body='test',
            client_ip='127.0.0.1'
        )
        print("✓ HTTP request logged")
        
        # Log HL7 conversion
        logger.log_hl7_conversion(
            'test data',
            'MSH|^~\\&|TEST|LAB|EHR|HOSP|202601271200||ADT^A01|MSG001|P|2.5'
        )
        print("✓ HL7 conversion logged")
        
        # Log HL7 response
        logger.log_hl7_response(
            hl7_host='localhost',
            hl7_port=2575,
            response='MSA|AA|MSG001',
            success=True
        )
        print("✓ HL7 response logged")
        
        # Log proxy error
        logger.log_proxy_error(
            error_type='test_error',
            error_message='Test error'
        )
        print("✓ Proxy error logged")
        
        # Verify files created
        jsonl_files = list(test_log_dir.rglob('*.jsonl'))
        assert len(jsonl_files) > 0, "No log files created"
        print(f"✓ Log files created: {len(jsonl_files)} files")
        
        # Clean up
        import shutil
        shutil.rmtree(test_log_dir, ignore_errors=True)
        
        return True
    except Exception as e:
        print(f"✗ Logging test failed: {e}")
        return False

def test_traffic_analysis():
    """Test traffic analysis module"""
    print("\n" + "="*60)
    print("TEST 4: Traffic Analysis")
    print("="*60)
    
    try:
        from medaudit.analysis.traffic.traffic_analysis import is_hl7_message
        
        # Test HL7 detection
        hl7_payload = b"MSH|^~\\&|LABSYS|HOSPITAL|EHR|HOSPITAL|202601251200||ADT^A01|MSG00001|P|2.5"
        is_hl7, header = is_hl7_message(hl7_payload)
        assert is_hl7, "Failed to detect HL7 message"
        print(f"✓ HL7 detection working: {header[:50]}...")
        
        # Test non-HL7 payload
        non_hl7 = b"This is just regular data"
        is_hl7, header = is_hl7_message(non_hl7)
        assert not is_hl7, "False positive HL7 detection"
        print("✓ Non-HL7 payloads correctly rejected")
        
        return True
    except Exception as e:
        print(f"✗ Traffic analysis test failed: {e}")
        return False

def test_pcap_analysis():
    """Test PCAP file analysis"""
    print("\n" + "="*60)
    print("TEST 5: PCAP File Analysis")
    print("="*60)
    
    try:
        from scapy.all import rdpcap, Raw
        
        pcap_file = Path('medaudit/testFiles/hl7_v2_unencrypted_synthetic.pcap')
        if not pcap_file.exists():
            print(f"⚠ PCAP file not found: {pcap_file}")
            return True
        
        packets = rdpcap(str(pcap_file))
        print(f"✓ PCAP loaded: {len(packets)} packet(s)")
        
        raw_packets = [p for p in packets if Raw in p]
        print(f"✓ Raw packets found: {len(raw_packets)}")
        
        if raw_packets:
            for i, pkt in enumerate(raw_packets):
                payload_size = len(pkt[Raw].load)
                print(f"  - Packet {i}: {payload_size} bytes")
        
        return True
    except Exception as e:
        print(f"✗ PCAP analysis test failed: {e}")
        return False

def test_proxy_server():
    """Test proxy server module imports"""
    print("\n" + "="*60)
    print("TEST 6: Proxy Server Module")
    print("="*60)
    
    try:
        from medaudit.proxy import proxy_server
        from medaudit.proxy.proxy_server import HL7ProxyHandler
        
        # Check that handler class exists and has required methods
        assert hasattr(HL7ProxyHandler, 'do_POST'), "HL7ProxyHandler missing do_POST method"
        print("✓ HL7ProxyHandler class valid")
        
        assert hasattr(proxy_server, 'start_proxy'), "proxy_server missing start_proxy function"
        print("✓ start_proxy function exists")
        
        return True
    except Exception as e:
        print(f"✗ Proxy server test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("MEDAUDIT 2.0 - COMPREHENSIVE TEST SUITE")
    print("="*60)
    
    results = []
    
    results.append(("Module Imports", test_imports()))
    results.append(("Configuration System", test_config()))
    results.append(("Logging System", test_logging()))
    results.append(("Traffic Analysis", test_traffic_analysis()))
    results.append(("PCAP Analysis", test_pcap_analysis()))
    results.append(("Proxy Server Module", test_proxy_server()))
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    print("-"*60)
    print(f"Total: {passed}/{total} tests passed")
    print("="*60 + "\n")
    
    return 0 if passed == total else 1

if __name__ == '__main__':
    sys.exit(main())
