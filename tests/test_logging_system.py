#!/usr/bin/env python3
"""Test script for logging system functionality"""

from medaudit.config.logging import ProxyLogger
from pathlib import Path

def test_logging():
    logger = ProxyLogger('test_logs')
    
    # Test HTTP request logging
    logger.log_http_request(
        method='POST',
        path='/api/test',
        content_length=9,
        client_ip='192.168.1.1'
    )
    
    # Test HL7 conversion logging
    logger.log_hl7_conversion(
        original_length=100,
        hl7_length=120,
        hl7_message_start='MSH|^~\\&|TEST|LAB|EHR|HOSP|202601251200||ADT^A01|MSG123|P|2.5'
    )
    
    # Test HL7 response logging
    logger.log_hl7_response(
        status='success',
        response_length=20,
        hl7_ack=b'MSA|AA|MSG123'
    )
    
    # Test proxy error logging
    logger.log_error(
        message='Test error message'
    )
    
    print('✓ Logging test completed successfully!')
    log_dir = Path('test_logs')
    print(f'✓ Log directory: {log_dir.resolve()}')
    
    for file in sorted(log_dir.rglob('*.jsonl')):
        print(f'  - {file.relative_to(".")}')
        with open(file) as f:
            lines = f.readlines()
            print(f'    {len(lines)} log entries')

if __name__ == '__main__':
    test_logging()
