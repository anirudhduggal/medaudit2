#!/usr/bin/env python3
"""
Test script for HL7 Server and Client

Demonstrates:
1. Starting an HL7 server
2. Connecting an HL7 client
3. Sending various HL7 messages (ADT, ORM, ORU)
4. Receiving ACK responses
5. Logging messages to files
"""

import sys
import time
import threading
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from medaudit.hl7server import HL7Server, HL7Client


def run_server(port=2575, duration=60):
    """Run server for specified duration."""
    server = HL7Server(
        host="localhost",
        port=port,
        verbose=True
    )
    
    server.start()
    
    # Run for specified duration
    start_time = time.time()
    try:
        while time.time() - start_time < duration:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
        return server


def run_client_tests(host="localhost", port=2575):
    """Run client tests."""
    time.sleep(1)  # Wait for server to start
    
    client = HL7Client(host=host, port=port, verbose=True)
    
    if not client.connect():
        print("Failed to connect to server")
        return
    
    try:
        print("\n" + "="*60)
        print("Test 1: Send ADT^A01 (Admission) Message")
        print("="*60)
        ack = client.send_adt_message(
            patient_id="MED001",
            patient_name="Smith^John",
            event_type="A01"
        )
        if ack:
            print(f"✓ Received ACK\n")
        time.sleep(0.5)

        print("="*60)
        print("Test 2: Send ADT^A03 (Discharge) Message")
        print("="*60)
        ack = client.send_adt_message(
            patient_id="MED002",
            patient_name="Johnson^Jane",
            event_type="A03"
        )
        if ack:
            print(f"✓ Received ACK\n")
        time.sleep(0.5)

        print("="*60)
        print("Test 3: Send ORM (Order) Message")
        print("="*60)
        ack = client.send_orm_message(
            patient_id="MED001",
            order_id="LAB-2024-001",
            test_code="CBC"
        )
        if ack:
            print(f"✓ Received ACK\n")
        time.sleep(0.5)

        print("="*60)
        print("Test 4: Send ORU (Result) Message")
        print("="*60)
        ack = client.send_oru_message(
            patient_id="MED001",
            result_id="RES-2024-001",
            test_code="GLU"
        )
        if ack:
            print(f"✓ Received ACK\n")
        time.sleep(0.5)

        print("="*60)
        print("Test 5: Send Custom HL7 Message")
        print("="*60)
        custom_message = (
            "MSH|^~\\&|CUSTOM_APP|CLINIC|SERVER|LAB|20240101120000||MDM^T02|MSG001|P|2.5\r"
            "PID|1||CUSTOM123||Doe^Custom\r"
            "TXA|1|DOC001|PA|AV|20240101120000"
        )
        ack = client.send_message(custom_message)
        if ack:
            print(f"✓ Received ACK\n")

        print("="*60)
        print("Client Statistics")
        print("="*60)
        print(f"Messages sent: {client.message_count}")
        print("="*60 + "\n")

    finally:
        client.disconnect()


def main():
    """Main test function."""
    print("\n" + "="*60)
    print("HL7 Server and Client Integration Test")
    print("="*60 + "\n")

    # Start server in background thread
    server_thread = threading.Thread(
        target=lambda: run_server(port=2575, duration=30),
        daemon=True
    )
    server_thread.start()

    # Run client tests
    try:
        run_client_tests(host="localhost", port=2575)
    except Exception as e:
        print(f"Error during tests: {e}")

    # Wait for server thread to finish
    server_thread.join(timeout=35)

    print("\n" + "="*60)
    print("Test Complete!")
    print("="*60)
    print("\nLog files created in: logs/hl7server/YYYY-MM-DD/")
    print("Available logs:")
    print("  - received_messages.jsonl - All received HL7 messages")
    print("  - sent_messages.jsonl - All sent responses (ACKs)")
    print("  - connections.jsonl - Connection/disconnection events")
    print("  - server_events.jsonl - Server start/stop events")
    print("  - errors.jsonl - Any errors that occurred")
    print("  - parsed_hl7.jsonl - Parsed HL7 message data")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
