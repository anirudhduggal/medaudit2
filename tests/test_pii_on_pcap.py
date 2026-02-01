#!/usr/bin/env python3
"""Test PII detection on HL7 synthetic PCAP file"""

from medaudit.analysis.traffic.traffic_analysis import is_hl7_message
from medaudit.analysis.pii.pii_check import create_analyzer, detect_pii
from scapy.all import rdpcap, Raw
from pathlib import Path

print("\n" + "=" * 80)
print("MEDAUDIT PII DETECTION TEST - HL7 SYNTHETIC PCAP")
print("=" * 80 + "\n")

# Load PCAP file (use fixture or compute path from project root)
print("1. Loading PCAP file...")
# Get workspace root (one level up from tests/)
workspace_root = Path(__file__).parent.parent
pcap_path = workspace_root / 'medaudit' / 'testFiles' / 'hl7_v2_unencrypted_synthetic.pcap'
packets = rdpcap(str(pcap_path))
print(f"   Total packets: {len(packets)}")

# Extract payload
print("\n2. Extracting payload...")
for i, packet in enumerate(packets):
    if Raw in packet:
        payload = packet[Raw].load
        text = payload.decode('utf-8', errors='ignore')
        print(f"   Packet {i}: {len(payload)} bytes")
        print(f"   Content preview: {text[:100]}...")
        
        # Check if HL7
        print("\n3. Checking for HL7 message...")
        is_hl7, header = is_hl7_message(payload)
        if is_hl7:
            print(f"   ✓ HL7 message detected: {header}")
        else:
            print(f"   ✗ Not an HL7 message")
        
        # Try PII detection
        print("\n4. PII Detection Test:")
        print(f"   Full text:\n   {text}\n")
        
        analyzer = create_analyzer()
        pii_found = detect_pii(payload, analyzer)
        
        if pii_found:
            print(f"   ✓ Found {len(pii_found)} PII items:")
            for item in pii_found:
                print(f"     - {item}")
        else:
            print(f"   ✗ No PII detected by Presidio analyzer")
            
        # Raw analysis
        print("\n5. Raw Presidio Analysis:")
        results = analyzer.analyze(text=text, language='en')
        if results:
            print(f"   ✓ Found {len(results)} entities:")
            for result in results:
                print(f"     - {result.entity_type}: {text[result.start:result.end]}")
        else:
            print(f"   ✗ No entities detected by Presidio")

print("\n" + "=" * 80)
print("TEST COMPLETE")
print("=" * 80 + "\n")
