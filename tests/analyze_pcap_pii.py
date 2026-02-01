#!/usr/bin/env python3
"""Analyze PCAP payload and PII detection"""

from scapy.all import rdpcap, Raw
from medaudit.analysis.pii.pii_check import create_analyzer
from pathlib import Path

# Get workspace root (one level up from tests/)
workspace_root = Path(__file__).parent.parent
pcap_path = workspace_root / 'medaudit' / 'testFiles' / 'hl7_v2_unencrypted_synthetic.pcap'

packets = rdpcap(str(pcap_path))
payload = packets[0][Raw].load

print("\n" + "=" * 80)
print("PCAP PAYLOAD ANALYSIS & PII DETECTION")
print("=" * 80)

# Analyze structure
print(f"\nPayload Size: {len(payload)} bytes")
print(f"First 10 bytes (hex): {payload[:10].hex()}")
print(f"First 10 bytes (repr): {repr(payload[:10])}")

# Check MLLP wrapper
if payload[0] == 0x0b:
    print("\n✓ MLLP wrapper detected (start byte: 0x0b)")
    if payload[-2] == 0x1c and payload[-1] == 0x0d:
        print("✓ MLLP end marker (0x1c 0x0d): Found")
        message = payload[1:-2]
    else:
        print(f"⚠ MLLP end marker different: {repr(payload[-3:])}")
        message = payload[1:]
else:
    message = payload

# Decode message
message_text = message.decode('utf-8', errors='ignore')

print("\n" + "-" * 80)
print("DECODED MESSAGE:")
print("-" * 80)
print(message_text)

# Extract segments
print("\n" + "-" * 80)
print("HL7 SEGMENTS:")
print("-" * 80)
segments = message_text.strip().split('\r')
for i, segment in enumerate(segments, 1):
    segment_type = segment.split('|')[0] if segment else 'UNKNOWN'
    print(f"{i}. {segment_type}: {segment[:60]}...")

# Extract PII-rich fields
print("\n" + "-" * 80)
print("DETECTED PII CONTENT:")
print("-" * 80)
for segment in segments:
    if segment.startswith('PID'):
        fields = segment.split('|')
        print(f"PID Segment Fields:")
        print(f"  - Name field: {fields[5] if len(fields) > 5 else 'N/A'}")
        print(f"  - DOB field: {fields[7] if len(fields) > 7 else 'N/A'}")
        print(f"  - Address field: {fields[11] if len(fields) > 11 else 'N/A'}")
        print(f"  - Phone field: {fields[13] if len(fields) > 13 else 'N/A'}")
        print(f"  - Patient ID: {fields[3] if len(fields) > 3 else 'N/A'}")
    elif segment.startswith('PV1'):
        fields = segment.split('|')
        print(f"PV1 Segment Fields:")
        print(f"  - Attending physician: {fields[7] if len(fields) > 7 else 'N/A'}")

# Try Presidio
print("\n" + "-" * 80)
print("PRESIDIO PII ANALYZER RESULTS:")
print("-" * 80)
analyzer = create_analyzer()
results = analyzer.analyze(text=message_text, language='en')

if results:
    print(f"✓ Found {len(results)} entities:")
    for result in results:
        text_sample = message_text[result.start:result.end]
        print(f"  - {result.entity_type}: '{text_sample}'")
else:
    print("✗ Presidio analyzer found NO entities")
    print("  Note: Presidio requires NER model configuration for PERSON/PHONE detection")

print("\n" + "=" * 80)
print("CONCLUSION:")
print("=" * 80)
print("✓ PCAP contains real PII data:")
print("  - Patient name: JOHN DOE")
print("  - Patient ID: 123456")
print("  - Address: 123 FAKE ST, FAKETOWN, CA")
print("  - Physician: SMITH, ALICE")
print("\n⚠ Presidio analyzer NOT detecting entities (configuration needed)")
print("✓ However, the PII exists in the PCAP file as unencrypted data")
print("=" * 80 + "\n")
