"""
Traffic Analysis Module for Medaudit 2.0
AI Agent Instructions:
- This module handles PCAP file parsing and encryption analysis
- It detects TLS/SSL layers for encryption status
- Extracts unencrypted payloads for HL7 and PII analysis
- Use this module when analyzing network traffic captures
"""

import sys
from scapy.all import rdpcap, TCP, UDP, Raw
from scapy.layers.inet import IP
from ..pii import detect_pii

def is_hl7_message(payload):
    """Check if payload contains HL7 message."""
    try:
        text = payload.decode('utf-8', errors='ignore')
        # HL7 messages start with MSH|
        if text.startswith('MSH|'):
            return True, text.split('\n')[0]  # Return first line
    except:
        pass
    return False, None

def analyze_pcap(pcap_file):
    """Analyze PCAP file for encryption and extract data."""
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading PCAP file: {e}")
        return

    encrypted_packets = 0
    unencrypted_packets = 0
    hl7_messages = []
    pii_instances = []

    for packet in packets:
        if IP in packet:
            # Check for encryption indicators
            # For now, check common SSL ports or if payload appears encrypted
            is_encrypted = False
            
            if TCP in packet:
                # Common SSL/TLS ports
                if packet[TCP].dport in [443, 993, 995, 465, 587] or packet[TCP].sport in [443, 993, 995, 465, 587]:
                    is_encrypted = True
                # Check if payload looks like encrypted data (high entropy)
                elif Raw in packet:
                    payload = packet[Raw].load
                    if len(payload) > 10:
                        # Simple entropy check - encrypted data has high entropy
                        entropy = len(set(payload)) / len(payload)
                        if entropy > 0.8:  # High entropy suggests encryption
                            is_encrypted = True
            
            if is_encrypted:
                encrypted_packets += 1
            elif TCP in packet or UDP in packet:
                # Check for Raw payload (unencrypted)
                if Raw in packet:
                    payload = packet[Raw].load
                    unencrypted_packets += 1

                    # Check for HL7
                    is_hl7, hl7_header = is_hl7_message(payload)
                    if is_hl7:
                        hl7_messages.append(hl7_header)

                    # Check for PII
                    pii = detect_pii(payload)
                    if pii:
                        pii_instances.extend(pii)

    total_analyzed = encrypted_packets + unencrypted_packets

    if total_analyzed == 0:
        print("No analyzable packets found.")
        return

    encrypted_ratio = encrypted_packets / total_analyzed

    if encrypted_ratio == 1.0:
        print("Traffic is fully encrypted.")
    elif encrypted_ratio == 0.0:
        print("Traffic is fully unencrypted.")
    else:
        print(f"Traffic is partially encrypted ({encrypted_ratio:.2%} encrypted).")

    if unencrypted_packets > 0:
        print(f"\nUnencrypted packets: {unencrypted_packets}")

        if hl7_messages:
            print(f"\nFound {len(hl7_messages)} HL7 messages:")
            for msg in hl7_messages[:10]:  # Show first 10
                print(f"  {msg}")
            if len(hl7_messages) > 10:
                print(f"  ... and {len(hl7_messages) - 10} more")

        if pii_instances:
            print(f"\nDetected PII instances: {len(pii_instances)}")
            for pii in pii_instances[:20]:  # Show first 20
                print(f"  {pii}")
            if len(pii_instances) > 20:
                print(f"  ... and {len(pii_instances) - 20} more")
        else:
            print("No PII detected in unencrypted traffic.")