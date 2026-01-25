#!/usr/bin/env python3
"""
Medaudit 2.0 - Main Entry Point
AI Agent Instructions:
- This is the main entry point for the Medaudit 2.0 application
- Run this script with a PCAP file as argument to start analysis
- It imports and calls the traffic analysis functionality
"""

import sys
from .analysis import analyze_pcap

def main():
    if len(sys.argv) != 2:
        print("Usage: python -m medaudit <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    analyze_pcap(pcap_file)

if __name__ == "__main__":
    main()