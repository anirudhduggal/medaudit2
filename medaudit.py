#!/usr/bin/env python3
"""
Medaudit 2.0 - Main Entry Point
"""

import sys
from traffic_analysis import analyze_pcap

def main():
    if len(sys.argv) != 2:
        print("Usage: python medaudit.py <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    analyze_pcap(pcap_file)

if __name__ == "__main__":
    main()