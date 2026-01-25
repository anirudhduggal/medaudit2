"""
PII Detection Module for Medaudit 2.0
AI Agent Instructions:
- This module handles detection of Personally Identifiable Information
- Uses regex patterns and Luhn algorithm for credit card validation
- Scans for names, addresses, payment methods, and financial keywords
- Call detect_pii() with raw payload bytes to analyze for PII
"""

import re

def luhn_checksum(card_num):
    """Validate credit card number using Luhn algorithm."""
    def digits_of(n):
        return [int(d) for d in str(n)]
    digits = digits_of(card_num)
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = sum(odd_digits)
    for d in even_digits:
        checksum += sum(digits_of(d*2))
    return checksum % 10 == 0

def is_credit_card(text):
    """Check if text contains potential credit card numbers."""
    # Match 13-19 digit numbers
    pattern = r'\b\d{13,19}\b'
    matches = re.findall(pattern, text)
    for match in matches:
        if luhn_checksum(int(match)):
            return True, match
    return False, None

def detect_pii(payload):
    """Detect PII in payload."""
    pii_found = []
    text = payload.decode('utf-8', errors='ignore').lower()

    # Credit card detection
    has_cc, cc_num = is_credit_card(payload.decode('utf-8', errors='ignore'))
    if has_cc:
        pii_found.append(f"Potential Credit Card: {cc_num}")

    # Payment methods
    payment_methods = ['visa', 'mastercard', 'amex', 'discover', 'paypal', 'stripe', 'apple pay', 'google pay']
    for method in payment_methods:
        if method in text:
            pii_found.append(f"Payment Method: {method}")

    # Names (basic: capitalized words)
    name_pattern = r'\b[A-Z][a-z]+\s[A-Z][a-z]+\b'
    names = re.findall(name_pattern, payload.decode('utf-8', errors='ignore'))
    if names:
        pii_found.extend([f"Potential Name: {name}" for name in names[:5]])  # Limit to 5

    # Addresses (basic: street patterns)
    address_patterns = [
        r'\b\d+\s+[A-Za-z0-9\s,.-]+\b',  # Street addresses
        r'\b[A-Z]{2}\s+\d{5}\b',  # State ZIP
    ]
    for pattern in address_patterns:
        addresses = re.findall(pattern, payload.decode('utf-8', errors='ignore'))
        if addresses:
            pii_found.extend([f"Potential Address: {addr}" for addr in addresses[:3]])

    # Financial info
    financial_keywords = ['account', 'balance', 'transaction', 'payment', 'invoice', 'billing']
    for keyword in financial_keywords:
        if keyword in text:
            pii_found.append(f"Financial Keyword: {keyword}")

    return pii_found