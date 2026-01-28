from medaudit.analysis.pii.pii_check import create_analyzer, detect_pii

def test_detect_pii_with_presidio():
    """
    Tests that the detect_pii function can find PII using Presidio.
    """
    analyzer = create_analyzer()
    test_data = b"His name is John Doe and his phone number is 212-555-5555"
    pii_found = detect_pii(test_data, analyzer)
    
    # Presidio should identify PERSON and PHONE_NUMBER
    # Note: The exact output format depends on your `detect_pii` implementation
    assert any("PERSON: John Doe" in p for p in pii_found)
    assert any("PHONE_NUMBER: 212-555-5555" in p for p in pii_found)

def test_detect_pii_credit_card_with_presidio():
    """
    Tests that the detect_pii function can find a credit card number using Presidio.
    """
    analyzer = create_analyzer()
    test_data = b"Patient credit card is 49927398716"
    pii_found = detect_pii(test_data, analyzer)
    assert any("CREDIT_CARD: 49927398716" in p for p in pii_found)

def test_detect_pii_no_pii():
    """
    Tests that the detect_pii function returns an empty list when no PII is present.
    """
    analyzer = create_analyzer()
    test_data = b"This is a test sentence with no personal information."
    pii_found = detect_pii(test_data, analyzer)
    assert len(pii_found) == 0
