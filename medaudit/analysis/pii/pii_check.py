"""
PII Detection Module for Medaudit 2.0
AI Agent Instructions:
- This module handles detection of Personally Identifiable Information
- Uses Presidio for PII detection
- Call detect_pii() with raw payload bytes to analyze for PII
"""
import logging
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer.recognizer_registry import RecognizerRegistry
from presidio_analyzer.predefined_recognizers import (
    CreditCardRecognizer,
    UsSsnRecognizer,
    PhoneRecognizer,
    EmailRecognizer,
    UsLicenseRecognizer,
    UsBankRecognizer,
    UsItinRecognizer,
    UsPassportRecognizer,
    IpRecognizer,
    DateRecognizer,
    SpacyRecognizer,
)

logger = logging.getLogger(__name__)

def create_analyzer():
    """Create a new Presidio analyzer engine with all PII recognizers."""
    try:
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}]
        })
        nlp_engine = provider.create_engine()
        
        registry = RecognizerRegistry()
        
        # Add SpacyRecognizer for NLP-based detection (PERSON, LOCATION, DATE, ORG, etc.)
        # This detects: names, addresses, organizations, dates
        spacy_recognizer = SpacyRecognizer(
            supported_language="en",
            supported_entities=["PERSON", "LOCATION", "DATE_TIME", "NRP", "GPE", "ORG"],
            check_label_groups=[
                ({"PERSON"}, {"PER", "PERSON"}),
                ({"LOCATION"}, {"LOC", "LOCATION", "GPE"}),
                ({"GPE"}, {"GPE", "LOC"}),  # Geo-Political Entity (cities, countries)
                ({"DATE_TIME"}, {"DATE", "TIME"}),
                ({"NRP"}, {"NORP", "NRP"}),  # Nationalities, religious, political groups
                ({"ORG"}, {"ORG"}),
            ]
        )
        registry.add_recognizer(spacy_recognizer)
        
        # Add pattern-based recognizers
        registry.add_recognizer(CreditCardRecognizer(supported_language="en"))
        registry.add_recognizer(UsSsnRecognizer(supported_language="en"))
        registry.add_recognizer(PhoneRecognizer(supported_language="en"))
        registry.add_recognizer(EmailRecognizer(supported_language="en"))
        registry.add_recognizer(UsLicenseRecognizer(supported_language="en"))
        registry.add_recognizer(UsBankRecognizer(supported_language="en"))
        registry.add_recognizer(UsItinRecognizer(supported_language="en"))
        registry.add_recognizer(UsPassportRecognizer(supported_language="en"))
        registry.add_recognizer(IpRecognizer(supported_language="en"))
        registry.add_recognizer(DateRecognizer(supported_language="en"))

        analyzer = AnalyzerEngine(
            nlp_engine=nlp_engine,
            registry=registry,
            supported_languages=["en"]
        )
        return analyzer
    except Exception as e:
        logger.error(f"Failed to create PII analyzer: {e}")
        return None

def detect_pii(payload, analyzer):
    """Detect PII in payload using Presidio (deduplicated)."""
    if analyzer is None:
        return []
    
    try:
        text = payload.decode('utf-8', errors='ignore')
        results = analyzer.analyze(text=text, language='en')
        pii_found = []
        seen = set()  # Track (entity_type, value) pairs to avoid duplicates
        for result in results:
            value = text[result.start:result.end]
            key = (result.entity_type, value)
            if key not in seen:
                seen.add(key)
                pii_found.append(f"{result.entity_type}: {value}")
        return pii_found
    except Exception as e:
        logger.error(f"PII detection failed: {e}")
        return []

