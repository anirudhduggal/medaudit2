"""
PII Detection Module for Medaudit 2.0
AI Agent Instructions:
- This module handles detection of Personally Identifiable Information
- Uses Presidio for PII detection
- Call detect_pii() with raw payload bytes to analyze for PII
"""
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer.recognizer_registry import RecognizerRegistry
from presidio_analyzer.predefined_recognizers import CreditCardRecognizer, UsSsnRecognizer
import spacy

def create_analyzer():
    """Create a new Presidio analyzer engine."""
    provider = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}]
    })
    
    registry = RecognizerRegistry()
    registry.add_recognizer(CreditCardRecognizer(supported_language="en"))
    registry.add_recognizer(UsSsnRecognizer(supported_language="en"))

    analyzer = AnalyzerEngine(
        nlp_engine=provider.create_engine(),
        registry=registry,
        supported_languages=["en"]
    )
    return analyzer

def detect_pii(payload, analyzer):
    """Detect PII in payload using Presidio."""
    text = payload.decode('utf-8', errors='ignore')
    results = analyzer.analyze(text=text, language='en')
    pii_found = []
    for result in results:
        pii_found.append(f"{result.entity_type}: {text[result.start:result.end]}")
    return pii_found
