'''
Deterministic Triage Engine

Purpose: Decide how bad the alert is and what it represents.

Responsibilities:
- Suppression logic (all IOCs whitelisted)
- Severity scoring (1–100)
- Tagging (phishing, malware, C2, etc.)
- MITRE ATT&CK technique aggregation

Why deterministic:
- Fully auditable
- Predictable outcomes
- Preferred in regulated environments
'''

import os
from typing import Dict, Any

from SOAR.Triage.rules import (
    TriageConfigLoader,
    SuppressionEngine,
    SeverityScorer,
    TagGenerator
)

__all__ = ["triage"]


def _build_config_path() -> str:
    """Resolve config path relative to this module."""
    triage_dir = os.path.dirname(__file__)
    return os.path.join(triage_dir, "config.yml")


# Lazy-load config and engines as singletons
_CONFIG_LOADER = None
_SUPPRESSION_ENGINE = None
_SEVERITY_SCORER = None
_TAG_GENERATOR = None


def _get_triage_components():
    """Lazy-load triage components as singletons."""
    global _CONFIG_LOADER, _SUPPRESSION_ENGINE, _SEVERITY_SCORER, _TAG_GENERATOR
    
    if _CONFIG_LOADER is None:
        config_path = _build_config_path()
        _CONFIG_LOADER = TriageConfigLoader(config_path)
        _SUPPRESSION_ENGINE = SuppressionEngine(_CONFIG_LOADER)
        _SEVERITY_SCORER = SeverityScorer(_CONFIG_LOADER)
        _TAG_GENERATOR = TagGenerator(_CONFIG_LOADER)
    
    return _CONFIG_LOADER, _SUPPRESSION_ENGINE, _SEVERITY_SCORER, _TAG_GENERATOR


def _validate_enriched_alert(alert: Dict[str, Any]) -> None:
    """
    Strictly validate enriched alert structure.
    
    Args:
        alert: Alert to validate
        
    Raises:
        ValueError: If alert structure is invalid
    """
    if not isinstance(alert, dict):
        raise ValueError("Alert must be a dictionary")
    
    # Check for enrichment field
    if "enrichment" not in alert:
        raise ValueError("Alert missing 'enrichment' field - must be enriched first")
    
    enrichment = alert["enrichment"]
    if not isinstance(enrichment, dict):
        raise ValueError("enrichment must be a dictionary")
    
    # Check for summary
    if "summary" not in enrichment:
        raise ValueError("enrichment missing 'summary' field")
    
    summary = enrichment["summary"]
    if not isinstance(summary, dict):
        raise ValueError("enrichment.summary must be a dictionary")
    
    # Validate summary fields
    required_fields = ["total_iocs", "malicious", "suspicious", "clean", "whitelisted", "unknown"]
    for field in required_fields:
        if field not in summary:
            raise ValueError(f"enrichment.summary missing required field: '{field}'")
        
        value = summary[field]
        if not isinstance(value, int):
            raise ValueError(f"enrichment.summary.{field} must be an integer, got {type(value)}")
        
        if value < 0:
            raise ValueError(f"enrichment.summary.{field} cannot be negative")
    
    # Check for alert type
    if "type" not in alert:
        raise ValueError("Alert missing 'type' field")
    
    if not isinstance(alert["type"], str) or not alert["type"].strip():
        raise ValueError("Alert 'type' must be a non-empty string")


def triage(enriched_alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Triage an enriched alert with deterministic rules.
    
    Args:
        enriched_alert: Alert with enrichment data from enricher.enrich()
        
    Returns:
        Alert with added triage fields:
        - triage.suppressed (bool)
        - triage.suppression_reason (str or None)
        - triage.severity_score (int 0-100)
        - triage.priority (str: critical/high/medium/low/informational)
        - triage.tags (list of strings)
        - triage.scoring_details (dict)
        
    Raises:
        ValueError: If alert structure is invalid
    """
    # Validate input
    _validate_enriched_alert(enriched_alert)
    
    # Get triage components
    config_loader, suppression_engine, severity_scorer, tag_generator = _get_triage_components()
    
    # Extract data
    summary = enriched_alert["enrichment"]["summary"]
    alert_type = enriched_alert["type"]
    
    # Generate MITRE techniques for this alert type
    mitre_techniques = config_loader.get_mitre_techniques(alert_type)
    
    # Initialize triage result
    triage_result = {
        "suppressed": False,
        "suppression_reason": None,
        "severity_score": 0,
        "priority": "informational",
        "tags": [],
        "mitre_techniques": mitre_techniques,
        "scoring_details": {}
    }
    
    # Step 1: Check suppression rules
    suppressed, reason = suppression_engine.evaluate(summary)
    triage_result["suppressed"] = suppressed
    triage_result["suppression_reason"] = reason
    
    if suppressed:
        # If suppressed, set severity to 0 and priority to informational
        triage_result["severity_score"] = 0
        triage_result["priority"] = "informational"
        triage_result["tags"] = ["suppressed"]
    else:
        # Step 2: Calculate severity score
        severity_data = severity_scorer.calculate(summary, alert_type)
        triage_result["severity_score"] = severity_data["severity_score"]
        triage_result["scoring_details"] = severity_data["scoring_details"]
        
        # Step 3: Determine priority
        triage_result["priority"] = config_loader.get_priority_for_score(
            triage_result["severity_score"]
        )
        
        # Step 4: Generate tags
        triage_result["tags"] = tag_generator.generate(alert_type, summary)
    
    # Add triage result to alert
    triaged_alert = enriched_alert.copy()
    triaged_alert["triage"] = triage_result
    
    return triaged_alert