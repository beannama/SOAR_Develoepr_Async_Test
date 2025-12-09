"""
Deterministic Triage Engine (severity-first).

Current focus: compute severity score from alert type and indicator risk verdicts.
"""

import os
from typing import Any, Dict, List, Tuple

from SOAR.Triage.rules import (
  TriageConfigLoader, 
  SeverityScorer, 
  AllowlistLoader, 
  SuppressionEngine,
  BucketClassifier,
  MitreMapper
)

__all__ = ["triage"]


def _build_config_path() -> str:
  triage_dir = os.path.dirname(__file__)
  return os.path.join(triage_dir, "config.yml")


_CONFIG_LOADER: TriageConfigLoader | None = None
_SEVERITY_SCORER: SeverityScorer | None = None
_ALLOWLIST_LOADER: AllowlistLoader | None = None
_SUPPRESSION_ENGINE: SuppressionEngine | None = None
_BUCKET_CLASSIFIER: BucketClassifier | None = None
_MITRE_MAPPER: MitreMapper | None = None


def _get_components():
  global _CONFIG_LOADER, _SEVERITY_SCORER, _ALLOWLIST_LOADER, _SUPPRESSION_ENGINE, _BUCKET_CLASSIFIER, _MITRE_MAPPER
  if _CONFIG_LOADER is None:
    config_path = _build_config_path()
    _CONFIG_LOADER = TriageConfigLoader(config_path)
    _SEVERITY_SCORER = SeverityScorer(_CONFIG_LOADER)
    allowlist_path = _CONFIG_LOADER.get_allowlist_path()
    _ALLOWLIST_LOADER = AllowlistLoader(allowlist_path)
    _SUPPRESSION_ENGINE = SuppressionEngine(_CONFIG_LOADER, _ALLOWLIST_LOADER)
    _BUCKET_CLASSIFIER = BucketClassifier(_CONFIG_LOADER)
    _MITRE_MAPPER = MitreMapper(_CONFIG_LOADER)
  return _CONFIG_LOADER, _SEVERITY_SCORER, _ALLOWLIST_LOADER, _SUPPRESSION_ENGINE, _BUCKET_CLASSIFIER, _MITRE_MAPPER


ALLOWED_VERDICTS = {"malicious", "suspicious", "clean", "unknown"}


def _validate_enriched_alert(alert: Dict[str, Any]) -> None:
  if not isinstance(alert, dict):
    raise ValueError("alert must be a dict")

  if "type" not in alert or not isinstance(alert.get("type"), str) or not alert["type"].strip():
    raise ValueError("alert['type'] must be a non-empty string")

  indicators = alert.get("indicators")
  if not isinstance(indicators, list) or not indicators:
    raise ValueError("alert['indicators'] must be a non-empty list")

  for idx, indicator in enumerate(indicators):
    if not isinstance(indicator, dict):
      raise ValueError(f"indicator[{idx}] must be a dict")
    if "type" not in indicator or not isinstance(indicator.get("type"), str) or not indicator["type"].strip():
      raise ValueError(f"indicator[{idx}]['type'] must be a non-empty string")
    if "value" not in indicator or not isinstance(indicator.get("value"), str) or not indicator["value"].strip():
      raise ValueError(f"indicator[{idx}]['value'] must be a non-empty string")
    risk = indicator.get("risk")
    if not isinstance(risk, dict):
      raise ValueError(f"indicator[{idx}]['risk'] must be a dict")
    verdict = risk.get("verdict")
    if verdict not in ALLOWED_VERDICTS:
      raise ValueError(f"indicator[{idx}].risk.verdict must be one of {sorted(ALLOWED_VERDICTS)}")


def triage(alert: Dict[str, Any]) -> Dict[str, Any]:
  """Compute severity, suppression, bucket, and MITRE techniques for an enriched alert."""
  _validate_enriched_alert(alert)
  config_loader, severity_scorer, allowlist_loader, suppression_engine, bucket_classifier, mitre_mapper = _get_components()

  indicators = alert["indicators"]
  
  # Calculate base severity with intel boosts
  severity = severity_scorer.calculate(alert["type"], indicators)
  severity_score = severity["severity_score"]
  
  # Apply allowlist suppression
  suppression_result = suppression_engine.evaluate(indicators)
  
  # Adjust severity based on suppression
  if suppression_result["is_fully_suppressed"]:
    # All IOCs allowlisted: severity = 0
    severity_score = 0
  elif suppression_result["allowlisted_count"] > 0:
    # Some IOCs allowlisted: subtract penalty
    severity_score -= suppression_result["severity_penalty"]
    severity_score = max(0, severity_score)  # Floor at 0
  
  # Ensure severity is clamped 0-100
  severity_score = max(0, min(100, int(severity_score)))
  
  # Classify into bucket
  bucket = bucket_classifier.classify(severity_score)
  
  # Get MITRE techniques
  techniques = mitre_mapper.get_techniques(alert["type"])
  
  triage_block = {
    "severity_score": severity_score,
    "bucket": bucket,
    "tags": suppression_result["tags"],
    "suppressed": suppression_result["is_fully_suppressed"]
  }

  result = alert.copy()
  result["triage"] = triage_block
  result["mitre"] = {"techniques": techniques}
  return result
