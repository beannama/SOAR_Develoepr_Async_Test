'''
Incident Normalization

Purpose: Produce a clean, portable incident format.

Responsibilities:
- Convert raw alert into normalized internal shape
- Preserve original alert as source reference
- Flatten indicators into a list
- Generate unique incident ID

Why important:
- Enables SIEM/SOC tooling interoperability
- Mirrors real SOAR data models
'''

from typing import Any, Dict, List
import copy
import uuid
from datetime import datetime

__all__ = ["normalize"]


def _generate_incident_id() -> str:
	"""
	Generate a unique incident ID.
	
	Format: INC-<ISO_TIMESTAMP>-<UUID_SHORT>
	Example: INC-20250809T140310Z-a7f2b1c3
	
	Returns:
		Unique incident ID string
	"""
	# Get current UTC timestamp in ISO format
	iso_timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
	
	# Get first 8 chars of UUID hex (sufficient uniqueness)
	uuid_short = uuid.uuid4().hex[:8]
	
	return f"INC-{iso_timestamp}-{uuid_short}"


def _validate_raw_alert(alert: Dict[str, Any]) -> None:
	"""Strictly validate the minimal alert structure before normalization."""
	if not isinstance(alert, dict):
		raise ValueError("alert must be a dictionary")

	required_fields = ["alert_id", "source", "type", "created_at", "indicators"]
	for field in required_fields:
		if field not in alert:
			raise ValueError(f"alert missing required field: '{field}'")

	for field in ["alert_id", "source", "type", "created_at"]:
		if not isinstance(alert[field], str) or not alert[field].strip():
			raise ValueError(f"alert['{field}'] must be a non-empty string")

	indicators = alert.get("indicators")
	if not isinstance(indicators, dict):
		raise ValueError("alert['indicators'] must be a dictionary")

	for ioc_type, values in indicators.items():
		if not isinstance(ioc_type, str) or not ioc_type.strip():
			raise ValueError("indicator type keys must be non-empty strings")
		if not isinstance(values, list):
			raise ValueError(f"alert['indicators']['{ioc_type}'] must be a list")
		for value in values:
			if not isinstance(value, str) or not value.strip():
				raise ValueError(f"IOC values for '{ioc_type}' must be non-empty strings")

	if "asset" in alert and not isinstance(alert.get("asset"), dict):
		raise ValueError("alert['asset'] must be a dictionary when present")

	if "raw" in alert and not isinstance(alert.get("raw"), dict):
		raise ValueError("alert['raw'] must be a dictionary when present")


def _flatten_indicators(indicators: Dict[str, List[str]]) -> List[Dict[str, str]]:
	"""Convert indicators dict into a flat list of {type, value} entries."""
	flattened: List[Dict[str, str]] = []
	for ioc_type, values in indicators.items():
		for value in values:
			flattened.append({"type": ioc_type, "value": value})
	return flattened


def _flatten_nested_dict(obj: Any, prefix: str = "", max_depth: int = 10, current_depth: int = 0) -> Dict[str, Any]:
	"""
	Recursively flatten a nested dictionary using dot notation.
	
	Args:
		obj: Object to flatten
		prefix: Current key prefix
		max_depth: Maximum recursion depth
		current_depth: Current recursion depth
		
	Returns:
		Flattened dictionary with dot-notation keys
		
	Raises:
		ValueError: If max depth exceeded or collision detected
	"""
	if current_depth > max_depth:
		raise ValueError(f"Flattening exceeded max depth of {max_depth}")
	
	flattened: Dict[str, Any] = {}
	
	if not isinstance(obj, dict):
		if prefix:
			flattened[prefix] = obj
		return flattened
	
	for key, value in obj.items():
		if not isinstance(key, str):
			continue
		
		new_key = f"{prefix}.{key}" if prefix else key
		
		if isinstance(value, dict):
			nested = _flatten_nested_dict(value, new_key, max_depth, current_depth + 1)
			for nested_key, nested_value in nested.items():
				if nested_key in flattened:
					raise ValueError(f"Key collision detected: {nested_key}")
				flattened[nested_key] = nested_value
		elif isinstance(value, list):
			flattened[new_key] = value
		else:
			if new_key in flattened:
				raise ValueError(f"Key collision detected: {new_key}")
			flattened[new_key] = value
	
	return flattened


def normalize(alert: Dict[str, Any]) -> Dict[str, Any]:
	"""
	Normalize a raw alert into an internal incident shape.

	- Keeps the original alert under incident.source_alert
	- Preserves asset data (device_id, hostname, ip) when present
	- Retains original indicator dict for compatibility with existing enrichment

	Args:
		alert: Raw alert dictionary from ingestion

	Returns:
		Normalized alert dictionary with original fields.

	Raises:
		ValueError: If input structure is invalid or flattening fails
	"""
	_validate_raw_alert(alert)

	# Generate unique incident ID
	incident_id = _generate_incident_id()

	flattened_indicators = _flatten_indicators(alert["indicators"])


	# Build complete normalized alert preserving all original top-level fields
    
	normalized_alert = copy.deepcopy(alert)
	normalized_alert["incident_id"] = incident_id
	normalized_alert["source_alert"] = copy.deepcopy(alert)
	normalized_alert["indicators"] = flattened_indicators

	return normalized_alert