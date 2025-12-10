"""
Incident JSON Exporter

Purpose: Export fully-processed alerts to structured incident JSON files.

Responsibilities:
- Extract incident data from alert
- Add allowlist status to indicators
- Build standardized JSON schema
- Write to out/incidents/<incident_id>.json

Design notes:
- Stateless export function
- Validates input before writing
- Reuses AllowlistLoader for indicator status
"""

import os
import json
import re
from typing import Any, Dict, List, Optional

from SOAR.Triage.rules import TriageConfigLoader, AllowlistLoader

__all__ = ["export_incident"]


class IncidentDataExtractor:
	"""Extract and validate incident data from processed alert."""
	
	def __init__(self, allowlist_loader: AllowlistLoader) -> None:
		self._allowlist = allowlist_loader
	
	def _validate_input(self, alert: Dict[str, Any]) -> None:
		"""Validate alert structure before extraction."""
		if not isinstance(alert, dict):
			raise ValueError("alert must be a dictionary")
		
		# Required top-level fields
		required_fields = ["incident_id", "indicators", "triage", "mitre", "actions"]
		for field in required_fields:
			if field not in alert:
				raise ValueError(f"alert missing required field: '{field}'")
		
		# Validate incident_id format
		incident_id = alert.get("incident_id", "")
		if not isinstance(incident_id, str) or not incident_id.strip():
			raise ValueError("incident_id must be a non-empty string")
		
		# Pattern: INC-20251210T010027Z-bf066066
		if not re.match(r'^INC-\d{8}T\d{6}Z-[a-f0-9]{8}$', incident_id):
			raise ValueError(f"incident_id has invalid format: {incident_id}")
		
		# Validate indicators is a list
		if not isinstance(alert.get("indicators"), list):
			raise ValueError("indicators must be a list")
		
		# Validate triage is a dict
		if not isinstance(alert.get("triage"), dict):
			raise ValueError("triage must be a dictionary")
		
		# Validate mitre is a dict
		if not isinstance(alert.get("mitre"), dict):
			raise ValueError("mitre must be a dictionary")
		
		# Validate actions is a list
		if not isinstance(alert.get("actions"), list):
			raise ValueError("actions must be a list")
	
	def extract_core_fields(self, alert: Dict[str, Any]) -> Dict[str, Any]:
		"""Extract incident_id and source_alert."""
		return {
			"incident_id": alert["incident_id"],
			"source_alert": alert.get("source_alert", {})
		}
	
	def extract_asset(self, alert: Dict[str, Any]) -> Dict[str, str]:
		"""Extract asset information (device_id, hostname, ip)."""
		asset = alert.get("asset", {})
		if not isinstance(asset, dict):
			return {}
		
		# Extract fields, defaulting to empty string if missing
		return {
			"device_id": asset.get("device_id", ""),
			"hostname": asset.get("hostname", ""),
			"ip": asset.get("ip", "")
		}
	
	def extract_indicators_with_allowlist(self, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
		"""
		Extract indicators and add allowlisted flag to each.
		
		Returns list of indicators with structure:
		{"type": "...", "value": "...", "risk": {...}, "allowlisted": bool}
		"""
		indicators = alert.get("indicators", [])
		result = []
		
		for indicator in indicators:
			if not isinstance(indicator, dict):
				continue
			
			ioc_type = indicator.get("type", "")
			ioc_value = indicator.get("value", "")
			risk = indicator.get("risk", {})
			
			# Check allowlist status (safe default: false if check fails)
			try:
				is_allowlisted = self._allowlist.is_allowlisted(ioc_type, ioc_value)
			except Exception:
				is_allowlisted = False
			
			result.append({
				"type": ioc_type,
				"value": ioc_value,
				"risk": risk,
				"allowlisted": is_allowlisted
			})
		
		return result
	
	def extract_triage_data(self, alert: Dict[str, Any]) -> Dict[str, Any]:
		"""
		Extract triage data and normalize field names.
		
		Renames severity_score -> severity for output schema.
		"""
		triage = alert.get("triage", {})
		if not isinstance(triage, dict):
			return {
				"severity": 0,
				"bucket": "Unknown",
				"tags": [],
				"suppressed": False
			}
		
		# Rename severity_score to severity
		severity = triage.get("severity_score", 0)
		if not isinstance(severity, (int, float)):
			severity = 0
		
		bucket = triage.get("bucket", "Unknown")
		if not isinstance(bucket, str):
			bucket = "Unknown"
		
		tags = triage.get("tags", [])
		if not isinstance(tags, list):
			tags = []
		
		suppressed = triage.get("suppressed", False)
		if not isinstance(suppressed, bool):
			suppressed = False
		
		return {
			"severity": int(severity),
			"bucket": bucket,
			"tags": tags,
			"suppressed": suppressed
		}
	
	def extract_mitre(self, alert: Dict[str, Any]) -> Dict[str, List[str]]:
		"""Extract MITRE ATT&CK techniques."""
		mitre = alert.get("mitre", {})
		if not isinstance(mitre, dict):
			return {"techniques": []}
		
		techniques = mitre.get("techniques", [])
		if not isinstance(techniques, list):
			return {"techniques": []}
		
		return {"techniques": techniques}
	
	def extract_actions(self, alert: Dict[str, Any]) -> List[Dict[str, str]]:
		"""Extract response actions."""
		actions = alert.get("actions", [])
		if not isinstance(actions, list):
			return []
		
		result = []
		for action in actions:
			if isinstance(action, dict):
				result.append({
					"type": action.get("type", ""),
					"target": action.get("target", ""),
					"result": action.get("result", ""),
					"ts": action.get("ts", "")
				})
		
		return result
	
	def extract(self, alert: Dict[str, Any]) -> Dict[str, Any]:
		"""Extract all incident data with validation."""
		self._validate_input(alert)
		
		core = self.extract_core_fields(alert)
		asset = self.extract_asset(alert)
		indicators = self.extract_indicators_with_allowlist(alert)
		triage = self.extract_triage_data(alert)
		mitre = self.extract_mitre(alert)
		actions = self.extract_actions(alert)
		
		return {
			"incident_id": core["incident_id"],
			"source_alert": core["source_alert"],
			"asset": asset,
			"indicators": indicators,
			"triage": triage,
			"mitre": mitre,
			"actions": actions
		}


class IncidentJSONBuilder:
	"""Build and validate incident JSON structure."""
	
	def __init__(self, extracted_data: Dict[str, Any]) -> None:
		self._data = extracted_data
	
	def _validate_schema(self) -> None:
		"""Validate that all required fields are present and properly typed."""
		required_keys = ["incident_id", "source_alert", "asset", "indicators", "triage", "mitre", "actions"]
		for key in required_keys:
			if key not in self._data:
				raise ValueError(f"Missing required key in extracted data: {key}")
		
		# Type checks
		if not isinstance(self._data["incident_id"], str):
			raise ValueError("incident_id must be a string")
		if not isinstance(self._data["source_alert"], dict):
			raise ValueError("source_alert must be a dict")
		if not isinstance(self._data["asset"], dict):
			raise ValueError("asset must be a dict")
		if not isinstance(self._data["indicators"], list):
			raise ValueError("indicators must be a list")
		if not isinstance(self._data["triage"], dict):
			raise ValueError("triage must be a dict")
		if not isinstance(self._data["mitre"], dict):
			raise ValueError("mitre must be a dict")
		if not isinstance(self._data["actions"], list):
			raise ValueError("actions must be a list")
		
		# Validate triage required fields
		triage = self._data["triage"]
		if "severity" not in triage or not isinstance(triage["severity"], int):
			raise ValueError("triage.severity must be an integer")
		if "bucket" not in triage or not isinstance(triage["bucket"], str):
			raise ValueError("triage.bucket must be a string")
	
	def build(self) -> Dict[str, Any]:
		"""Build the final incident JSON structure."""
		self._validate_schema()
		
		# Return in the exact order specified
		return {
			"incident_id": self._data["incident_id"],
			"source_alert": self._data["source_alert"],
			"asset": self._data["asset"],
			"indicators": self._data["indicators"],
			"triage": self._data["triage"],
			"mitre": self._data["mitre"],
			"actions": self._data["actions"]
		}


def _build_config_path() -> str:
	"""Build path to triage config.yml (to get allowlist path)."""
	# Go up from Reporting to SOAR, then to Triage
	reporting_dir = os.path.dirname(__file__)
	soar_dir = os.path.dirname(reporting_dir)
	triage_dir = os.path.join(soar_dir, "Triage")
	return os.path.join(triage_dir, "config.yml")


# Singleton instances
_CONFIG_LOADER: Optional[TriageConfigLoader] = None
_ALLOWLIST_LOADER: Optional[AllowlistLoader] = None


def _get_allowlist_loader() -> AllowlistLoader:
	"""Lazy-load AllowlistLoader singleton."""
	global _CONFIG_LOADER, _ALLOWLIST_LOADER
	if _ALLOWLIST_LOADER is None:
		config_path = _build_config_path()
		_CONFIG_LOADER = TriageConfigLoader(config_path)
		allowlist_path = _CONFIG_LOADER.get_allowlist_path()
		_ALLOWLIST_LOADER = AllowlistLoader(allowlist_path)
	return _ALLOWLIST_LOADER


def export_incident(alert: Dict[str, Any], output_dir: str) -> bool:
	"""
	Export processed alert to incident JSON file.
	
	Args:
		alert: Fully processed alert from respond() stage
		output_dir: Base output directory (e.g., "out")
	
	Returns:
		True if export succeeded, False otherwise
	
	Raises:
		ValueError: If alert structure is invalid
	"""
	try:
		# Load allowlist loader
		allowlist_loader = _get_allowlist_loader()
		
		# Extract data
		extractor = IncidentDataExtractor(allowlist_loader)
		extracted_data = extractor.extract(alert)
		
		# Build JSON
		builder = IncidentJSONBuilder(extracted_data)
		incident_json = builder.build()
		
		# Ensure incidents directory exists
		incidents_dir = os.path.join(output_dir, "incidents")
		os.makedirs(incidents_dir, exist_ok=True)
		
		# Write to file
		incident_id = incident_json["incident_id"]
		file_path = os.path.join(incidents_dir, f"{incident_id}.json")
		
		with open(file_path, "w", encoding="utf-8") as f:
			json.dump(incident_json, f, indent=2, ensure_ascii=False)
		
		return True
	
	except Exception as e:
		# Graceful degradation: log error but don't break pipeline
		import sys
		print(f"Error exporting incident: {e}", file=sys.stderr)
		return False
