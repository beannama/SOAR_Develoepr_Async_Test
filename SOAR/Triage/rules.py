"""
Deterministic triage rules.

Currently implements severity scoring using:
- Base severity per alert type (with Unknown fallback)
- Intel boosts from indicator risk verdicts
"""

import os
from typing import Any, Dict, List

import yaml

__all__ = ["TriageConfigLoader", "SeverityScorer", "AllowlistLoader", "SuppressionEngine", "BucketClassifier", "MitreMapper"]


class TriageConfigLoader:
	"""Load triage configuration (severity tables and boosts)."""

	def __init__(self, config_path: str) -> None:
		self._config_path = config_path
		self._config = self._load()

	def _load(self) -> Dict[str, Any]:
		if not os.path.isfile(self._config_path):
			raise FileNotFoundError(f"Triage config not found: {self._config_path}")
		with open(self._config_path, "r", encoding="utf-8") as f:
			return yaml.safe_load(f) or {}

	@property
	def severity_base(self) -> Dict[str, int]:
		return (self._config.get("severity", {}) or {}).get("base", {})

	@property
	def intel_boosts(self) -> Dict[str, int]:
		return (self._config.get("severity", {}) or {}).get("intel_boosts", {})

	@property
	def suppression_config(self) -> Dict[str, Any]:
		return self._config.get("suppression", {}) or {}

	def get_allowlist_path(self) -> str:
		"""Get absolute path to allowlist file."""
		rel_path = self.suppression_config.get("allowlist_path", "")
		if not rel_path:
			return ""
		config_dir = os.path.dirname(self._config_path)
		return os.path.normpath(os.path.join(config_dir, rel_path))

	def get_allowlist_penalty(self) -> int:
		return int(self.suppression_config.get("allowlist_penalty", 25))

	@property
	def bucket_config(self) -> Dict[str, Any]:
		return self._config.get("bucket", {}) or {}

	@property
	def mitre_config(self) -> Dict[str, Any]:
		return self._config.get("mitre", {}) or {}

	def get_mitre_mapping_path(self) -> str:
		"""Get absolute path to MITRE mapping file."""
		rel_path = self.mitre_config.get("mapping_path", "")
		if not rel_path:
			return ""
		config_dir = os.path.dirname(self._config_path)
		return os.path.normpath(os.path.join(config_dir, rel_path))

	def get_bucket_for_score(self, severity_score: int) -> str:
		"""
		Classify severity score into bucket.
		
		Args:
			severity_score: Score 0-100 (should be clamped)
		
		Returns:
			Bucket name: "Suppressed", "Low", "Medium", "High", or "Critical"
		"""
		# Ensure score is within range (defensive)
		score = max(0, min(100, int(severity_score)))
		
		bucket_ranges = self.bucket_config.get("ranges", [])
		if not bucket_ranges:
			# Fallback if config missing
			if score == 0:
				return "Suppressed"
			elif score <= 39:
				return "Low"
			elif score <= 69:
				return "Medium"
			elif score <= 89:
				return "High"
			else:
				return "Critical"
		
		# Use config-defined ranges
		for bucket in bucket_ranges:
			min_val = bucket.get("min", 0)
			max_val = bucket.get("max", 100)
			if min_val <= score <= max_val:
				return bucket.get("name", "Unknown")
		
		return "Unknown"


class SeverityScorer:
	"""Compute severity score from alert type and indicator verdicts."""

	ALLOWED_VERDICTS = {"malicious", "suspicious", "clean", "unknown"}

	def __init__(self, config_loader: TriageConfigLoader) -> None:
		self._config = config_loader

	def calculate(self, alert_type: str, indicators: List[Dict[str, Any]]) -> Dict[str, Any]:
		base_table = self._config.severity_base
		boosts = self._config.intel_boosts

		base = base_table.get(alert_type, base_table.get("Unknown", 40))

		malicious_boost = int(boosts.get("malicious", 0))
		suspicious_boost = int(boosts.get("suspicious", 0))
		extra_per = int(boosts.get("extra_flagged_per_ioc", 0))
		extra_cap = int(boosts.get("extra_flagged_cap", 0))

		flagged_count = 0
		first_flag_boost = 0

		for indicator in indicators:
			risk = indicator.get("risk", {}) if isinstance(indicator, dict) else {}
			verdict = risk.get("verdict") if isinstance(risk, dict) else None
			if verdict not in self.ALLOWED_VERDICTS:
				continue
			if verdict in ("malicious", "suspicious"):
				flagged_count += 1
				if flagged_count == 1:
					first_flag_boost = malicious_boost if verdict == "malicious" else suspicious_boost

		extra_boost = 0
		if flagged_count > 1:
			extra_boost = min((flagged_count - 1) * extra_per, extra_cap)

		severity_score = base + first_flag_boost + extra_boost
		severity_score = max(0, min(100, int(severity_score)))

		return {
			"severity_score": severity_score,
			"scoring_details": {
				"base": base,
				"flagged_iocs": flagged_count,
				"first_flag_boost": first_flag_boost,
				"extra_boost": extra_boost,
			}
		}


class AllowlistLoader:
	"""Load and parse allowlist YAML file for IOC matching."""

	def __init__(self, allowlist_path: str) -> None:
		self._allowlist_path = allowlist_path
		self._allowlist = self._load()

	def _load(self) -> Dict[str, Any]:
		"""Load allowlist file, return empty dict if not found or malformed."""
		if not self._allowlist_path or not os.path.isfile(self._allowlist_path):
			return {}
		try:
			with open(self._allowlist_path, "r", encoding="utf-8") as f:
				data = yaml.safe_load(f) or {}
				return data.get("indicators", {}) or {}
		except Exception:
			return {}

	def is_allowlisted(self, ioc_type: str, ioc_value: str) -> bool:
		"""Check if an IOC (type, value) exists in allowlist."""
		if not isinstance(self._allowlist, dict):
			return False
		allowlist_values = self._allowlist.get(ioc_type, [])
		if not isinstance(allowlist_values, list):
			return False
		# Normalize for case-insensitive comparison
		normalized_value = ioc_value.lower().strip()
		normalized_allowlist = [str(v).lower().strip() for v in allowlist_values]
		return normalized_value in normalized_allowlist


class SuppressionEngine:
	"""Apply allowlist suppression logic to indicators."""

	def __init__(self, config_loader: TriageConfigLoader, allowlist_loader: AllowlistLoader) -> None:
		self._config = config_loader
		self._allowlist = allowlist_loader

	def evaluate(self, indicators: List[Dict[str, Any]]) -> Dict[str, Any]:
		"""
		Check indicators against allowlist and return suppression result.
		
		Returns:
			{
				"allowlisted_count": int,
				"total_count": int,
				"is_fully_suppressed": bool,
				"severity_penalty": int,
				"tags": List[str]
			}
		"""
		total_count = len(indicators)
		allowlisted_count = 0

		for indicator in indicators:
			if not isinstance(indicator, dict):
				continue
			ioc_type = indicator.get("type", "")
			ioc_value = indicator.get("value", "")
			if not ioc_type or not ioc_value:
				continue
			if self._allowlist.is_allowlisted(ioc_type, ioc_value):
				allowlisted_count += 1

		is_fully_suppressed = (allowlisted_count > 0 and allowlisted_count == total_count)
		penalty = self._config.get_allowlist_penalty()

		tags = []
		if allowlisted_count > 0:
			tags.append("allowlisted")
		if is_fully_suppressed:
			tags.append("suppressed")

		return {
			"allowlisted_count": allowlisted_count,
			"total_count": total_count,
			"is_fully_suppressed": is_fully_suppressed,
			"severity_penalty": penalty if allowlisted_count > 0 else 0,
			"tags": tags
		}


class BucketClassifier:
	"""Classify severity score into risk bucket."""

	def __init__(self, config_loader: TriageConfigLoader) -> None:
		self._config = config_loader

	def classify(self, severity_score: int) -> str:
		"""
		Classify a severity score into a bucket.
		
		Args:
			severity_score: Score 0-100
		
		Returns:
			Bucket name: "Suppressed", "Low", "Medium", "High", or "Critical"
		"""
		return self._config.get_bucket_for_score(severity_score)


class MitreMapper:
	"""Map alert types to MITRE ATT&CK techniques."""

	def __init__(self, config_loader: TriageConfigLoader) -> None:
		self._config = config_loader
		self._mapping = self._load_mapping()

	def _load_mapping(self) -> Dict[str, Any]:
		"""Load MITRE mapping from YAML file."""
		mapping_path = self._config.get_mitre_mapping_path()
		if not mapping_path or not os.path.isfile(mapping_path):
			return {}
		
		try:
			with open(mapping_path, "r", encoding="utf-8") as f:
				data = yaml.safe_load(f) or {}
				return data
		except Exception:
			# Graceful degradation: malformed YAML or read error
			return {}

	def get_techniques(self, alert_type: str) -> List[str]:
		"""
		Get MITRE ATT&CK techniques for an alert type.
		
		Args:
			alert_type: Alert type string (e.g., "CredentialAccess")
		
		Returns:
			List of technique codes (e.g., ["T1056", "T1555"])
			Returns defaults if type not found or empty list if no defaults
		"""
		if not isinstance(alert_type, str) or not alert_type.strip():
			return self._mapping.get("defaults", [])
		
		# Look up alert type in types section (case-sensitive)
		types_map = self._mapping.get("types", {})
		if alert_type in types_map:
			techniques = types_map[alert_type]
			if isinstance(techniques, list):
				return techniques
		
		# Return defaults if not found
		defaults = self._mapping.get("defaults", [])
		return defaults if isinstance(defaults, list) else []

