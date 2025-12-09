'''
IOC Enrichment

Purpose: Enrich observables with threat context.

Responsibilities:
- Match IOCs against mock_ti
- Attach threat level, confidence, notes
- Flag whitelisted indicators
Design notes:
- Stateless and idempotent
- Easy to swap with real TI feeds
'''

import os
from typing import Any, Dict, List

from SOAR.Enrichment.mock_ti import MockTI

__all__ = ["enrich"]


def _build_paths() -> Dict[str, str]:
	"""Resolve config and TI directories relative to this module."""
	enrichment_dir = os.path.dirname(__file__)
	soar_root = os.path.dirname(enrichment_dir)
	return {
		"config_dir": os.path.join(soar_root, "configs"),
		"ti_dir": os.path.join(enrichment_dir, "mocks", "it"),
	}


_MOCK_TI = None


def _get_mock_ti() -> MockTI:
	"""Lazy-load a singleton MockTI instance."""
	global _MOCK_TI
	if _MOCK_TI is None:
		paths = _build_paths()
		_MOCK_TI = MockTI(paths["config_dir"], paths["ti_dir"])
	return _MOCK_TI


def _validate_alert(alert: Dict[str, Any]) -> None:
	"""Strictly validate alert structure before enrichment."""
	if not isinstance(alert, dict):
		raise ValueError("alert must be a dict")

	if "type" not in alert:
		raise ValueError("alert must contain 'type'")

	if not isinstance(alert.get("type"), str) or not alert["type"].strip():
		raise ValueError("alert['type'] must be a non-empty string")

	# Validate indicators presence in either normalized list or legacy dict
	has_norm_list = isinstance(alert.get("normalized_indicators"), list)
	has_incident_list = isinstance(alert.get("incident", {}).get("indicators"), list)
	has_dict = isinstance(alert.get("indicators"), dict)

	if not (has_norm_list or has_incident_list or has_dict):
		raise ValueError("alert must contain indicators (normalized list or indicators dict)")

	# Validate normalized list if present
	def _validate_list(indicators_list: List[Any]) -> None:
		for item in indicators_list:
			if not isinstance(item, dict):
				raise ValueError("normalized indicators must be dict entries")
			if "type" not in item or "value" not in item:
				raise ValueError("each indicator must have 'type' and 'value'")
			if not isinstance(item["type"], str) or not item["type"].strip():
				raise ValueError("indicator 'type' must be a non-empty string")
			if not isinstance(item["value"], str) or not item["value"].strip():
				raise ValueError("indicator 'value' must be a non-empty string")

	if has_norm_list:
		_validate_list(alert["normalized_indicators"])
	if has_incident_list:
		_validate_list(alert["incident"]["indicators"])

	if has_dict:
		indicators = alert.get("indicators")
		for ioc_type, values in indicators.items():
			if not isinstance(values, list):
				raise ValueError(f"alert['indicators'][{ioc_type!r}] must be a list")
			for v in values:
				if not isinstance(v, str):
					raise ValueError(f"IOC values for {ioc_type!r} must be strings")


def _get_indicator_list(alert: Dict[str, Any]) -> List[Dict[str, str]]:
	"""Extract indicators as a list of {type, value}, preferring normalized data."""
	if isinstance(alert.get("normalized_indicators"), list):
		return alert["normalized_indicators"]
	if isinstance(alert.get("incident", {}).get("indicators"), list):
		return alert["incident"]["indicators"]

	# Fallback: legacy dict -> convert to list
	indicators_dict = alert.get("indicators", {})
	flattened: List[Dict[str, str]] = []
	for ioc_type, values in indicators_dict.items():
		if not isinstance(values, list):
			continue
		for value in values:
			if isinstance(value, str):
				flattened.append({"type": ioc_type, "value": value})
	return flattened


def enrich(alert: Dict[str, Any]) -> Dict[str, Any]:
	"""Enrich an alert with TI data and MITRE mapping using mock_ti."""
	_validate_alert(alert)
	ti = _get_mock_ti()

	indicators = _get_indicator_list(alert)

	# Build IOC enrichment and summary
	enrichment = {
		"enriched_iocs": [],
		"summary": {
			"total_iocs": 0,
			"malicious": 0,
			"suspicious": 0,
			"clean": 0,
			"whitelisted": 0,
			"unknown": 0,
		},
	}

	for indicator in indicators:
		ioc_type = indicator.get("type")
		ioc_value = indicator.get("value")
		if not isinstance(ioc_type, str) or not isinstance(ioc_value, str):
			continue

		ioc_result = ti.query_ioc(ioc_type, ioc_value)
		enrichment["enriched_iocs"].append(ioc_result)
		enrichment["summary"]["total_iocs"] += 1

		if ioc_result["whitelisted"]:
			enrichment["summary"]["whitelisted"] += 1
		elif ioc_result["threat_level"] == "malicious":
			enrichment["summary"]["malicious"] += 1
		elif ioc_result["threat_level"] == "suspicious":
			enrichment["summary"]["suspicious"] += 1
		elif ioc_result["threat_level"] == "clean":
			enrichment["summary"]["clean"] += 1
		else:
			enrichment["summary"]["unknown"] += 1

	enriched_alert = alert.copy()
	enriched_alert["enrichment"] = enrichment
	return enriched_alert

