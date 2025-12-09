'''
IOC Enrichment

Purpose: Enrich observables with threat intelligence data.

Responsibilities:
- Match IOCs against local TI data
- Merge risk assessments from multiple providers
- Provide verdict and confidence scores

Design notes:
- Stateless and idempotent
- Easy to swap with real TI feeds
- Multiple provider support with risk merging
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

	# Validate indicators list presence
	if not isinstance(alert.get("indicators"), list):
		raise ValueError("alert must contain 'indicators' as a list")

	# Validate each indicator in the list
	indicators_list = alert.get("indicators", [])
	for item in indicators_list:
		if not isinstance(item, dict):
			raise ValueError("each indicator must be a dict")
		if "type" not in item or "value" not in item:
			raise ValueError("each indicator must have 'type' and 'value'")
		if not isinstance(item["type"], str) or not item["type"].strip():
			raise ValueError("indicator 'type' must be a non-empty string")
		if not isinstance(item["value"], str) or not item["value"].strip():
			raise ValueError("indicator 'value' must be a non-empty string")


def _get_indicators_for_enrichment(alert: Dict[str, Any]) -> List[Dict[str, Any]]:
	"""Get indicators from alert for enrichment (returns reference, not copy)."""
	# Return reference to the indicators list for in-place modification
	return alert.get("indicators", [])


def enrich(alert: Dict[str, Any]) -> Dict[str, Any]:
	"""Enrich an alert by adding risk data directly to indicators."""
	_validate_alert(alert)
	ti = _get_mock_ti()

	indicators = _get_indicators_for_enrichment(alert)

	# Enrich each indicator in-place by adding risk field
	for indicator in indicators:
		ioc_type = indicator.get("type")
		ioc_value = indicator.get("value")
		
		# Skip malformed indicators
		if not isinstance(ioc_type, str) or not isinstance(ioc_value, str):
			continue

		# Query TI and get risk data
		ioc_result = ti.query_ioc(ioc_type, ioc_value)
		
		# Add risk field directly to indicator
		indicator["risk"] = ioc_result["risk"]

	return alert

