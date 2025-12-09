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
from typing import Any, Dict

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

	if "indicators" not in alert or "type" not in alert:
		raise ValueError("alert must contain 'indicators' and 'type'")

	indicators = alert.get("indicators")
	if not isinstance(indicators, dict):
		raise ValueError("alert['indicators'] must be a dict")

	for ioc_type, values in indicators.items():
		if not isinstance(values, list):
			raise ValueError(f"alert['indicators'][{ioc_type!r}] must be a list")
		for v in values:
			if not isinstance(v, str):
				raise ValueError(f"IOC values for {ioc_type!r} must be strings")

	if not isinstance(alert.get("type"), str) or not alert["type"].strip():
		raise ValueError("alert['type'] must be a non-empty string")


def enrich(alert: Dict[str, Any]) -> Dict[str, Any]:
	"""Enrich an alert with TI data and MITRE mapping using mock_ti."""
	_validate_alert(alert)
	ti = _get_mock_ti()

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

	for ioc_type, ioc_list in alert.get("indicators", {}).items():
		if not isinstance(ioc_list, list):
			continue

		for ioc_value in ioc_list:
			if not isinstance(ioc_value, str):
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

	mitre_techniques = ti.get_mitre_techniques(alert.get("type", ""))

	enriched_alert = alert.copy()
	enriched_alert["enrichment"] = enrichment
	enriched_alert["mitre_techniques"] = mitre_techniques
	return enriched_alert

