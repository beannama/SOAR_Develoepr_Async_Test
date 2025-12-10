'''
Response Playbooks

Purpose: Execute automated response actions based on triage decisions.

Current behavior:
- Simulate device isolation by writing to output/isolation.log

Why simulated:
- No destructive actions
- Safe demonstration of SOAR concepts

Response Actions:
- Device Isolation: Isolate devices with severity >= 70 (unless allowlisted)

Extensible to:
- Ticket creation
- User disablement
- Firewall blocking
- Email notifications
'''

import os
from typing import Any, Dict

from SOAR.Response.device_allowlist_checker import ResponseConfigLoader, AllowlistLoader
from SOAR.Response.isolation_executor import DeviceIsolationExecutor

__all__ = ["respond"]


def _build_config_path() -> str:
	"""Build path to response config.yml."""
	response_dir = os.path.dirname(__file__)
	return os.path.join(response_dir, "config.yml")


_CONFIG_LOADER: ResponseConfigLoader | None = None
_ALLOWLIST_LOADER: AllowlistLoader | None = None
_DEVICE_ISOLATION_EXECUTOR: DeviceIsolationExecutor | None = None


def _get_components():
	"""Lazy-load response components (singletons)."""
	global _CONFIG_LOADER, _ALLOWLIST_LOADER, _DEVICE_ISOLATION_EXECUTOR
	if _CONFIG_LOADER is None:
		config_path = _build_config_path()
		_CONFIG_LOADER = ResponseConfigLoader(config_path)
		allowlist_path = _CONFIG_LOADER.get_allowlist_path()
		_ALLOWLIST_LOADER = AllowlistLoader(allowlist_path)
		_DEVICE_ISOLATION_EXECUTOR = DeviceIsolationExecutor(_CONFIG_LOADER, _ALLOWLIST_LOADER)
	return _CONFIG_LOADER, _ALLOWLIST_LOADER, _DEVICE_ISOLATION_EXECUTOR


def _validate_triaged_alert(alert: Dict[str, Any]) -> None:
	"""Validate that alert has required triage and incident data."""
	if not isinstance(alert, dict):
		raise ValueError("alert must be a dictionary")
	
	if "incident_id" not in alert or not isinstance(alert.get("incident_id"), str):
		raise ValueError("alert['incident_id'] must be a non-empty string")
	
	if "triage" not in alert or not isinstance(alert.get("triage"), dict):
		raise ValueError("alert['triage'] must be a dictionary")
	
	triage = alert["triage"]
	if "severity_score" not in triage or not isinstance(triage.get("severity_score"), (int, float)):
		raise ValueError("alert['triage']['severity_score'] must be a number")


def respond(alert: Dict[str, Any]) -> Dict[str, Any]:
	"""
	Execute response actions based on triaged alert.
	
	Current actions:
	- Device Isolation: Check if device should be isolated, log if needed
	
	Args:
		alert: Triaged alert with incident_id and triage data
	
	Returns:
		Alert with response block added
	
	Raises:
		ValueError: If alert structure is invalid
	"""
	_validate_triaged_alert(alert)
	config_loader, allowlist_loader, device_isolation_executor = _get_components()
	
	# Get severity and device info
	severity_score = alert["triage"]["severity_score"]
	device_id = alert.get("asset", {}).get("device_id", "")
	incident_id = alert.get("incident_id", "")
	
	# Evaluate device isolation
	should_isolate = device_isolation_executor.should_isolate(severity_score, device_id)

	if should_isolate:
		# Execute isolation action
		device_isolation_executor.execute_isolation(device_id, incident_id)
	

	
	result = alert.copy()
	
	return result
