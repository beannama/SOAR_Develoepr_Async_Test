"""
Device Isolation Executor

Responsibilities:
- Evaluate if a device should be isolated
- Generate isolation log entries
- Execute isolation action (write to log file)
"""

import os
from typing import Any, Dict
from datetime import datetime

from SOAR.Response.device_allowlist_checker import ResponseConfigLoader, AllowlistLoader

__all__ = ["DeviceIsolationExecutor"]


class DeviceIsolationExecutor:
	"""Execute device isolation response action."""

	def __init__(self, config_loader: ResponseConfigLoader, allowlist_loader: AllowlistLoader) -> None:
		self._config = config_loader
		self._allowlist = allowlist_loader

	def should_isolate(self, severity_score: int, device_id: str) -> bool:
		"""
		Determine if a device should be isolated.
		
		Conditions (all must be true):
		1. Isolation is enabled in config
		2. Severity score >= threshold (default 70)
		3. Device ID is present and non-empty
		4. Device ID is NOT in allowlist
		
		Args:
			severity_score: Severity score 0-100 (from triage)
			device_id: Device ID from alert asset
		
		Returns:
			True if device should be isolated, False otherwise
		"""
		# Check if isolation is enabled
		if not self._config.is_isolation_enabled():
			return False
		
		# Check severity threshold
		threshold = self._config.get_isolation_threshold()
		if not isinstance(severity_score, (int, float)) or severity_score < threshold:
			return False
		
		# Check device_id is present
		if not isinstance(device_id, str) or not device_id.strip():
			return False
		
		# Check device is NOT allowlisted
		if self._allowlist.is_device_allowlisted(device_id):
			return False
		
		return True

	def generate_isolation_log_entry(self, device_id: str, incident_id: str) -> str:
		"""
		Generate a log entry for device isolation.
		
		Format: <ISO-TS> isolate device_id=<ID> incident=<INCIDENT_ID> result=isolated
		Example: 2025-12-09T15:30:45Z isolate device_id=dev-9001 incident=INC-20250809T140310Z-a7f2b1c3 result=isolated
		
		Args:
			device_id: Device ID being isolated
			incident_id: Incident ID that triggered the isolation
		
		Returns:
			Formatted log entry string
		
		Raises:
			ValueError: If device_id or incident_id is invalid
		"""
		if not isinstance(device_id, str) or not device_id.strip():
			raise ValueError("device_id must be a non-empty string")
		if not isinstance(incident_id, str) or not incident_id.strip():
			raise ValueError("incident_id must be a non-empty string")
		
		# Generate ISO timestamp
		iso_timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
		
		# Format: <ISO-TS> isolate device_id=<ID> incident=<INCIDENT_ID> result=isolated
		return f"{iso_timestamp} isolate device_id={device_id} incident={incident_id} result=isolated"

	def execute_isolation(self, device_id: str, incident_id: str) -> bool:
		"""
		Execute device isolation by writing to isolation log.
		
		Args:
			device_id: Device ID to isolate
			incident_id: Incident ID triggering isolation
		
		Returns:
			True if isolation was logged successfully, False otherwise
		"""
		try:
			# Generate log entry
			log_entry = self.generate_isolation_log_entry(device_id, incident_id)
			
			# Get log path
			log_path = self._config.get_isolation_log_path()
			if not log_path:
				return False
			
			# Ensure log directory exists
			log_dir = os.path.dirname(log_path)
			if log_dir:
				os.makedirs(log_dir, exist_ok=True)
			
			# Append to log file
			with open(log_path, "a", encoding="utf-8") as f:
				f.write(log_entry + "\n")
			
			return True
		except Exception:
			# Graceful degradation: log failures don't break the pipeline
			return False

	def generate_action_entry(self, device_id: str, incident_id: str) -> Dict[str, str]:
		"""
		Generate a structured action entry for response tracking.
		
		This is separate from logging to allow Response stage to track actions
		in the alert JSON while also maintaining the isolation.log file.
		
		Args:
			device_id: Device ID being isolated
			incident_id: Incident ID that triggered the isolation
		
		Returns:
			Dict with keys: type, target, result, ts
			Example: {"type": "isolate", "target": "device:dev-9001", "result": "isolated", "ts": "2025-12-09T15:30:45Z"}
		
		Raises:
			ValueError: If device_id or incident_id is invalid
		"""
		if not isinstance(device_id, str) or not device_id.strip():
			raise ValueError("device_id must be a non-empty string")
		if not isinstance(incident_id, str) or not incident_id.strip():
			raise ValueError("incident_id must be a non-empty string")
		
		# Generate ISO timestamp
		iso_timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
		
		# Return action dictionary
		return {
			"type": "isolate",
			"target": f"device:{device_id}",
			"result": "isolated",
			"ts": iso_timestamp
		}

