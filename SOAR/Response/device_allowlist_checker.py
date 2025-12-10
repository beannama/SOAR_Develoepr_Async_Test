"""
Device Isolation - Allowlist and Configuration

Responsibilities:
- Load device allowlist from YAML
- Check if device is allowlisted (should not be isolated)
- Load response configuration
"""

import os
from typing import Any, Dict, List

import yaml

__all__ = ["ResponseConfigLoader", "AllowlistLoader"]


class ResponseConfigLoader:
	"""Load response configuration (device isolation rules, etc)."""

	def __init__(self, config_path: str) -> None:
		self._config_path = config_path
		self._config = self._load()

	def _load(self) -> Dict[str, Any]:
		if not os.path.isfile(self._config_path):
			raise FileNotFoundError(f"Response config not found: {self._config_path}")
		with open(self._config_path, "r", encoding="utf-8") as f:
			return yaml.safe_load(f) or {}

	@property
	def device_isolation_config(self) -> Dict[str, Any]:
		return self._config.get("device_isolation", {}) or {}

	def is_isolation_enabled(self) -> bool:
		"""Check if device isolation is enabled."""
		return bool(self.device_isolation_config.get("enabled", True))

	def get_isolation_threshold(self) -> int:
		"""Get severity threshold for device isolation."""
		return int(self.device_isolation_config.get("severity_threshold", 70))

	def get_allowlist_path(self) -> str:
		"""Get absolute path to allowlist file."""
		rel_path = self.device_isolation_config.get("allowlist_path", "")
		if not rel_path:
			return ""
		config_dir = os.path.dirname(self._config_path)
		return os.path.normpath(os.path.join(config_dir, rel_path))

	def get_isolation_log_path(self) -> str:
		"""Get absolute path to isolation log file."""
		rel_path = self.device_isolation_config.get("log_path", "")
		if not rel_path:
			return ""
		config_dir = os.path.dirname(self._config_path)
		return os.path.normpath(os.path.join(config_dir, rel_path))


class AllowlistLoader:
	"""Load and check device allowlist from YAML."""

	def __init__(self, allowlist_path: str) -> None:
		self._allowlist_path = allowlist_path
		self._allowlist = self._load()

	def _load(self) -> Dict[str, Any]:
		"""Load allowlist from YAML file."""
		if not self._allowlist_path or not os.path.isfile(self._allowlist_path):
			return {}
		
		try:
			with open(self._allowlist_path, "r", encoding="utf-8") as f:
				data = yaml.safe_load(f) or {}
				return data
		except Exception:
			# Graceful degradation: malformed YAML or read error
			return {}

	def is_device_allowlisted(self, device_id: str) -> bool:
		"""
		Check if a device is allowlisted (exempt from isolation).
		
		Args:
			device_id: Device ID to check (case-insensitive)
		
		Returns:
			True if device is in allowlist, False otherwise
		"""
		if not isinstance(device_id, str) or not device_id.strip():
			return False
		
		# Get device list from allowlist
		assets = self._allowlist.get("assets", {})
		device_ids = assets.get("device_ids", [])
		
		if not isinstance(device_ids, list):
			return False
		
		# Case-insensitive matching
		device_id_lower = device_id.lower()
		for allowlisted_id in device_ids:
			if isinstance(allowlisted_id, str) and allowlisted_id.lower() == device_id_lower:
				return True
		
		return False

