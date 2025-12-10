"""
Timeline Manager

Purpose: Maintain a per-alert timeline of processing stages.

Responsibilities:
- Initialize a timeline array on alerts
- Add stage entries with ISO UTC timestamps
- Validate timeline structure before export

Stages supported: ingest, normalize, enrich, triage, respond
"""

from __future__ import annotations
from typing import Any, Dict, List
from datetime import datetime

__all__ = ["TimelineManager", "TIMELINE_STAGES"]

TIMELINE_STAGES = {"ingest", "normalize", "enrich", "triage", "respond"}


class TimelineManager:
	"""Manage timeline lifecycle for alerts."""

	def __init__(self) -> None:
		self._iso_format = "%Y-%m-%dT%H:%M:%SZ"

	def _now(self) -> str:
		"""Return current UTC time as ISO string."""
		return datetime.utcnow().strftime(self._iso_format)

	def initialize(self, alert: Dict[str, Any]) -> Dict[str, Any]:
		"""Ensure alert has an empty timeline list."""
		if not isinstance(alert, dict):
			raise ValueError("alert must be a dictionary to initialize timeline")
		if "timeline" not in alert or not isinstance(alert.get("timeline"), list):
			alert["timeline"] = []
		return alert

	def add_entry(self, alert: Dict[str, Any], stage: str, details: str) -> Dict[str, Any]:
		"""Append a timeline entry with validation."""
		if not isinstance(alert, dict):
			raise ValueError("alert must be a dictionary when adding timeline entries")
		if stage not in TIMELINE_STAGES:
			raise ValueError(f"stage must be one of {sorted(TIMELINE_STAGES)}")
		if not isinstance(details, str) or not details.strip():
			raise ValueError("details must be a non-empty string")

		if "timeline" not in alert or not isinstance(alert.get("timeline"), list):
			alert["timeline"] = []

		entry = {"stage": stage, "ts": self._now(), "details": details.strip()}
		alert["timeline"].append(entry)
		return alert

	def validate(self, alert: Dict[str, Any]) -> None:
		"""Validate timeline structure for export."""
		timeline = alert.get("timeline") if isinstance(alert, dict) else None
		if timeline is None:
			raise ValueError("timeline missing from alert")
		if not isinstance(timeline, list):
			raise ValueError("timeline must be a list")

		for entry in timeline:
			if not isinstance(entry, dict):
				raise ValueError("each timeline entry must be a dict")
			stage = entry.get("stage")
			ts = entry.get("ts")
			details = entry.get("details")

			if stage not in TIMELINE_STAGES:
				raise ValueError("timeline entry stage invalid")
			if not isinstance(ts, str) or not ts.strip():
				raise ValueError("timeline entry ts must be a non-empty string")
			if not isinstance(details, str) or not details.strip():
				raise ValueError("timeline entry details must be a non-empty string")

		# Optional ordering check: stages should not go backwards
		stage_order = {name: idx for idx, name in enumerate(sorted(TIMELINE_STAGES))}
		prev = -1
		for entry in timeline:
			stage_idx = stage_order.get(entry.get("stage"), -1)
			if stage_idx < prev:
				raise ValueError("timeline stages appear out of order")
			prev = stage_idx

	def get(self, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
		"""Return timeline list or empty list if missing."""
		if not isinstance(alert, dict):
			return []
		timeline = alert.get("timeline")
		return timeline if isinstance(timeline, list) else []
