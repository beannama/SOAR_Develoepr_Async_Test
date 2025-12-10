"""
Markdown Summary Renderer

Purpose: Generate human-readable Markdown analyst summaries from incident data.

Responsibilities:
- Transform incident data into template-friendly format
- Load and render Jinja2 templates
- Write Markdown summaries to out/summaries/<incident_id>.md

Design notes:
- Reuses IncidentDataExtractor from incident_exporter
- Jinja2 templates for flexible formatting
- Graceful fallback if template missing
"""

import os
from typing import Any, Dict, List
from datetime import datetime

try:
	from jinja2 import Environment, FileSystemLoader, Template, select_autoescape
	JINJA2_AVAILABLE = True
except ImportError:
	JINJA2_AVAILABLE = False

from SOAR.Reporting.incident_exporter import IncidentDataExtractor, _get_allowlist_loader

__all__ = ["render_summary"]


class SummaryDataTransformer:
	"""Transform extracted incident data into template-ready format."""
	
	def __init__(self, extracted_data: Dict[str, Any]) -> None:
		self._data = extracted_data
	
	def transform_incident_overview(self) -> Dict[str, str]:
		"""Extract incident overview fields."""
		source_alert = self._data.get("source_alert", {})
		return {
			"id": self._data.get("incident_id", ""),
			"created_at": source_alert.get("created_at", ""),
			"source": source_alert.get("source", ""),
			"type": source_alert.get("type", "")
		}
	
	def transform_asset(self) -> Dict[str, str]:
		"""Extract asset information."""
		asset = self._data.get("asset", {})
		return {
			"device_id": asset.get("device_id", ""),
			"hostname": asset.get("hostname", ""),
			"ip": asset.get("ip", "")
		}
	
	def transform_indicators_table(self) -> List[Dict[str, Any]]:
		"""
		Transform indicators into table-friendly format.
		
		Extracts: type, value, verdict, score, allowlisted
		"""
		indicators = self._data.get("indicators", [])
		result = []
		
		for indicator in indicators:
			if not isinstance(indicator, dict):
				continue
			
			risk = indicator.get("risk", {})
			if not isinstance(risk, dict):
				risk = {}
			
			result.append({
				"type": indicator.get("type", ""),
				"value": indicator.get("value", ""),
				"verdict": risk.get("verdict", "unknown"),
				"score": risk.get("score", 0),
				"allowlisted": indicator.get("allowlisted", False)
			})
		
		return result
	
	def transform_severity_section(self) -> Dict[str, Any]:
		"""Extract severity and triage data."""
		triage = self._data.get("triage", {})
		if not isinstance(triage, dict):
			return {
				"score": 0,
				"bucket": "Unknown",
				"tags": [],
				"suppressed": False
			}
		
		return {
			"score": triage.get("severity", 0),
			"bucket": triage.get("bucket", "Unknown"),
			"tags": triage.get("tags", []),
			"suppressed": triage.get("suppressed", False)
		}
	
	def transform_mitre_techniques(self) -> Dict[str, List[str]]:
		"""Extract MITRE ATT&CK techniques."""
		mitre = self._data.get("mitre", {})
		if not isinstance(mitre, dict):
			return {"techniques": []}
		
		techniques = mitre.get("techniques", [])
		if not isinstance(techniques, list):
			return {"techniques": []}
		
		return {"techniques": techniques}
	
	def transform_actions_section(self) -> List[Dict[str, str]]:
		"""Extract actions taken."""
		actions = self._data.get("actions", [])
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

	def transform_timeline(self) -> List[Dict[str, str]]:
		"""Extract timeline entries."""
		timeline = self._data.get("timeline", [])
		if not isinstance(timeline, list):
			return []
		return timeline
	
	def transform(self) -> Dict[str, Any]:
		"""
		Transform all data into template context.
		
		Returns dict with all template variables.
		"""
		return {
			"incident": self.transform_incident_overview(),
			"asset": self.transform_asset(),
			"indicators": self.transform_indicators_table(),
			"severity": self.transform_severity_section(),
			"mitre": self.transform_mitre_techniques(),
			"actions": self.transform_actions_section(),
			"timeline": self.transform_timeline(),
			"summary_generated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
		}


class MarkdownTemplateLoader:
	"""Load and manage Jinja2 templates for Markdown rendering."""
	
	def __init__(self) -> None:
		self._template_dir = self._get_template_dir()
	
	def _get_template_dir(self) -> str:
		"""Get absolute path to templates directory."""
		reporting_dir = os.path.dirname(__file__)
		return os.path.join(reporting_dir, "templates")
	
	def _create_inline_fallback(self) -> str:
		"""
		Create inline template as fallback if file not found.
		
		Returns simple text-based template.
		"""
		return """# Incident Report: {{ incident.id }}

Generated: {{ summary_generated_at }}

---

## Incident Overview

- Incident ID: {{ incident.id }}
- Created: {{ incident.created_at }}
- Source: {{ incident.source }}
- Alert Type: {{ incident.type }}
{% if asset.device_id -%}
- Affected Asset: {{ asset.device_id }}
{% endif %}

## Indicators

{% if indicators -%}
{% for indicator in indicators -%}
- {{ indicator.type }}: {{ indicator.value }} ({{ indicator.verdict }}, score: {{ indicator.score }})
{% endfor %}
{% else -%}
No indicators found.
{% endif %}

## Severity

- Score: {{ severity.score }}/100
- Classification: {{ severity.bucket }}
- Suppressed: {{ 'Yes' if severity.suppressed else 'No' }}

## MITRE Techniques

{% if mitre.techniques -%}
{% for technique in mitre.techniques -%}
- {{ technique }}
{% endfor %}
{% else -%}
No MITRE techniques mapped.
{% endif %}

## Actions Taken

{% if actions -%}
{% for action in actions -%}
- {{ action.ts }} - {{ action.type }}: {{ action.target }} -> {{ action.result }}
{% endfor %}
{% else -%}
No automated response actions executed.
{% endif %}

---
End of Report
"""
	
	def load_template(self) -> Template:
		"""
		Load Jinja2 template from file or use inline fallback.
		
		Returns:
			Jinja2 Template object
		
		Raises:
			RuntimeError: If Jinja2 is not installed
		"""
		if not JINJA2_AVAILABLE:
			raise RuntimeError("Jinja2 is required but not installed. Run: pip install Jinja2")
		
		template_file = "analyst_summary.md.j2"
		template_path = os.path.join(self._template_dir, template_file)
		
		# Try to load from file
		if os.path.isfile(template_path):
			try:
				env = Environment(
					loader=FileSystemLoader(self._template_dir),
					autoescape=select_autoescape(['html', 'xml']),
					trim_blocks=True,
					lstrip_blocks=True
				)
				return env.get_template(template_file)
			except Exception:
				# Fall through to inline template
				pass
		
		# Use inline fallback template
		env = Environment(
			autoescape=select_autoescape(['html', 'xml']),
			trim_blocks=True,
			lstrip_blocks=True
		)
		return env.from_string(self._create_inline_fallback())


def render_summary(alert: Dict[str, Any], output_dir: str) -> bool:
	"""
	Render Markdown analyst summary from processed alert.
	
	Args:
		alert: Fully processed alert from respond() stage
		output_dir: Base output directory (e.g., "out")
	
	Returns:
		True if rendering succeeded, False otherwise
	
	Raises:
		ValueError: If alert structure is invalid
		RuntimeError: If Jinja2 is not installed
	"""
	try:
		# Check Jinja2 availability
		if not JINJA2_AVAILABLE:
			import sys
			print("Warning: Jinja2 not installed. Skipping Markdown summary generation.", file=sys.stderr)
			print("Install with: pip install Jinja2", file=sys.stderr)
			return False
		
		# Extract data using shared extractor
		allowlist_loader = _get_allowlist_loader()
		extractor = IncidentDataExtractor(allowlist_loader)
		extracted_data = extractor.extract(alert)
		
		# Transform data for template
		transformer = SummaryDataTransformer(extracted_data)
		context = transformer.transform()
		
		# Load template
		template_loader = MarkdownTemplateLoader()
		template = template_loader.load_template()
		
		# Render Markdown
		markdown_content = template.render(**context)
		
		# Ensure summaries directory exists
		summaries_dir = os.path.join(output_dir, "summaries")
		os.makedirs(summaries_dir, exist_ok=True)
		
		# Write to file
		incident_id = context["incident"]["id"]
		file_path = os.path.join(summaries_dir, f"{incident_id}.md")
		
		with open(file_path, "w", encoding="utf-8") as f:
			f.write(markdown_content)
		
		return True
	
	except Exception as e:
		# Graceful degradation: log error but don't break pipeline
		import sys
		print(f"Error rendering summary: {e}", file=sys.stderr)
		return False
