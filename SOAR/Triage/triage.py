'''
Deterministic Triage Engine

Purpose: Decide how bad the alert is and what it represents.

Responsibilities:
- Suppression logic (all IOCs whitelisted)
- Severity scoring (1–100)
- Tagging (phishing, malware, C2, etc.)
- MITRE ATT&CK technique aggregation

Why deterministic:
- Fully auditable
- Predictable outcomes
- Preferred in regulated environments
'''