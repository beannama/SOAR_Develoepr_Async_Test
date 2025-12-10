'''
Orchestrator

Single responsibility: glue the pipeline together.

Responsibilities:
- Parse CLI arguments
- Call each pipeline stage in order
- Decide whether a response playbook should execute

This file contains no business logic.

'''
import argparse
import os
import json


def parse_args():
    p = argparse.ArgumentParser(description="Tiny SOAR Pipeline")
    p.add_argument("input", nargs="?", help="Alert JSON path")
    p.add_argument("--outdir", "-o", default="out")
    p.add_argument("--sample", action="store_true")
    return p.parse_args()


from SOAR.Ingest.loader import load_alert
from SOAR.Normalize.normalize import normalize
from SOAR.Enrichment.enricher import enrich
from SOAR.Triage.triage import triage
from SOAR.Response.response import respond
from SOAR.Reporting.incident_exporter import export_incident
from SOAR.Reporting.summary_renderer import render_summary
from SOAR.Timeline.timeline_manager import TimelineManager

def main():
    args = parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    os.makedirs(os.path.join(args.outdir, "incidents"), exist_ok=True)
    os.makedirs(os.path.join(args.outdir, "summaries"), exist_ok=True)

    timeline = TimelineManager()

    alert = load_alert(path=args.input, use_sample=args.sample)
    alert = timeline.initialize(alert)
    alert = timeline.add_entry(alert, "ingest", "Alert loaded")
   
    # Normalize alert prior to enrichment and triage
    alert = normalize(alert)
    alert = timeline.add_entry(alert, "ingest", f"Incident created: {alert.get('incident_id', '')}")

    # Enrich alert with local mock TI (multi-provider)
    alert = enrich(alert)
    indicator_count = len(alert.get("indicators", [])) if isinstance(alert.get("indicators"), list) else 0
    alert = timeline.add_entry(alert, "enrich", f"Enriched indicators: {indicator_count}")

    # Triage alert with deterministic rules
    alert = triage(alert)
    triage_data = alert.get("triage", {}) if isinstance(alert.get("triage"), dict) else {}
    severity = triage_data.get("severity_score", triage_data.get("severity", 0))
    bucket = triage_data.get("bucket", "Unknown")
    alert = timeline.add_entry(alert, "triage", f"Severity {severity}, Bucket {bucket}")

    # Execute response actions
    alert = respond(alert)
    action_count = len(alert.get("actions", [])) if isinstance(alert.get("actions"), list) else 0
    alert = timeline.add_entry(alert, "respond", f"Actions executed: {action_count}")

    # Export incident to JSON
    export_incident(alert, args.outdir)

    # Generate Markdown summary
    render_summary(alert, args.outdir)

if __name__ == "__main__":
    main()
