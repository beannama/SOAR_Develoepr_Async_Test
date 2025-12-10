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

def main():
    args = parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    os.makedirs(os.path.join(args.outdir, "incidents"), exist_ok=True)

    alert = load_alert(path=args.input, use_sample=args.sample)
   
    # Normalize alert prior to enrichment and triage
    alert = normalize(alert)

    # Enrich alert with local mock TI (multi-provider)
    alert = enrich(alert)

    # Triage alert with deterministic rules
    alert = triage(alert)

    # Execute response actions
    alert = respond(alert)

    pretty_print = json.dumps(alert, indent=2)
    print(pretty_print)
if __name__ == "__main__":
    main()
