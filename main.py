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
    p.add_argument("--input", "-i", help="Alert JSON path")
    p.add_argument("--outdir", "-o", default="output")
    p.add_argument("--sample", action="store_true")
    return p.parse_args()


from SOAR.Ingest.loader import load_alert
from SOAR.Enrichment.enricher import enrich

def main():
    args = parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    alert = load_alert(path=args.input, use_sample=args.sample)

    # Enrich alert with local mock TI and MITRE mapping
    alert = enrich(alert)

    pretty_print = json.dumps(alert, indent=2)
    print(pretty_print)

if __name__ == "__main__":
    main()
