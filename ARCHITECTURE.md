# Tiny SOAR Pipeline – High-Level Architecture

## High-level Flow

```
Alert (JSON)
   │
   ▼
Ingest ──▶ Enrichment ──▶ Triage ──▶ Response ──▶ Outputs
                         (Rules)        (Simulated)
```

---

## Pipeline Components

### Ingest

**Purpose:** Load and validate alert data from various sources.

```
┌─────────────────────┐        ┌─────────────────────┐        ┌─────────────────────┐
│       INPUT         │        │   FUNCTION: INGEST  │        │       OUTPUT        │
├─────────────────────┤        ├─────────────────────┤        ├─────────────────────┤
│                     │        │                     │        │                     │
│ • JSON alert files  │        │ load_alert()        │        │ Normalized Alert:   │
│   (Sentinel,        │  ──▶  │                     │  ──▶   │                     │
│    SumoLogic)       │        │ • Reads JSON from   │        │ • alert_id, source  │
│ • File path or      │        │   disk              │        │ • type, created_at  │
│   --sample flag     │        │ • Returns sample    │        │ • asset (device_id, │
│                     │        │   for testing       │        │   hostname, ip)     │
│                     │        │ • Validates file    │        │ • indicators (ipv4, │
│                     │        │   existence         │        │   domains, urls,    │
│                     │        │                     │        │   sha256)           │
│                     │        │                     │        │ • raw (metadata)    │
└─────────────────────┘        └─────────────────────┘        └─────────────────────┘
```

**Module:** `SOAR/Ingest/loader.py`

---

### Enrichment

**Purpose:** Populate IOC threat intelligence risk factors from multiple providers (Defender, Anomali, ReversingLabs).

```
┌─────────────────────┐        ┌──────────────────────────┐        ┌──────────────────────────┐
│       INPUT         │        │ FUNCTION: ENRICHMENT     │        │       OUTPUT             │
├─────────────────────┤        ├──────────────────────────┤        ├──────────────────────────┤
│                     │        │                          │        │                          │
│ Normalized Alert:   │        │ enrich(alert)            │        │ Enriched Alert:          │
│ • indicators: [     │        │                          │        │ • Original alert fields  │
│   {type, value},    │  ──▶  │ • Validates indicators   │  ──▶  │ • indicators with risk:  │
│   ...               │        │ • Queries MockTI for     │        │   {type, value,          │
│ ]                   │        │   each IOC               │        │    risk: {               │
│ • alert_id, type    │        │ • Merges multi-provider  │        │      verdict,            │
│ • asset, raw        │        │   TI verdicts            │        │      score,              │
│                     │        │ • Adds risk to each      │        │      sources,             │
│                     │        │   indicator in-place     │        │      provider_details    │
│                     │        │                          │        │    }                     │
│                     │        │ Providers:               │        │   }                      │
│                     │        │ • Defender TI            │        │                          │
│                     │        │ • Anomali                │        │ Verdict Hierarchy:       │
│                     │        │ • ReversingLabs          │        │ malicious > suspicious   │
│                     │        │                          │        │ > clean > unknown        │
│                     │        │ Risk Merging:            │        │                          │
│                     │        │ • Consensus verdict      │        │                          │
│                     │        │ • Maximum score          │        │                          │
└─────────────────────┘        └──────────────────────────┘        └──────────────────────────┘
```

**Modules:** 
- `SOAR/Enrichment/enricher.py` - `enrich()`, `_validate_alert()`, `_get_indicators_for_enrichment()`
- `SOAR/Enrichment/mock_ti.py` - `MockTI.query_ioc()`, `RiskMerger`, `MockTIIndex`, `ConfigLoader`

---

### Triage

**Purpose:** Analyze enriched alerts with deterministic rules to assign severity, bucket, tags, and MITRE ATT&CK techniques.

```
┌──────────────────────┐        ┌──────────────────────┐        ┌──────────────────────┐
│       INPUT          │        │   TRIAGE LOGIC       │        │       OUTPUT         │
├──────────────────────┤        ├──────────────────────┤        ├──────────────────────┤
│                      │        │                      │        │                      │
│ Enriched Alert:      │        │ triage(alert)        │        │ Triaged Alert:       │
│ • indicators with    │        │                      │        │ • Original + enrich  │
│   risk: {verdict,    │        │ 1. Severity Score:   │        │ • triage: {          │
│   score, sources}    │  ──▶  │    • Base by type    │  ──▶  │   severity_score     │
│ • alert_id, type     │        │    • Intel boosts    │        │   (0-100)            │
│ • asset, raw         │        │    • Clamped 0-100   │        │   bucket             │
│                      │        │                      │        │   (Suppressed/Low/   │
│                      │        │ 2. Suppression:      │        │   Medium/High/       │
│                      │        │    • Check allowlist │        │   Critical)          │
│                      │        │    • Apply penalties │        │   tags: []           │
│                      │        │    • Suppress if all │        │   suppressed: bool   │
│                      │        │      allowlisted     │        │ }                    │
│                      │        │                      │        │                      │
│                      │        │ 3. Bucket:           │        │ mitre: {             │
│                      │        │    • Map severity    │        │   techniques: [...]  │
│                      │        │      to bucket       │        │ }                    │
│                      │        │                      │        │                      │
│                      │        │ 4. MITRE Mapping:    │        │ Config-driven:       │
│                      │        │    • Alert type →    │        │ • Severity params    │
│                      │        │      techniques      │        │ • Bucket ranges      │
│                      │        │    • Use defaults    │        │ • Allowlist path     │
│                      │        │      if unmapped     │        │ • MITRE mappings     │
│                      │        │                      │        │                      │
│                      │        │ Config: config.yml   │        │                      │
│                      │        │ Allowlist:           │        │                      │
│                      │        │ allowlists.yml       │        │                      │
│                      │        │                      │        │                      │
└──────────────────────┘        └──────────────────────┘        └──────────────────────┘
```

**Modules:** 
- `SOAR/Triage/triage.py` - `triage()`, `_validate_enriched_alert()`
- `SOAR/Triage/rules.py` - `TriageConfigLoader`, `SeverityScorer`, `SuppressionEngine`, `BucketClassifier`, `MitreMapper`
- `SOAR/Triage/config.yml` - Configuration (severity base, intel boosts, suppression, bucket ranges, MITRE mapping path)
- `SOAR/configs/allowlists.yml` - Allowlist data (IOCs to suppress)
- `SOAR/configs/mitre_map.yml` - MITRE mappings (alert types to techniques)

---

### Response

**Purpose:** Execute automated response actions based on triage decisions (simulate device isolation).

```
┌──────────────────────┐        ┌──────────────────────┐        ┌──────────────────────┐
│       INPUT          │        │   RESPONSE LOGIC     │        │       OUTPUT         │
├──────────────────────┤        ├──────────────────────┤        ├──────────────────────┤
│                      │        │                      │        │                      │
│ Triaged Alert:       │        │ respond(alert)       │        │ Alert (unchanged):   │
│ • incident_id        │        │                      │        │ • Original + triage  │
│ • triage: {          │        │ 1. Load Config:      │        │    + Actions         │
│   severity_score,    │  ──▶  │    • Isolation rules │  ──▶   │                      │
│   bucket,            │        │    • Threshold (70)  │        │ Isolation Log Entry: │
│   tags,              │        │    • Allowlist path  │        │ (if criteria met)    │
│   suppressed         │        │    • Log path        │        │ • Timestamp (ISO)    │
│ }                    │        │                      │        │ • device_id          │
│ • asset: {           │        │ 2. Check Allowlist:  │        │ • incident_id        │
│   device_id,         │        │    • Load device     │        │ • result=isolated    │
│   hostname, ip       │        │      allowlist       │        │                      │
│ }                    │        │    • Verify device   │        │ Example Log Line:    │
│                      │        │      not allowlisted │        │ 2025-12-10T15:30:45Z│
│                      │        │                      │        │ isolate              │
│                      │        │ 3. Evaluate:         │        │ device_id=dev-9001   │
│                      │        │    • Severity >= 70? │        │ incident=INC-20250809│
│                      │        │    • Device present? │        │ T140310Z-a7f2b1c3    │
│                      │        │    • Not allowlisted?│        │ result=isolated      │
│                      │        │                      │        │                      │
│                      │        │ 4. Execute (if all   │        │ Written to:          │
│                      │        │    criteria met):    │        │ output/isolation.log │
│                      │        │    • Generate log    │        │                      │
│                      │        │      entry           │        │                      │
│                      │        │    • Write to        │        │                      │
│                      │        │      isolation.log   │        │                      │
│                      │        │                      │        │                      │
│                      │        │ Config: config.yml   │        │                      │
│                      │        │ Allowlist:           │        │                      │
│                      │        │ allowlists.yml       │        │                      │
│                      │        │                      │        │                      │
└──────────────────────┘        └──────────────────────┘        └──────────────────────┘
```

**Modules:** 
- `SOAR/Response/response.py` - `respond()`, `_validate_triaged_alert()`, `_get_components()`
- `SOAR/Response/isolation_executor.py` - `DeviceIsolationExecutor` (isolation evaluation, log generation, execution)
- `SOAR/Response/device_allowlist_checker.py` - `ResponseConfigLoader`, `AllowlistLoader` (config + device allowlist checking)
- `SOAR/Response/config.yml` - Configuration (isolation threshold, allowlist path, log path)
- `SOAR/configs/allowlists.yml` - Device allowlist (assets.device_ids)

---

### Reporting

**Purpose:** Export fully-processed incident data in two formats: machine-readable JSON for systems and human-readable Markdown for analysts.

```
┌─────────────────────┐        ┌─────────────────────┐        ┌─────────────────────┐
│       INPUT         │        │   REPORTING LOGIC   │        │       OUTPUT        │
├─────────────────────┤        ├─────────────────────┤        ├─────────────────────┤
│                     │        │                     │        │                     │
│ Fully Processed     │        │ 1. Export JSON:     │        │ JSON File:          │
│ Alert:              │        │                     │        │ out/incidents/      |
│ • All enrichment    │  ──▶  │ • Extract incident  │  ──▶   │ <incident_id>.json  │
│ • Triage results    │        │   data              │        │                     │
│ • Response actions  │        │ • Add allowlist     │        │ Markdown File:      │
│ • Decision logs     │        │   indicators        │        │ out/summaries/      │
│                     │        │                     │        │ <incident_id>.md    │
│                     │        │ 2. Render Markdown: │        │                     │
│                     │        │                     │        │ Contains:           │
│                     │        │ • Transform data    │        │ • Incident details  │
│                     │        │   for template      │        │ • IOC table         │
│                     │        │ • Load Jinja2       │        │ • Severity score    │
│                     │        │   template          │        │ • MITRE techniques  │
│                     │        │ • Render to         │        │ • Actions executed  │
│                     │        │   Markdown          │        │                     │
│                     │        │                     │        │                     │
└─────────────────────┘        └─────────────────────┘        └─────────────────────┘
```

**Modules:** 
- `SOAR/Reporting/incident_exporter.py` - Export to JSON
- `SOAR/Reporting/summary_renderer.py` - Render Markdown summary
- `SOAR/Reporting/templates/analyst_summary.md.j2` - Markdown template

---
