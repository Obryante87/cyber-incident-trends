# High Impact Breach Predictor (Proxy)

## Purpose
Predict whether a breach is "high impact" using a proxy target: mega_breach (records_affected >= 1,000,000).

## Data
- Breach events from public sources (raw.breach_events -> staging.breach_events)
- KEV pressure signals from CISA KEV catalog and NVD enrichment

## Features
- industry, breach_type, ransomware_flag
- kev_added_30d, kev_added_90d
- avg_cvss_recent

## Target
- target_high_impact = mega_breach

## Metrics
- Report AUC and classification report

## Limitations
- Records affected is an imperfect proxy for cost/severity.
- Public reporting bias: incidents may be underreported and inconsistent across industries.
