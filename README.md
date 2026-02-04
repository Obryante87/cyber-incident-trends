# cyber-incident-trends

# Cyber Incident Trends & Ransomware Risk Explorer

## What this is
End-to-end analytics product:
- Ingest KEV (CISA) and breach events (CSV export)
- Enrich CVEs via NVD (optional API key)
- Build marts for trends + ransomware + KEV pressure
- Train a baseline model predicting high impact (proxy)
- Serve an executive dashboard in Streamlit

## Quick start
1) Copy `.env.example` to `.env` and set values.
2) Start Postgres + initial KEV ingest:
   - `docker compose up -d --build db etl`
3) Build marts:
   - `docker compose run --rm etl python build_marts.py`
4) (Optional) Enrich KEV CVEs via NVD:
   - `docker compose run --rm etl python enrich_nvd.py`
   - then rebuild marts
5) Train model:
   - `docker compose run --rm models`
6) Start dashboard:
   - `docker compose up -d --build app`
   - Open http://localhost:8501

## Breach data
Provide a breach CSV at `./data/breaches.csv` or set `BREACH_CSV_PATH`.
Required columns:
- event_id, event_date, industry, breach_type, records_affected, location, source_url
Optional columns:
- organization, description

## Notes
- "High impact" target uses mega_breach proxy (records_affected >= 1,000,000).
- Public breach reporting is incomplete and biased; interpret trends carefully.
