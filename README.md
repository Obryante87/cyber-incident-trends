# Cybersecurity Incident Trends & Risk Analytics

## Overview
This project is an end-to-end cybersecurity analytics platform designed to ingest, enrich, analyze, and visualize **real-world breach and vulnerability data**. It combines public breach disclosures with known exploited vulnerabilities (KEV) and NVD CVSS scoring to surface trends, quantify risk, and support executive decision-making.

The system follows a production-style analytics workflow: data ingestion → enrichment → feature engineering → analytics marts → dashboards.

---

## Key Questions Addressed
- Which sectors experience the highest breach and ransomware activity?
- How are breach frequency and severity trending over time?
- How does vulnerability pressure (KEV + CVSS) relate to breach impact?
- What conditions are associated with high-impact (“mega”) breaches?

---

## Data Sources
- **HHS OCR Breach Portal** – Public healthcare breach disclosures  
- **CISA Known Exploited Vulnerabilities (KEV) Catalog**  
- **NIST National Vulnerability Database (NVD)** – CVSS enrichment  

> **Note:** Raw datasets are not committed to this repository. Instructions for obtaining data are provided below.

---

## Architecture

**Ingestion → Enrichment → Feature Engineering → Analytics → Visualization**

1. **Ingestion**
   - Normalizes breach disclosures into a unified schema
   - Ingests KEV CVEs from CISA

2. **Enrichment**
   - Enriches CVEs with CVSS v3 and v2 metrics from NVD
   - Handles API rate limiting, retries, and partial failures gracefully

3. **Feature Engineering**
   - Ransomware indicators
   - Mega-breach flags
   - Rolling KEV pressure windows (30/90 days)
   - Monthly severity aggregation

4. **Analytics Marts**
   - Industry time-series metrics
   - Vulnerability pressure metrics
   - Model-ready training datasets

5. **Visualization**
   - Interactive Streamlit dashboards
   - Executive-style trend analysis

---

## Repository Structure
cyber-incident-trends/
├── app/                 # Streamlit dashboards
├── etl/                 # Ingestion, enrichment, mart building
├── models/              # Risk modeling & training code
├── db/                  # Database schemas
├── ops/                 # Docker & orchestration
├── docker-compose.yml
├── .env.example
└── README.md

