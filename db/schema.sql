CREATE SCHEMA IF NOT EXISTS raw;
CREATE SCHEMA IF NOT EXISTS staging;
CREATE SCHEMA IF NOT EXISTS mart;

-- RAW: CISA KEV
CREATE TABLE IF NOT EXISTS raw.kev_cves (
  cve_id TEXT NOT NULL,
  vendor_project TEXT,
  product TEXT,
  vulnerability_name TEXT,
  date_added DATE,
  short_description TEXT,
  required_action TEXT,
  due_date DATE,
  known_ransomware_campaign_use TEXT,
  notes TEXT,
  source_url TEXT,
  ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (cve_id, date_added)
);

-- RAW: breaches (PRC or other public breach dataset)
CREATE TABLE IF NOT EXISTS raw.breach_events (
  event_id TEXT PRIMARY KEY,
  event_date DATE,
  organization TEXT,
  industry TEXT,
  breach_type TEXT,
  records_affected BIGINT,
  location TEXT,
  description TEXT,
  source_url TEXT,
  ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- STAGING: cleaned and typed
CREATE TABLE IF NOT EXISTS staging.kev_cves (
  cve_id TEXT PRIMARY KEY,
  vendor_project TEXT,
  product TEXT,
  vulnerability_name TEXT,
  date_added DATE,
  due_date DATE,
  known_ransomware_campaign_use BOOLEAN,
  notes TEXT,
  source_url TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS staging.breach_events (
  event_id TEXT PRIMARY KEY,
  event_date DATE NOT NULL,
  industry TEXT,
  breach_type TEXT,
  records_affected BIGINT,
  location TEXT,
  ransomware_flag BOOLEAN NOT NULL DEFAULT FALSE,
  mega_breach BOOLEAN NOT NULL DEFAULT FALSE,
  source_url TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Enriched CVE data from NVD
CREATE TABLE IF NOT EXISTS staging.cve_enriched (
  cve_id TEXT PRIMARY KEY,
  published_date TIMESTAMPTZ,
  last_modified TIMESTAMPTZ,
  cvss_base_score NUMERIC,
  cvss_severity TEXT,
  attack_vector TEXT,
  cwe_id TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- MARTS
CREATE TABLE IF NOT EXISTS mart.industry_time_metrics (
  period_start DATE NOT NULL,
  industry TEXT NOT NULL,
  breach_count INT NOT NULL,
  ransomware_count INT NOT NULL,
  ransomware_share NUMERIC NOT NULL,
  median_records BIGINT,
  mega_breach_rate NUMERIC NOT NULL,
  PRIMARY KEY (period_start, industry)
);

CREATE TABLE IF NOT EXISTS mart.kev_pressure (
  period_start DATE PRIMARY KEY,
  kev_added_count INT NOT NULL,
  kev_added_30d INT NOT NULL,
  avg_cvss_recent NUMERIC
);

CREATE TABLE IF NOT EXISTS mart.model_training_set (
  event_id TEXT PRIMARY KEY,
  event_date DATE NOT NULL,
  industry TEXT,
  breach_type TEXT,
  ransomware_flag BOOLEAN NOT NULL,
  kev_added_30d INT NOT NULL,
  kev_added_90d INT NOT NULL,
  avg_cvss_recent NUMERIC,
  target_high_impact BOOLEAN NOT NULL
);
