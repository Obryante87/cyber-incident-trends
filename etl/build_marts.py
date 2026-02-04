import pandas as pd
from datetime import datetime, date, timedelta
from dotenv import load_dotenv
from utils import pg_conn

load_dotenv()

def main():
    conn = pg_conn()

    # --- Stage KEV: collapse raw to latest per cve_id
    kev_raw = pd.read_sql("""
        SELECT DISTINCT ON (cve_id)
          cve_id, vendor_project, product, vulnerability_name,
          date_added, due_date, known_ransomware_campaign_use, notes, source_url
        FROM raw.kev_cves
        ORDER BY cve_id, date_added DESC
    """, conn)

    kev_raw["known_ransomware_campaign_use"] = kev_raw["known_ransomware_campaign_use"].astype(str).str.lower().isin(["yes","true","1"])
    with conn.cursor() as cur:
        cur.execute("TRUNCATE staging.kev_cves;")
    conn.commit()
    kev_raw.to_sql("kev_cves", conn, schema="staging", if_exists="append", index=False, method="multi")

    # --- Stage breaches: basic flags
    breaches = pd.read_sql("""
        SELECT event_id, event_date, industry, breach_type, records_affected, location, source_url
        FROM raw.breach_events
        WHERE event_date IS NOT NULL
    """, conn)

    breaches["breach_type"] = breaches["breach_type"].fillna("unknown")
    breaches["industry"] = breaches["industry"].fillna("unknown")
    breaches["ransomware_flag"] = breaches["breach_type"].str.lower().str.contains("ransom", na=False)
    breaches["mega_breach"] = breaches["records_affected"].fillna(0).astype("int64") >= 1_000_000

    with conn.cursor() as cur:
        cur.execute("TRUNCATE staging.breach_events;")
    conn.commit()
    breaches_stg = breaches[["event_id","event_date","industry","breach_type","records_affected","location","ransomware_flag","mega_breach","source_url"]]
    breaches_stg.to_sql("breach_events", conn, schema="staging", if_exists="append", index=False, method="multi")

    # --- Mart: industry_time_metrics (monthly)
    breaches_stg["period_start"] = pd.to_datetime(breaches_stg["event_date"]).dt.to_period("M").dt.to_timestamp().dt.date

    g = breaches_stg.groupby(["period_start","industry"], dropna=False)
    mart1 = g.agg(
        breach_count=("event_id","count"),
        ransomware_count=("ransomware_flag","sum"),
        median_records=("records_affected","median"),
        mega_breach_rate=("mega_breach","mean")
    ).reset_index()

    mart1["ransomware_share"] = (mart1["ransomware_count"] / mart1["breach_count"]).fillna(0)

    with conn.cursor() as cur:
        cur.execute("TRUNCATE mart.industry_time_metrics;")
    conn.commit()
    mart1.to_sql("industry_time_metrics", conn, schema="mart", if_exists="append", index=False, method="multi")

    # --- Mart: KEV pressure (monthly + 30d rolling)
    kev = pd.read_sql("SELECT cve_id, date_added FROM staging.kev_cves WHERE date_added IS NOT NULL", conn)
    if not kev.empty:
        kev["period_start"] = pd.to_datetime(kev["date_added"]).dt.to_period("M").dt.to_timestamp().dt.date
        kev_month = kev.groupby("period_start").agg(kev_added_count=("cve_id","count")).reset_index()
    else:
        kev_month = pd.DataFrame(columns=["period_start","kev_added_count"])

    # 30d rolling based on calendar months (approx): compute for each month start
    all_months = pd.date_range(
        start=(pd.Timestamp.today() - pd.DateOffset(months=36)).to_period("M").to_timestamp(),
        end=pd.Timestamp.today().to_period("M").to_timestamp(),
        freq="MS"
    ).date

    kev_added_30d = []
    for m in all_months:
        start = pd.Timestamp(m)
        end = start + pd.Timedelta(days=30)
        cnt = 0 if kev.empty else ((pd.to_datetime(kev["date_added"]) >= start) & (pd.to_datetime(kev["date_added"]) < end)).sum()
        kev_added_30d.append((m, int(cnt)))

    kev30 = pd.DataFrame(kev_added_30d, columns=["period_start","kev_added_30d"])

    # avg CVSS recent (from enriched)
    cvss = pd.read_sql("""
      SELECT cve_id, cvss_base_score, published_date
      FROM staging.cve_enriched
      WHERE cvss_base_score IS NOT NULL
    """, conn)
    cvss["published_date"] = pd.to_datetime(cvss["published_date"], errors="coerce")
    cvss_month = (
        cvss.dropna(subset=["published_date"])
            .assign(period_start=lambda d: d["published_date"].dt.to_period("M").dt.to_timestamp().dt.date)
            .groupby("period_start")
            .agg(avg_cvss_recent=("cvss_base_score","mean"))
            .reset_index()
    )

    mart2 = pd.DataFrame({"period_start": list(all_months)})
    mart2 = mart2.merge(kev_month, on="period_start", how="left").merge(kev30, on="period_start", how="left").merge(cvss_month, on="period_start", how="left")
    mart2["kev_added_count"] = mart2["kev_added_count"].fillna(0).astype(int)
    mart2["kev_added_30d"] = mart2["kev_added_30d"].fillna(0).astype(int)

    with conn.cursor() as cur:
        cur.execute("TRUNCATE mart.kev_pressure;")
    conn.commit()
    mart2.to_sql("kev_pressure", conn, schema="mart", if_exists="append", index=False, method="multi")

    # --- Mart: model training set (join breach months with KEV pressure)
    # add 90d rolling quickly from 3-month window approximation
    kev_added_90d = []
    for m in all_months:
        start = pd.Timestamp(m)
        end = start + pd.Timedelta(days=90)
        cnt = 0 if kev.empty else ((pd.to_datetime(kev["date_added"]) >= start) & (pd.to_datetime(kev["date_added"]) < end)).sum()
        kev_added_90d.append((m, int(cnt)))
    kev90 = pd.DataFrame(kev_added_90d, columns=["period_start","kev_added_90d"])

    pressure = mart2.merge(kev90, on="period_start", how="left")
    pressure["kev_added_90d"] = pressure["kev_added_90d"].fillna(0).astype(int)

    # training target = mega_breach (proxy for high impact)
    train = breaches_stg.merge(pressure, left_on="period_start", right_on="period_start", how="left")
    train["target_high_impact"] = train["mega_breach"].astype(bool)

    train_out = train[[
        "event_id","event_date","industry","breach_type","ransomware_flag",
        "kev_added_30d","kev_added_90d","avg_cvss_recent","target_high_impact"
    ]].copy()
    train_out["kev_added_30d"] = train_out["kev_added_30d"].fillna(0).astype(int)
    train_out["kev_added_90d"] = train_out["kev_added_90d"].fillna(0).astype(int)

    with conn.cursor() as cur:
        cur.execute("TRUNCATE mart.model_training_set;")
    conn.commit()
    train_out.to_sql("model_training_set", conn, schema="mart", if_exists="append", index=False, method="multi")

    print(f"[{datetime.utcnow().isoformat()}] Built marts successfully.")
    conn.close()

if __name__ == "__main__":
    main()
