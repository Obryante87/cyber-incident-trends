import os
import requests
import pandas as pd
from datetime import datetime
from dotenv import load_dotenv
from tenacity import retry, stop_after_attempt, wait_exponential
from utils import pg_conn, upsert_rows

load_dotenv()

CISA_KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

@retry(stop=stop_after_attempt(5), wait=wait_exponential(min=1, max=20))
def fetch_kev():
    r = requests.get(CISA_KEV_JSON, timeout=30)
    r.raise_for_status()
    return r.json()

def main():
    data = fetch_kev()
    vulns = data.get("vulnerabilities", [])
    df = pd.DataFrame(vulns)

    # Normalize fields
    df["cveID"] = df["cveID"].astype(str)
    df["dateAdded"] = pd.to_datetime(df["dateAdded"], errors="coerce").dt.date
    df["dueDate"] = pd.to_datetime(df.get("dueDate"), errors="coerce").dt.date

    rows = []
    for _, r in df.iterrows():
        rows.append((
            r.get("cveID"),
            r.get("vendorProject"),
            r.get("product"),
            r.get("vulnerabilityName"),
            r.get("dateAdded"),
            r.get("shortDescription"),
            r.get("requiredAction"),
            r.get("dueDate"),
            r.get("knownRansomwareCampaignUse"),
            r.get("notes"),
            CISA_KEV_JSON,
        ))

    cols = [
        "cve_id","vendor_project","product","vulnerability_name","date_added",
        "short_description","required_action","due_date","known_ransomware_campaign_use",
        "notes","source_url"
    ]

    conn = pg_conn()
    n = upsert_rows(conn, "raw.kev_cves", cols, rows, conflict_cols=["cve_id", "date_added"])
    print(f"[{datetime.utcnow().isoformat()}] Upserted raw.kev_cves rows: {n}")
    conn.close()

if __name__ == "__main__":
    main()
