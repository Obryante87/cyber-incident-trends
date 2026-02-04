import os
import time
import requests
import pandas as pd
from datetime import datetime
from dotenv import load_dotenv
from tenacity import retry, stop_after_attempt, wait_exponential
from utils import pg_conn, upsert_rows

load_dotenv()

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_kev_cves(conn, limit=2000):
    sql = "SELECT cve_id FROM staging.kev_cves ORDER BY cve_id LIMIT %s"
    return pd.read_sql(sql, conn, params=(limit,))["cve_id"].tolist()

@retry(stop=stop_after_attempt(5), wait=wait_exponential(min=1, max=20))
def fetch_cve(cve_id, api_key=None):
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key

    r = requests.get(NVD_API, params={"cveId": cve_id}, headers=headers, timeout=30)
    r.raise_for_status()
    return r.json()

def parse_cve(json_obj, cve_id):
    vulns = json_obj.get("vulnerabilities", [])
    if not vulns:
        return None

    cve = vulns[0].get("cve", {})
    published = cve.get("published")
    modified = cve.get("lastModified")

    metrics = cve.get("metrics", {})
    cvss = None
    severity = None
    attack_vector = None

    # Try CVSS v3.1 then v3.0
    for key in ["cvssMetricV31", "cvssMetricV30"]:
        arr = metrics.get(key)
        if arr:
            data = arr[0].get("cvssData", {})
            cvss = data.get("baseScore")
            severity = data.get("baseSeverity")
            attack_vector = data.get("attackVector")
            break

    # CWE (best-effort)
    cwe = None
    weaknesses = cve.get("weaknesses", [])
    if weaknesses:
        descs = weaknesses[0].get("description", [])
        if descs:
            cwe = descs[0].get("value")

    return (
        cve_id,
        published,
        modified,
        cvss,
        severity,
        attack_vector,
        cwe,
    )

def main():
    api_key = os.getenv("NVD_API_KEY", "").strip() or None
    conn = pg_conn()

    # Ensure staging KEV table is populated first
    cves = get_kev_cves(conn)
    rows = []
    for i, cve_id in enumerate(cves, 1):
        try:
            j = fetch_cve(cve_id, api_key=api_key)
            parsed = parse_cve(j, cve_id)
            if parsed:
                rows.append(parsed)
        except Exception as e:
            print(f"Failed CVE {cve_id}: {e}")

        # polite pacing to avoid rate limits if no API key
        if not api_key:
            time.sleep(0.7)

        if i % 100 == 0:
            print(f"Processed {i}/{len(cves)} CVEs")

    cols = ["cve_id","published_date","last_modified","cvss_base_score","cvss_severity","attack_vector","cwe_id"]
    n = upsert_rows(conn, "staging.cve_enriched", cols, rows, conflict_cols=["cve_id"])
    print(f"[{datetime.utcnow().isoformat()}] Upserted staging.cve_enriched rows: {n}")
    conn.close()

if __name__ == "__main__":
    main()
