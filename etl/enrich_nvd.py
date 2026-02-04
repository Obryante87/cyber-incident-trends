import os
import time
import requests
import pandas as pd
from datetime import datetime
from dotenv import load_dotenv
from tenacity import retry, stop_after_attempt, wait_exponential
from utils import pg_conn, upsert_rows
from sqlalchemy import create_engine
from requests import HTTPError


load_dotenv()

def pg_engine():
    return create_engine(
        f"postgresql+psycopg2://{os.getenv('POSTGRES_USER')}:{os.getenv('POSTGRES_PASSWORD')}"
        f"@{os.getenv('POSTGRES_HOST')}:{os.getenv('POSTGRES_PORT')}/{os.getenv('POSTGRES_DB')}"
    )

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_kev_cves(engine, limit=2000):
    sql = "SELECT cve_id FROM staging.kev_cves ORDER BY cve_id LIMIT %(limit)s"
    return pd.read_sql(sql, engine, params={"limit": limit})["cve_id"].tolist()

@retry(stop=stop_after_attempt(5), wait=wait_exponential(min=1, max=20))
def fetch_cve(cve_id, api_key=None):
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key

    r = requests.get(NVD_API, params={"cveId": cve_id}, headers=headers, timeout=30)

    # If not found / bad request, don't retry
    if r.status_code in (400, 404):
        return None

    # If rate limited or server errors, let retry happen
    if r.status_code in (429, 500, 502, 503, 504):
        r.raise_for_status()

    # Any other error -> skip
    if r.status_code >= 400:
        return None

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

        # Try CVSS v3.1 then v3.0, then fall back to CVSS v2
    for key in ["cvssMetricV31", "cvssMetricV30"]:
        arr = metrics.get(key)
        if arr:
            data = arr[0].get("cvssData", {})
            cvss = data.get("baseScore")
            severity = data.get("baseSeverity")
            attack_vector = data.get("attackVector")
            break

    # Fallback: CVSS v2 (common for older CVEs)
    if cvss is None:
        arr = metrics.get("cvssMetricV2")
        if arr:
            data = arr[0].get("cvssData", {})
            cvss = data.get("baseScore")
            # v2 uses different field names
            severity = arr[0].get("baseSeverity") or data.get("baseSeverity")
            attack_vector = data.get("accessVector")  # v2 name


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
    engine = pg_engine()
    conn = pg_conn()

    # Ensure staging KEV table is populated first
    cves = get_kev_cves(engine)
    rows = []

    for i, cve_id in enumerate(cves, 1):
        try:
            j = fetch_cve(cve_id, api_key=api_key)
            if not j:
                continue

            parsed = parse_cve(j, cve_id)
            if parsed:
                rows.append(parsed)

        except Exception as e:
            status = None
            # tenacity RetryError wraps the last exception
            cause = getattr(e, "last_attempt", None)
            if cause:
                e2 = cause.exception()
            else:
                e2 = e

            if hasattr(e2, "response") and e2.response is not None:
                status = e2.response.status_code

            if status:
                print(f"Failed CVE {cve_id}: HTTP {status} - {e2}")
            else:
                print(f"Failed CVE {cve_id}: {e2}")


        # polite pacing to avoid rate limits if no API key
        if not api_key:
            time.sleep(0.7)

        if i % 100 == 0:
            print(f"Processed {i}/{len(cves)} CVEs")

    cols = ["cve_id","published_date","last_modified","cvss_base_score","cvss_severity","attack_vector","cwe_id"]
    n = upsert_rows(conn, "staging.cve_enriched", cols, rows, conflict_cols=["cve_id"])
    print(f"[{datetime.utcnow().isoformat()}] Upserted staging.cve_enriched rows: {n}")

    conn.close()
    engine.dispose()
if __name__ == "__main__":
    main()
