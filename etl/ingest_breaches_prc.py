import os
import pandas as pd
from datetime import datetime
from dotenv import load_dotenv
from utils import pg_conn, upsert_rows

load_dotenv()

# Provide your exported breach CSV here (columns can be adapted)
DEFAULT_CSV = os.getenv("BREACH_CSV_PATH", "/mnt/data/breaches.csv")

def main():
    if not os.path.exists(DEFAULT_CSV):
        raise FileNotFoundError(
            f"Missing {DEFAULT_CSV}. Provide an exported breach CSV and set BREACH_CSV_PATH."
        )

    df = pd.read_csv(DEFAULT_CSV)

    # Expected minimal columns (rename as needed):
    # event_id, event_date, organization, industry, breach_type, records_affected, location, description, source_url
    df["event_date"] = pd.to_datetime(df["event_date"], errors="coerce").dt.date
    df["records_affected"] = pd.to_numeric(df["records_affected"], errors="coerce").fillna(0).astype("int64")

    rows = []
    for _, r in df.iterrows():
        rows.append((
            str(r["event_id"]),
            r["event_date"],
            r.get("organization"),
            r.get("industry"),
            r.get("breach_type"),
            int(r.get("records_affected", 0)),
            r.get("location"),
            r.get("description"),
            r.get("source_url"),
        ))

    cols = ["event_id","event_date","organization","industry","breach_type","records_affected","location","description","source_url"]
    conn = pg_conn()
    n = upsert_rows(conn, "raw.breach_events", cols, rows, conflict_cols=["event_id"])
    print(f"[{datetime.utcnow().isoformat()}] Upserted raw.breach_events rows: {n}")
    conn.close()

if __name__ == "__main__":
    main()
