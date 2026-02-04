import pandas as pd
from pathlib import Path

IN_PATH = Path("/mnt/data/hhs_ocr.csv")
OUT_PATH = Path("/mnt/data/breaches.csv")

def find_col(df, contains_any):
    cols = {c.lower(): c for c in df.columns}
    for needle in contains_any:
        for k, orig in cols.items():
            if needle in k:
                return orig
    return None

def main():
    if not IN_PATH.exists():
        raise FileNotFoundError(f"Missing {IN_PATH}. Put your downloaded file in data/hhs_ocr.csv")

    df = pd.read_csv(IN_PATH)

    date_col = find_col(df, ["breach submission date", "submission date", "date"])
    name_col = find_col(df, ["name of covered entity", "covered entity"])
    state_col = find_col(df, ["state"])
    affected_col = find_col(df, ["individuals affected", "affected"])
    breach_type_col = find_col(df, ["type of breach", "breach type"])
    loc_col = find_col(df, ["location of breached information", "location"])

    required = {"date": date_col, "name": name_col, "breach_type": breach_type_col, "affected": affected_col}
    missing = [k for k, v in required.items() if v is None]
    if missing:
        raise ValueError(f"Could not find required columns: {missing}. Columns found: {list(df.columns)}")

    out = pd.DataFrame()
    out["event_date"] = pd.to_datetime(df[date_col], errors="coerce").dt.date
    out["industry"] = "healthcare"
    out["breach_type"] = df[breach_type_col].astype(str)
    out["records_affected"] = pd.to_numeric(df[affected_col], errors="coerce").fillna(0).astype("int64")

    # event_id: stable-ish slug
    out["event_id"] = (
        df[name_col].astype(str).str.strip().str.replace(r"\s+", "-", regex=True).str.lower()
        + "-"
        + pd.to_datetime(df[date_col], errors="coerce").dt.strftime("%Y%m%d").fillna("unknown")
    )

    out["location"] = df[state_col].astype(str) if state_col else (df[loc_col].astype(str) if loc_col else "unknown")
    out["source_url"] = "https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf"

    out = out[["event_id","event_date","industry","breach_type","records_affected","location","source_url"]]
    out = out.dropna(subset=["event_date"])
    out.to_csv(OUT_PATH, index=False)
    print(f"Wrote {len(out)} rows -> {OUT_PATH}")

if __name__ == "__main__":
    main()
