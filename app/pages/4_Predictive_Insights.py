import os
import joblib
import pandas as pd
import streamlit as st
import psycopg2
from dotenv import load_dotenv

load_dotenv()

MODEL_PATH = os.getenv("MODEL_PATH", "/models/artifacts/high_impact_model.joblib")

def conn():
    return psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "db"),
        port=int(os.getenv("POSTGRES_PORT", "5432")),
        dbname=os.getenv("POSTGRES_DB", "cyber"),
        user=os.getenv("POSTGRES_USER", "cyber_user"),
        password=os.getenv("POSTGRES_PASSWORD", "cyber_pass"),
    )

st.title("Predictive Insights (High Impact Proxy)")

if not os.path.exists(MODEL_PATH):
    st.warning("Model artifact not found. Train it in the models container (or run train_high_impact.py).")
    st.stop()

pipe = joblib.load(MODEL_PATH)

c = conn()
df = pd.read_sql("SELECT * FROM mart.model_training_set ORDER BY event_date DESC LIMIT 2000", c)
c.close()

st.caption("Scoring recent events (proxy model).")

X = df.drop(columns=["target_high_impact", "event_id"])
proba = pipe.predict_proba(X)[:, 1]
out = df[["event_id","event_date","industry","breach_type","ransomware_flag","target_high_impact"]].copy()
out["p_high_impact"] = proba

st.dataframe(out.sort_values("p_high_impact", ascending=False).head(25))
