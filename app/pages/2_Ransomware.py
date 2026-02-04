import os
import pandas as pd
import streamlit as st
import plotly.express as px
import psycopg2
from dotenv import load_dotenv

load_dotenv()

def conn():
    return psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "db"),
        port=int(os.getenv("POSTGRES_PORT", "5432")),
        dbname=os.getenv("POSTGRES_DB", "cyber"),
        user=os.getenv("POSTGRES_USER", "cyber_user"),
        password=os.getenv("POSTGRES_PASSWORD", "cyber_pass"),
    )

st.title("Ransomware Focus")

c = conn()
df = pd.read_sql("SELECT * FROM mart.industry_time_metrics ORDER BY period_start", c)
c.close()

latest = df[df["period_start"] == df["period_start"].max()].sort_values("ransomware_share", ascending=False).head(10)
st.subheader("Top industries by ransomware share (latest period)")
st.dataframe(latest[["industry","breach_count","ransomware_count","ransomware_share"]])

fig = px.line(df, x="period_start", y="ransomware_share", color="industry")
st.plotly_chart(fig, use_container_width=True)
