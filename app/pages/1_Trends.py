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

st.title("Trends")

c = conn()
df = pd.read_sql("SELECT * FROM mart.industry_time_metrics ORDER BY period_start", c)
c.close()

industries = sorted(df["industry"].unique().tolist())
sel = st.multiselect("Industries", industries, default=industries[:5] if industries else [])

plot_df = df[df["industry"].isin(sel)] if sel else df

fig = px.line(plot_df, x="period_start", y="breach_count", color="industry")
st.plotly_chart(fig, use_container_width=True)

fig2 = px.line(plot_df, x="period_start", y="median_records", color="industry")
st.plotly_chart(fig2, use_container_width=True)
