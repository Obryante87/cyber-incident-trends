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

st.title("KEV / Exploitation Pressure")

c = conn()
df = pd.read_sql("SELECT * FROM mart.kev_pressure ORDER BY period_start", c)
c.close()

fig = px.bar(df, x="period_start", y="kev_added_count")
st.plotly_chart(fig, use_container_width=True)

fig2 = px.line(df, x="period_start", y="avg_cvss_recent")
st.plotly_chart(fig2, use_container_width=True)
