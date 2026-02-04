import os
import streamlit as st

st.set_page_config(page_title="Cyber Incident Trends", layout="wide")

st.title("Cyber Incident Trends & Ransomware Risk Explorer")
st.write("""
This dashboard tracks breach and ransomware trends, vulnerability exploitation pressure (KEV),
and provides a proxy "high impact" prediction model.
""")

st.info("Use the pages on the left: Trends, Ransomware, KEV Pressure, Predictive Insights.")
