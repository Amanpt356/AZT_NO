import streamlit as st
import pandas as pd

LOG_FILE = "logs/traffic_log.csv"

st.set_page_config(page_title="AZT-NO Dashboard", layout="wide")

@st.cache_data(ttl=5)
def load_data():
    return pd.read_csv(
        LOG_FILE,
        names=["src_ip", "dst_ip", "protocol", "src_port", "dst_port", "packet_size"]
    )

df = load_data()

st.title("AZT-NO : Network Traffic Monitoring Dashboard")

# --- Metrics ---
col1, col2, col3 = st.columns(3)
col1.metric("Total Packets", len(df))
col2.metric("Unique Source IPs", df["src_ip"].nunique())
col3.metric("Unique Destination IPs", df["dst_ip"].nunique())

# --- Charts ---
st.subheader("Protocol Distribution")
st.bar_chart(df["protocol"].value_counts())

st.subheader("Top Source IPs")
st.dataframe(df["src_ip"].value_counts().head(10), use_container_width=True)

st.subheader("Top Destination IPs")
st.dataframe(df["dst_ip"].value_counts().head(10), use_container_width=True)

st.subheader("Packet Size Statistics")
st.write(df["packet_size"].describe())
