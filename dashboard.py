import streamlit as st
import pandas as pd
import requests
import json
import time
import datetime
import plotly.express as px
import plotly.graph_objects as go
import os

st.set_page_config(page_title="AZT-NO Dashboard", layout="wide")

# Constants
API_URL = "http://localhost:8000/predict"

st.title("🛡️ Adaptive Zero Trust Network Observer (AZT-NO)")
st.subheader("Real-time AI-Powered Cybersecurity Monitoring")

# Sidebar for simulation
st.sidebar.header("Simulation Control")
dataset_path = 'AZT_NO_ZeroTrust_Dataset.csv'
if os.path.exists(dataset_path):
    df_sample = pd.read_csv(dataset_path).sample(100)
    simulate_btn = st.sidebar.button("Simulate Random Traffic")
else:
    st.sidebar.error("Dataset not found for simulation.")

# Tabs
tab1, tab2, tab3 = st.tabs(["Real-time Monitor", "Threat Analysis", "System Logs"])

if "alerts" not in st.session_state:
    st.session_state.alerts = []

def send_to_api(row):
    try:
        data = row.to_dict()
        # Clean up data for API
        payload = {
            "device_type": str(data['device_type']),
            "protocol": str(data['protocol']),
            "src_port": int(data['src_port']),
            "dst_port": int(data['dst_port']),
            "packet_size": int(data['packet_size']),
            "session_duration": float(data['session_duration']),
            "failed_login_attempts": int(data['failed_login_attempts']),
            "dns_requests": int(data['dns_requests']),
            "outbound_connections": int(data['outbound_connections']),
            "lateral_movement_flag": int(data['lateral_movement_flag']),
            "traffic_volume": float(data['traffic_volume']),
            "port_scan_flag": int(data['port_scan_flag']),
            "malware_comm_flag": int(data['malware_comm_flag']),
            "brute_force_flag": int(data['brute_force_flag']),
            "time_of_day": str(data['time_of_day']),
            "peak_hour": int(data['peak_hour']),
            "ip_address": str(data['ip_address'])
        }
        resp = requests.post(API_URL, json=payload)
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        return {"error": str(e)}
    return None

if simulate_btn:
    with st.spinner("Simulating traffic..."):
        for _, row in df_sample.iterrows():
            result = send_to_api(row)
            if result:
                st.session_state.alerts.insert(0, result)
                if len(st.session_state.alerts) > 50:
                    st.session_state.alerts.pop()
            time.sleep(0.1)
    st.success("Simulation complete!")

# tab 1: Real-time Monitor
with tab1:
    col1, col2, col3, col4 = st.columns(4)
    
    total_events = len(st.session_state.alerts)
    threats_detected = len([a for a in st.session_state.alerts if a.get('action_taken') != 'Allow'])
    avg_risk = sum([a.get('risk_score', 0) for a in st.session_state.alerts]) / total_events if total_events > 0 else 0
    
    col1.metric("Total Events", total_events)
    col2.metric("Threats Flagged", threats_detected, delta=threats_detected, delta_color="inverse")
    col3.metric("Avg Risk Score", f"{avg_risk:.1f}")
    col4.metric("System Health", "Active", delta_color="normal")

    st.divider()
    
    if st.session_state.alerts:
        latest = st.session_state.alerts[0]
        st.write(f"### Latest Event: {latest['threat_type']}")
        
        c1, c2 = st.columns([1, 2])
        with c1:
            fig = go.Figure(go.Indicator(
                mode = "gauge+number",
                value = latest['risk_score'],
                domain = {'x': [0, 1], 'y': [0, 1]},
                title = {'text': "Risk Score"},
                gauge = {
                    'axis': {'range': [None, 100]},
                    'bar': {'color': "darkblue"},
                    'steps' : [
                        {'range': [0, 50], 'color': "lightgreen"},
                        {'range': [50, 80], 'color': "orange"},
                        {'range': [80, 100], 'color': "red"}],
                    'threshold': {
                        'line': {'color': "black", 'width': 4},
                        'thickness': 0.75,
                        'value': latest['risk_score']}}))
            st.plotly_chart(fig, use_container_width=True)
            
        with c2:
            st.json(latest)
            
    else:
        st.info("No traffic data yet. Use the simulation tool in the sidebar.")

# tab 2: Threat Analysis
with tab2:
    if st.session_state.alerts:
        df_alerts = pd.DataFrame(st.session_state.alerts)
        
        c1, c2 = st.columns(2)
        with c1:
            fig_pie = px.pie(df_alerts, names='threat_type', title="Threat Type Distribution")
            st.plotly_chart(fig_pie)
        
        with c2:
            fig_bar = px.bar(df_alerts, x='action_taken', title="Mitigation Actions Taken")
            st.plotly_chart(fig_bar)
            
        fig_line = px.line(df_alerts, y='risk_score', title="Risk Score Over Time")
        st.plotly_chart(fig_line, use_container_width=True)
    else:
        st.info("Start simulation to see analysis.")

# tab 3: System Logs
with tab3:
    if st.session_state.alerts:
        st.dataframe(pd.DataFrame(st.session_state.alerts), use_container_width=True)
    else:
        st.info("No logs available yet.")

# Auto-refresh simulation (optional)
# st.sidebar.button("Reset Session State", on_click=lambda: st.session_state.clear())
