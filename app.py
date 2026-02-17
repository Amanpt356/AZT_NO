from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import pandas as pd
import joblib
import os
import datetime
import logging

app = FastAPI(title="Adaptive Zero Trust Network Observer (AZT-NO) API")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve Frontend
app.mount("/static", StaticFiles(directory="frontend"), name="static")

@app.get("/")
async def read_root():
    return FileResponse('frontend/index.html')

# Setup Logging
logging.basicConfig(filename='alerts.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load Models and Encoders
MODELS_DIR = 'models'
try:
    encoders = joblib.load(os.path.join(MODELS_DIR, 'encoders.joblib'))
    scaler = joblib.load(os.path.join(MODELS_DIR, 'scaler.joblib'))
    feature_names = joblib.load(os.path.join(MODELS_DIR, 'feature_names.joblib'))
    best_model_name = joblib.load(os.path.join(MODELS_DIR, 'best_model_name.joblib'))
    model = joblib.load(os.path.join(MODELS_DIR, f'{best_model_name}.joblib'))
    iso_forest = joblib.load(os.path.join(MODELS_DIR, 'isolation_forest.joblib'))
except Exception as e:
    logging.error(f"Error loading models: {e}")
    print(f"Error loading models: {e}")

class NetworkInput(BaseModel):
    device_type: str
    protocol: str
    src_port: int
    dst_port: int
    packet_size: int
    session_duration: float
    failed_login_attempts: int
    dns_requests: int
    outbound_connections: int
    lateral_movement_flag: int
    traffic_volume: float
    port_scan_flag: int
    malware_comm_flag: int
    brute_force_flag: int
    time_of_day: str
    peak_hour: int
    ip_address: str = "Unknown"

@app.post("/predict")
async def predict(data: NetworkInput):
    try:
        # Convert input to DataFrame
        input_df = pd.DataFrame([data.dict()])
        ip_addr = input_df['ip_address'][0]
        input_df = input_df.drop(columns=['ip_address'])

        # Preprocess categorical features
        categorical_cols = ['device_type', 'protocol', 'time_of_day']
        for col in categorical_cols:
            if data.dict()[col] in encoders[col].classes_:
                input_df[col] = encoders[col].transform([data.dict()[col]])[0]
            else:
                # Handle unseen categories by assigning a default or the most frequent one
                input_df[col] = 0 

        # Reorder columns to match model training
        input_df = input_df[feature_names]

        # Scale features
        X_scaled = scaler.transform(input_df)

        # Predict Threat Type
        prediction = model.predict(X_scaled)[0]
        threat_type = encoders['threat_type'].inverse_transform([prediction])[0]

        # Get Anomaly Score (from Isolation Forest)
        anomaly_score = -iso_forest.decision_function(X_scaled)[0] # Invert so higher is more anomalous
        
        # Calculate Risk Score (0-100)
        # Based on anomaly score and model confidence (if available)
        base_risk = (anomaly_score + 1) * 50 # Normalize to 0-100 range roughly
        risk_score = min(max(base_risk, 0), 100)

        # Mitigation Engine Logic
        action = "Allow"
        if threat_type != "Normal" or risk_score > 70:
            if risk_score > 90 or threat_type in ["Malware", "Data Exfiltration"]:
                action = "Block"
            else:
                action = "Throttle"

        # Result object
        result = {
            "source_ip": ip_addr,
            "threat_type": threat_type,
            "risk_score": round(risk_score, 2),
            "anomaly_score": round(anomaly_score, 4),
            "action_taken": action,
            "timestamp": datetime.datetime.now().isoformat()
        }

        # Log alert if suspicious
        if action != "Allow":
            logging.warning(f"ALERT: {threat_type} detected from {ip_addr}. Risk: {risk_score}. Action: {action}")
        
        return result

    except Exception as e:
        logging.error(f"Prediction error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health():
    return {"status": "Service is running"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
