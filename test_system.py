import requests
import json
import time
import os

def test_api_health():
    print("Testing API Health...")
    try:
        resp = requests.get("http://localhost:8000/health")
        if resp.status_code == 200:
            print("✅ API is Running")
            return True
        else:
            print(f"❌ API health check failed: {resp.status_code}")
    except Exception as e:
        print(f"❌ Could not connect to API: {e}")
    return False

def test_prediction():
    print("\nTesting Prediction Endpoint...")
    url = "http://localhost:8000/predict"
    sample_payload = {
        "device_type": "Server",
        "protocol": "TCP",
        "src_port": 443,
        "dst_port": 58920,
        "packet_size": 1347,
        "session_duration": 17.16,
        "failed_login_attempts": 12,
        "dns_requests": 2,
        "outbound_connections": 15,
        "lateral_movement_flag": 0,
        "traffic_volume": 145.49,
        "port_scan_flag": 0,
        "malware_comm_flag": 0,
        "brute_force_flag": 1,
        "time_of_day": "Evening",
        "peak_hour": 1,
        "ip_address": "192.168.1.100"
    }
    
    try:
        resp = requests.post(url, json=sample_payload)
        if resp.status_code == 200:
            result = resp.json()
            print("✅ Prediction Successful")
            print(f"Result: {json.dumps(result, indent=2)}")
        else:
            print(f"❌ Prediction failed: {resp.status_code} - {resp.text}")
    except Exception as e:
        print(f"❌ Error during prediction test: {e}")

if __name__ == "__main__":
    if not os.path.exists('models'):
        print("⚠️ Warning: 'models' directory not found. Please run train_models.py first.")
    
    print("--- AZT-NO System Verification ---")
    if test_api_health():
        test_prediction()
    else:
        print("\nSkipping prediction test. Please start the backend with 'python app.py' first.")
