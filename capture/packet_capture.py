from scapy.all import sniff, IP, TCP, UDP
from utils.feature_extractor import extract_features
import csv
import os

LOG_FILE = "logs/traffic_log.csv"

def init_log():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "src_ip",
                "dst_ip",
                "protocol",
                "src_port",
                "dst_port",
                "packet_size"
            ])

def packet_handler(packet):
    if IP in packet:
        data = extract_features(packet)
        with open(LOG_FILE, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(data)

def start_capture():
    init_log()
    print("[AZT-NO] Starting packet capture...")
    sniff(prn=packet_handler, store=False)

