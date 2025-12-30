from scapy.all import IP, TCP, UDP

def extract_features(packet):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    packet_size = len(packet)

    protocol = "OTHER"
    src_port = "-"
    dst_port = "-"

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    return [
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        packet_size
    ]
