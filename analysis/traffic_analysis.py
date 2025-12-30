import pandas as pd

LOG_FILE = "logs/traffic_log.csv"

def load_data():
    df = pd.read_csv(LOG_FILE)
    return df

def basic_overview(df):
    print("\n[AZT-NO] Traffic Overview")
    print(df.head())
    print("\nTotal packets captured:", len(df))


def top_destination_ips(df, n=5):
    print("\nTop Destination IPs:")
    print(df["dst_ip"].value_counts().head(n))

def top_source_ips(df, n=5):
    print("\nTop Source IPs:")
    print(df["src_ip"].value_counts().head(n))

def top_destination_ips(df, n=5):
    print("\nTop Destination IPs:")
    print(df["dst_ip"].value_counts().head(n))

def protocol_distribution(df):
    print("\nProtocol Distribution:")
    print(df["protocol"].value_counts())

def classify_traffic(df):
    def is_internal(ip):
        return ip.startswith("192.168.") or ip.startswith("10.")

    df["src_type"] = df["src_ip"].apply(lambda x: "Internal" if is_internal(x) else "External")
    df["dst_type"] = df["dst_ip"].apply(lambda x: "Internal" if is_internal(x) else "External")

    print("\nTraffic Type Summary:")
    print(df[["src_type", "dst_type"]].value_counts())

    return df
def packet_size_stats(df):
    print("\nPacket Size Statistics:")
    print(df["packet_size"].describe())


if __name__ == "__main__":
    df = load_data()
    basic_overview(df)
    top_source_ips(df)
    top_destination_ips(df)
    protocol_distribution(df)
    df = classify_traffic(df)
    packet_size_stats(df)
