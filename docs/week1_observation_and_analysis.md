# Phase 1 – Network Observation and Traffic Analysis

## 1. Introduction
The first phase of AZT-NO combines network traffic observation and behavioral analysis into a single cohesive stage. This phase focuses on capturing real network traffic, converting raw packets into structured data, and analyzing the traffic to establish a baseline of normal network behavior.

Combining observation and analysis ensures that data collection and interpretation remain closely aligned, resulting in accurate and realistic behavioral insights.

---

## 2. Problem Context
Modern campus and small-scale enterprise networks lack lightweight, adaptive monitoring solutions capable of understanding network behavior in real time. Existing tools are often rule-based, resource-intensive, or designed for large enterprise environments.

There is a need for a modular system that can observe live traffic, extract meaningful features, and analyze communication patterns without assuming implicit trust in any device or connection.

---

## 3. Objectives of Phase 1
- Capture live network traffic in real time
- Extract structured features from raw packets
- Store traffic data in a reusable and analyzable format
- Analyze traffic patterns to understand normal behavior
- Establish a baseline for future anomaly detection

---

## 4. Network Observation (Traffic Capture)

### 4.1 Packet Capture
Live network packets are captured using a packet sniffing mechanism. Only IP-based packets are considered to ensure relevance to network communication analysis.

### 4.2 Feature Extraction
For each captured packet, the following features are extracted:
- Source IP address
- Destination IP address
- Protocol type (TCP, UDP, Other)
- Source and destination ports (where applicable)
- Packet size in bytes

These features provide a compact yet meaningful representation of network behavior.

### 4.3 Traffic Logging
Extracted features are stored in a structured CSV file. Each row represents a single network packet, enabling efficient storage, retrieval, and analysis of traffic data.

---

## 5. Traffic Analysis and Behavioral Understanding

### 5.1 Traffic Overview
The captured dataset is inspected to verify integrity and scale. Sample records are reviewed to confirm correct feature extraction and logging. The total packet count provides insight into traffic volume and dataset realism.

---

### 5.2 IP Frequency Analysis
Source and destination IP addresses are analyzed to identify dominant communication endpoints. This analysis highlights:
- Frequently communicating internal hosts
- Commonly accessed external servers

These patterns help define normal communication behavior.

---

### 5.3 Protocol Distribution
Traffic is analyzed based on protocol usage to understand protocol dominance within the network. TCP traffic typically dominates due to web and application usage, while UDP and other protocols represent control or auxiliary communication.

---

### 5.4 Internal vs External Traffic Classification
Traffic is classified based on IP address ranges to distinguish internal network communication from external interactions. This classification adds context to traffic behavior and aligns with Zero-Trust principles, where all traffic is continuously evaluated.

---

### 5.5 Packet Size Statistical Analysis
Statistical metrics are computed for packet sizes, including:
- Minimum and maximum values
- Mean packet size
- Standard deviation

These statistics establish quantitative baselines for normal traffic behavior.

---

## 6. Outcome of Phase 1
At the end of Phase 1, AZT-NO successfully delivers:
- A functional network observation layer
- Structured traffic datasets derived from real network activity
- Behavioral insights into normal traffic patterns
- Statistical baselines required for anomaly detection

This phase provides a solid foundation for implementing rule-based and AI-driven anomaly detection mechanisms in subsequent phases.

---

## 7. Significance
By combining traffic observation and analysis into a single phase, AZT-NO ensures that behavior modeling is grounded in realistic data. This approach improves the accuracy, interpretability, and reliability of future security detection components.
