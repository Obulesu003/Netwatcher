# Netwatcher - Network Traffic Analyzer with ML & AI

## Project Overview

**Project Name:** Netwatcher  
**Type:** Network security monitoring tool with ML-powered anomaly detection  
**Core Functionality:** Captures network traffic, classifies it using ML, generates AI explanations, and alerts users on suspicious activity  
**Target Users:** Network administrators, security analysts, IT professionals, and organizations needing automated traffic monitoring

---

## Project Structure

```
Netwatcher/
├── SPEC.md
├── README.md
├── requirements.txt
├── src/
│   ├── __init__.py
│   ├── capture/
│   │   ├── __init__.py
│   │   ├── packet_capture.py      # Live capture using pyshark/tshark
│   │   └── traffic_processor.py   # Process captured packets
│   ├── ml/
│   │   ├── __init__.py
│   │   ├── model_trainer.py        # Train ML model on CICIDS dataset
│   │   ├── classifier.py           # Classify traffic
│   │   └── features.py             # Feature extraction from packets
│   ├── ai/
│   │   ├── __init__.py
│   │   └── explanation_engine.py    # AI explanation generation
│   ├── alerts/
│   │   ├── __init__.py
│   │   ├── alert_manager.py        # Alert orchestration
│   │   ├── email_alert.py
│   │   ├── sms_alert.py
│   │   └── slack_alert.py
│   ├── dashboard/
│   │   ├── __init__.py
│   │   ├── app.py                  # Flask application
│   │   └── templates/
│   │       └── index.html          # Dashboard UI
│   └── utils/
│       ├── __init__.py
│       ├── config.py               # Configuration management
│       └── logger.py               # Logging utility
├── models/                         # Trained model storage
│   └── traffic_classifier.pkl
├── data/
│   ├── captured/                   # Captured traffic data
│   └── cicids2017_sample.csv       # Sample training data
├── train_model.py                  # Model training script
├── export_report.py                # Export functionality
└── run.py                          # Main entry point
```

---

## Functionality Specification

### 1. Capture Module

**Features:**
- Live packet capture using `pyshark` (Python wrapper for tshark)
- Interface selection (auto-detect or specify interface)
- Capture filtering using BPF syntax (e.g., `tcp port 80`, `udp`, `host 192.168.1.1`)
- Configurable capture duration or continuous mode
- PCAP file saving for later analysis
- Real-time packet event streaming

**Data Captured Per Packet:**
- Timestamp
- Source/Destination IP
- Source/Destination Port
- Protocol (TCP/UDP/ICMP)
- Packet length
- TCP flags (if applicable)
- Payload size
- Inter-arrival time

**Edge Cases:**
- No network interfaces available → graceful error with list of available interfaces
- Permission denied (non-root on Linux) → clear error message with sudo instructions
- Wireshark/tshark not installed → installation instructions
- Capture buffer overflow → warning and automatic buffer management

### 2. ML Module

**Training Pipeline:**
- Dataset: CICIDS2017 (Canadian Institute for Cybersecurity Intrusion Detection)
- Features: 78 network traffic features (flow duration, packet counts, byte counts, etc.)
- Model: XGBoost classifier (gradient boosting)
- Classes: Normal, Brute Force (FTP-SSH), DoS, Port Scan, Infiltration, Web Attack, Botnet

**Feature Extraction:**
- Flow-based features (aggregated statistics)
- Connection patterns (packets per second, bytes per second)
- Protocol distribution
- Port usage patterns
- Session duration metrics

**Model Output:**
- Classification label (Normal/Attack Type)
- Confidence score (0-1)
- Feature importance for explanation

**Edge Cases:**
- Insufficient training data → use pre-trained model
- Unknown attack type → classify as "Suspicious - Unknown Type"
- Model file missing → auto-train on first run

### 3. AI Explanation Engine

**Capabilities:**
- Plain-English summary of traffic patterns
- Specific threat explanation when attack detected
- Recommended actions for mitigation
- Context-aware explanations based on classification

**Output Format:**
```
[Traffic Summary]
Total packets: 1,234 | Duration: 60s | Protocols: TCP(89%), UDP(11%)
Normal traffic ratio: 95.2%

[Threat Analysis - DETECTED]
Attack Type: Port Scan
Confidence: 94.3%

[AI Explanation]
The traffic pattern shows rapid connection attempts to multiple sequential 
ports (22, 23, 80, 443, 3306, 5432) from IP 192.168.1.105. This is 
characteristic of reconnaissance activity, likely attempting to identify 
running services before a potential attack.

[Recommended Actions]
1. Block source IP 192.168.1.105 at firewall
2. Review authentication logs on targeted hosts
3. Enable enhanced logging for port 22, 3306, 5432
```

**Configuration:**
- OpenAI API key for GPT models (configurable)
- Fallback to local template-based explanations if no API key
- Adjustable explanation verbosity (brief/detailed)

### 4. Alerting Module

**Alert Channels:**

**Email (SMTP):**
- Configurable SMTP server (host, port, TLS)
- Authentication (username, password)
- Recipients list
- Subject templates with attack type
- Rate limiting (prevent alert floods)

**SMS (Twilio):**
- Twilio credentials (account_sid, auth_token)
- From/To phone numbers
- Concise alert message (160 chars)

**Slack Webhook:**
- Webhook URL
- Channel override
- Rich formatting with attack details
- Alert severity color coding

**Alert Triggers:**
- Attack detected with confidence > 80%
- Anomalous traffic spike (> 3x normal)
- Port scan detection
- Multiple failed connection attempts

**Edge Cases:**
- Network failure → queue alerts for retry
- Rate limiting hit → exponential backoff
- Invalid credentials → clear error with validation

### 5. Dashboard

**Visualizations:**
- Real-time traffic rate (packets/second)
- Protocol distribution (pie chart)
- Classification results (bar chart)
- Recent alerts timeline
- Top source/destination IPs
- Threat level gauge

**Sections:**
1. **Header:** App title, status indicator, settings gear
2. **Stats Cards:** Live metrics (packets captured, threats detected, uptime)
3. **Traffic Chart:** Line chart showing traffic over time
4. **Classification Panel:** ML results with confidence
5. **AI Explanation:** Current traffic analysis in plain English
6. **Alerts Feed:** Recent alerts with severity icons
7. **Controls:** Start/Stop capture, interface selector, filter input

**Refresh:** Auto-refresh every 5 seconds (configurable)

---

## Acceptance Criteria

### Capture Module
- [ ] Successfully captures packets from any available network interface
- [ ] Applies BPF filters correctly
- [ ] Saves PCAP files that can be opened in Wireshark
- [ ] Streams packets in real-time to dashboard
- [ ] Handles errors gracefully with user-friendly messages

### ML Module
- [ ] Trains model on CICIDS2017 dataset achieving >95% accuracy
- [ ] Classifies traffic in real-time with <100ms latency
- [ ] Outputs confidence scores alongside predictions
- [ ] Handles unknown traffic types gracefully

### AI Explanation
- [ ] Generates human-readable traffic summaries
- [ ] Explains detected threats in context
- [ ] Provides actionable recommendations
- [ ] Falls back to template explanations when API unavailable

### Alerting
- [ ] Sends email alerts with formatted content
- [ ] Sends SMS via Twilio for critical alerts
- [ ] Posts to Slack with rich formatting
- [ ] Implements rate limiting to prevent spam

### Dashboard
- [ ] Displays live traffic statistics
- [ ] Shows real-time charts updating every 5s
- [ ] Displays AI explanations
- [ ] Shows alert history
- [ ] Allows start/stop of capture
- [ ] Responsive design for different screen sizes

### Export
- [ ] Exports captured data as CSV
- [ ] Generates PDF reports with charts and analysis

---

## Configuration (config.yaml)

```yaml
capture:
  interface: "auto"          # or specific interface name
  filter: ""                  # BPF filter
  buffer_size: 10000         # packets
  output_dir: "./data/captured"

ml:
  model_path: "./models/traffic_classifier.pkl"
  confidence_threshold: 0.8   # trigger alerts above this
  training_data: "./data/cicids2017_sample.csv"

ai:
  provider: "openai"          # or "local"
  api_key: ""                 # Set via environment variable
  model: "gpt-3.5-turbo"
  explanation_level: "detailed"

alerts:
  email:
    enabled: false
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    username: ""
    password: ""
    recipients: []
  sms:
    enabled: false
    twilio_sid: ""
    twilio_token: ""
    from_number: ""
    to_numbers: []
  slack:
    enabled: false
    webhook_url: ""

dashboard:
  host: "0.0.0.0"
  port: 5000
  refresh_interval: 5        # seconds

export:
  csv_dir: "./data/exports"
  pdf_dir: "./data/reports"
```

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Capture | pyshark, tshark |
| ML | scikit-learn, XGBoost, pandas, numpy |
| AI | OpenAI API / fallback templates |
| Alerts | smtplib, twilio, requests |
| Dashboard | Flask, Chart.js, Bootstrap 5 |
| Export | pandas (CSV), reportlab (PDF) |

---

## Dependencies

```
pyshark>=0.4
xgboost>=1.7
scikit-learn>=1.0
pandas>=1.5
numpy>=1.21
flask>=2.0
twilio>=7.0
requests>=2.28
reportlab>=4.0
pyyaml>=6.0
python-dotenv>=0.19
```
