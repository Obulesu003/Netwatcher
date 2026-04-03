# Netwatcher - Technical Specification

## 1. Project Overview

**Project Name:** Netwatcher
**Type:** Network Intrusion Detection System (IDS)
**Core Functionality:** Real-time network traffic capture, ML-powered threat classification, AI explanations, and multi-channel alerting
**Target Users:** Network administrators, security analysts, IT professionals

---

## 2. Project Structure

```
Netwatcher/
├── src/
│   ├── ai/
│   │   ├── __init__.py
│   │   └── explanation_engine.py    # AI explanation generation
│   ├── alerts/
│   │   ├── __init__.py
│   │   ├── alert_manager.py        # Alert orchestration & rate limiting
│   │   ├── email_alert.py          # SMTP email alerts
│   │   ├── sms_alert.py            # Twilio SMS alerts
│   │   ├── slack_alert.py          # Slack webhook alerts
│   │   └── models.py               # Alert data models
│   ├── capture/
│   │   ├── __init__.py
│   │   ├── packet_capture.py       # Live capture using pyshark/tshark
│   │   └── traffic_processor.py    # Packet processing & attack detection
│   ├── dashboard/
│   │   ├── __init__.py
│   │   ├── app.py                  # Flask application with SocketIO
│   │   └── templates/
│   │       └── index.html          # Dashboard UI (single-page app)
│   ├── ml/
│   │   ├── __init__.py
│   │   ├── classifier.py           # Rule-based + ML traffic classification
│   │   ├── features.py             # Feature extraction
│   │   └── model_trainer.py        # Model training utilities
│   └── utils/
│       ├── __init__.py
│       ├── config.py               # YAML configuration management
│       └── logger.py               # Logging utilities
├── scripts/
│   ├── train_model.py              # Train ML classifier
│   ├── train_real_model.py         # Train on CICIDS2017 dataset
│   ├── download_and_train.py       # Download and train pipeline
│   ├── generate_pcaps_fast.py      # Generate test PCAP files
│   ├── export_report.py            # Export reports as CSV/PDF
├── data/
│   ├── test_pcaps/                  # Test PCAP files (6 attack types)
│   ├── cicids2017/                  # CICIDS2017 dataset (optional)
│   └── captured/                    # User-captured traffic
├── models/                          # Trained model storage
├── tests/                           # Unit tests (if any)
├── README.md                        # Project overview
├── SPEC.md                          # This specification
├── CONTRIBUTING.md                   # Contribution guidelines
├── LICENSE                          # MIT License
├── requirements.txt                 # Python dependencies
├── config.example.yaml             # Configuration template
└── run.py                           # Application entry point
```

---

## 3. Functionality Specification

### 3.1 Capture Module (`src/capture/`)

**Features:**
- Live packet capture using pyshark/tshark
- Auto-detect or specify network interface
- BPF filter support (e.g., `tcp port 80`, `udp`, `host 192.168.1.1`)
- PCAP file saving for offline analysis
- Real-time packet event streaming via SocketIO

**Packet Data Captured:**
- Timestamp, Source/Destination IP, Source/Destination Port
- Protocol (TCP/UDP/ICMP/OTHER)
- Packet length, TCP flags, Payload
- Inter-arrival time (calculated)

**Edge Cases:**
- No interfaces available → list available with error
- tshark not installed → installation instructions
- Permission denied → clear error with sudo hint

### 3.2 Traffic Processor (`src/capture/traffic_processor.py`)

**Attack Detection (Rule-Based):**

| Attack | Detection Logic | Threshold |
|--------|-----------------|------------|
| **DoS** | High-volume UDP from single source | 20+ packets >1000 bytes in 10s |
| **Port Scan** | Single source hitting many ports rapidly | 15+ distinct ports in 30s |
| **Brute Force** | Rapid SSH connection attempts | 10+ attempts in 60s |
| **SQL Injection** | Suspicious patterns in HTTP payloads | Dangerous keyword OR 2+ indicators |
| **XSS** | Script injection patterns | Dangerous vector detected |
| **Bot** | Regular interval traffic to suspicious ports | 3+ regular beacon intervals |

**Statistics Tracked:**
- Packet/byte counts, protocol distribution
- Top source/destination IPs and ports
- Packets per second, bytes per second
- Attack pattern counters

### 3.3 ML Classifier (`src/ml/classifier.py`)

**Classification Labels:**
- `BENIGN`, `Bot`, `Brute Force`, `DoS`, `Port Scan`, `SQL Injection`, `XSS`

**Categories & Severity:**
| Category | Attack Types | Severity |
|----------|--------------|----------|
| Normal | BENIGN | 0 |
| Botnet | Bot | 4 |
| Brute Force | Brute Force | 3 |
| DoS | DoS | 3 |
| Reconnaissance | Port Scan | 2 |
| Web Attack | SQL Injection, XSS | 3 |

**Classification Logic:**
1. Always run rule-based detection first
2. If attack patterns detected → use rule-based result
3. If no patterns → check ML model as secondary
4. ML attack predictions require feature evidence (no false positives)

**Output:**
- `label`: Classification category
- `confidence`: 0.0-1.0 confidence score
- `severity`: 0-4 severity level
- `is_threat`: Boolean threat flag
- `all_detected_attacks`: List of detected attack types

### 3.4 AI Explanation Engine (`src/ai/explanation_engine.py`)

**Capabilities:**
- Plain-English traffic summaries
- Context-aware threat explanations
- MITRE ATT&CK tactic mapping
- IOC (Indicators of Compromise) extraction
- Actionable mitigation recommendations

**Output Format:**
```
[Traffic Summary]
Total packets: X | Duration: Xs | Rate: X pps
Protocol distribution: TCP (X%), UDP (X%), ICMP (X%)

[Threat Analysis]
Status: [DETECTED/NORMAL]
Attack Type: [type]
Confidence: [X%]
Severity: [level]

[AI Explanation]
[Dynamic contextual analysis based on attack type]

[MITRE ATT&CK Mapping]
[Tactic] - [Technique]

[Indicators of Compromise]
- IP: [suspicious IPs]
- Ports: [suspicious ports]

[Recommended Actions]
1. [action]
2. [action]
```

**Configuration:**
- OpenAI API key (optional, falls back to templates)
- Explanation verbosity (brief/detailed)

### 3.5 Alerting Module (`src/alerts/`)

**Channels:**
1. **Email (SMTP)** - Formatted HTML alerts
2. **SMS (Twilio)** - Concise 160-char alerts
3. **Slack** - Rich formatting with severity colors

**Alert Manager:**
- Rate limiting: max 3 alerts per 5 minutes
- Severity threshold filtering
- Alert queue with retry on failure
- Alert history tracking

**Alert Trigger Conditions:**
- Attack detected with confidence >= threshold
- Anomalous traffic patterns
- Rate limit bypass for critical threats

### 3.6 Dashboard (`src/dashboard/`)

**Technology:** Flask + SocketIO + Bootstrap 5 + Chart.js

**Tabs:**
1. **Dashboard** - Overview with stats, charts, recent activity
2. **Packet Monitor** - Live packet table with classification
3. **Analytics** - Protocol distribution, top IPs, threat trends
4. **Alerts** - Alert history with filtering
5. **Reports** - Export data as CSV/HTML

**Real-time Features:**
- Live traffic stats (packets/sec, bytes/sec)
- Protocol distribution pie chart
- Top source/destination IPs bar chart
- Threat level indicator
- Recent alerts feed
- AI analysis panel

**Refresh:** Auto-refresh every 5 seconds via SocketIO

---

## 4. Configuration Schema (`config.yaml`)

```yaml
capture:
  interface: "auto"              # or specific interface
  filter: ""                      # BPF filter
  buffer_size: 10000             # packet buffer
  output_dir: "./data/captured"

ml:
  model_path: "./models/traffic_classifier.pkl"
  confidence_threshold: 0.95     # alert threshold

ai:
  provider: "openai"              # or "local"
  api_key: "${OPENAI_API_KEY}"   # environment variable
  model: "gpt-3.5-turbo"
  explanation_level: "detailed"

alerts:
  rate_limit_seconds: 300        # 5 min rate limit
  max_alerts_per_window: 3
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
  refresh_interval: 5

export:
  csv_dir: "./data/exports"
  pdf_dir: "./data/reports"
```

---

## 5. API Reference

### REST Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard home |
| `/api/status` | GET | System status & stats |
| `/api/capture/start` | POST | Start capture |
| `/api/capture/stop` | POST | Stop capture |
| `/api/capture/status` | GET | Capture status |
| `/api/traffic/stats` | GET | Traffic statistics |
| `/api/traffic/packets` | GET | Recent packets (last 100) |
| `/api/alerts` | GET | Alert history |
| `/api/interfaces` | GET | Available network interfaces |
| `/api/model/info` | GET | ML model information |
| `/api/explanation` | GET | AI explanation for current traffic |

### WebSocket Events

**Server → Client:**
- `traffic_update` - Real-time traffic statistics
- `packet` - New packet captured
- `alert` - Alert triggered
- `classification` - ML classification result

**Client → Server:**
- `start_capture` - Start packet capture
- `stop_capture` - Stop packet capture

---

## 6. Test PCAP Files

Generated for testing in `data/test_pcaps/`:

| File | Attack Type | Packets | Size |
|------|-------------|---------|------|
| `dos_attack.pcap` | DoS (UDP flood) | 50,000 | ~52 MB |
| `port_scan.pcap` | Port Scan (TCP SYN) | 30,000 | ~2 MB |
| `brute_force.pcap` | SSH Brute Force | 25,000 | ~2 MB |
| `sql_injection.pcap` | SQL Injection | 30,000 | ~3 MB |
| `xss_attack.pcap` | XSS Attack | 30,000 | ~4 MB |
| `mixed_attack.pcap` | Mixed (all types) | 40,000 | ~7 MB |

---

## 7. Tech Stack

| Component | Technology |
|-----------|------------|
| Capture | pyshark, tshark (Wireshark) |
| ML | scikit-learn (Random Forest) |
| Dashboard | Flask, Flask-SocketIO |
| Frontend | Bootstrap 5, Chart.js, Socket.IO |
| Alerts | smtplib, twilio, requests |
| Config | PyYAML, python-dotenv |

---

## 8. Dependencies

```
flask>=2.0
flask-socketio
pyshark>=0.4
scikit-learn>=1.0
pandas>=1.5
numpy>=1.21
twilio>=7.0
requests>=2.28
pyyaml>=6.0
python-dotenv>=0.19
```

---

## 9. Acceptance Criteria

### Capture Module
- [x] Capture packets from available network interface
- [x] Apply BPF filters correctly
- [x] Stream packets in real-time to dashboard
- [x] Handle errors gracefully

### Detection
- [x] Detect DoS attacks (UDP flood)
- [x] Detect Port Scan attacks
- [x] Detect Brute Force attempts (SSH)
- [x] Detect SQL Injection in HTTP traffic
- [x] Detect XSS attacks in HTTP traffic
- [x] Low false positive rate

### ML Classification
- [x] Rule-based classification with thresholds
- [x] Confidence scoring
- [x] Severity levels
- [x] Attack pattern confirmation

### AI Explanations
- [x] Dynamic threat analysis
- [x] MITRE ATT&CK mapping
- [x] IOC extraction
- [x] Recommended actions

### Dashboard
- [x] Real-time traffic visualization
- [x] Live packet table with classification
- [x] Alert history and management
- [x] Responsive design

### Alerting
- [x] Email alerts with rate limiting
- [x] SMS alerts (Twilio)
- [x] Slack webhook alerts

---

## 10. Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.1.0 | 2024-04-04 | Professional docs, cleanup, ML Model tab removed |
| 2.0.0 | 2024-04-03 | AI explanations, attack detection tuning |
| 1.0.0 | 2024-04-03 | Initial release with basic IDS |

---

*Last Updated: 2024-04-04*