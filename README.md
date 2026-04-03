# Netwatcher - Network Intrusion Detection System

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

**Real-time network traffic analysis with ML-powered threat detection and AI explanations**

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Documentation](#documentation) • [Contributing](#contributing)

</div>

---

## Overview

Netwatcher is a powerful network intrusion detection system (IDS) that captures and analyzes network traffic in real-time. It combines rule-based detection with machine learning classification to identify threats such as DoS attacks, port scans, brute force attempts, SQL injection, and XSS attacks.

### Key Capabilities

- **Real-time Traffic Capture** - Monitor network packets using tshark/pyshark
- **ML-Based Classification** - Detect threats using Random Forest trained on CICIDS2017 dataset
- **AI-Powered Analysis** - Get contextual threat explanations with recommended actions
- **Multi-Channel Alerts** - Email, SMS (Twilio), and Slack notifications
- **Interactive Dashboard** - Web-based real-time monitoring and visualization

---

## Features

| Feature | Description |
|---------|-------------|
| **Live Packet Capture** | Capture network traffic with BPF filtering, interface selection, and PCAP export |
| **Attack Detection** | Detect DoS, Port Scan, Brute Force, SQL Injection, XSS, and Bot attacks |
| **ML Classification** | Rule-based + ML model for accurate threat identification |
| **AI Explanations** | Context-aware threat analysis with plain-English summaries |
| **Real-time Dashboard** | Web interface with live charts, alerts, and packet monitoring |
| **Alert Integration** | Email, SMS, and Slack notifications with rate limiting |

---

## Installation

### Prerequisites

- **Python 3.8+**
- **Wireshark/tshark** - [Download](https://www.wireshark.org/download.html)
- **OpenAI API Key** (optional, for AI explanations)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/Obulesu003/Netwatcher.git
cd Netwatcher

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Start the dashboard
python run.py
```

Open http://localhost:5000 in your browser.

### Configuration

Copy `config.example.yaml` to `config.yaml` and customize:

```yaml
capture:
  interface: "auto"        # or specific interface name
  filter: ""               # BPF filter (e.g., "tcp port 80")
  output_dir: "./data/captured"

ml:
  model_path: "./models/traffic_classifier.pkl"
  confidence_threshold: 0.95

ai:
  provider: "openai"
  api_key: "${OPENAI_API_KEY}"  # Set via environment variable
  model: "gpt-3.5-turbo"

alerts:
  email:
    enabled: false
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    username: "your-email@gmail.com"
    password: "your-app-password"
    recipients: ["admin@example.com"]

dashboard:
  host: "0.0.0.0"
  port: 5000
  refresh_interval: 5
```

---

## Usage

### Start Capture & Analysis

```bash
# Run dashboard
python run.py
```

### CLI Commands

```bash
# Capture packets from interface
python -m src.capture.packet_capture --interface eth0 --duration 60

# Analyze PCAP file
python -m src.capture.packet_capture --file capture.pcap --analyze

# Generate test PCAP files
python scripts/generate_pcaps_fast.py
```

### Dashboard Features

1. **Dashboard Tab** - Overview with stats, charts, and recent activity
2. **Packet Monitor** - Live packet table with classification and confidence
3. **Analytics** - Protocol distribution, top IPs, threat trends
4. **Alerts** - Alert history and management
5. **Reports** - Export captured data as CSV or PDF

---

## Project Structure

```
Netwatcher/
├── src/
│   ├── ai/                  # AI explanation engine
│   ├── alerts/              # Alert channels (email, SMS, Slack)
│   ├── capture/             # Packet capture and processing
│   ├── dashboard/          # Flask web interface
│   ├── ml/                  # ML training and classification
│   └── utils/              # Configuration and utilities
├── scripts/                 # Utility scripts
│   ├── train_model.py       # Train ML model
│   ├── generate_pcaps_fast.py
│   └── export_report.py
├── data/
│   ├── test_pcaps/          # Test PCAP files
│   └── cicids2017/          # Training dataset (optional)
├── models/                  # Trained ML models
├── README.md
├── SPEC.md
└── requirements.txt
```

---

## Attack Detection

Netwatcher detects the following attack types:

| Attack | Detection Method | Threshold |
|--------|------------------|-----------|
| **DoS** | High-volume UDP traffic | 30+ packets, 200+ pps |
| **Port Scan** | Multiple ports from single source | 15+ ports, rapid enumeration |
| **Brute Force** | Rapid connection attempts (SSH) | 10+ attempts in 60s |
| **SQL Injection** | Suspicious patterns in HTTP payloads | 20+ detections |
| **XSS** | Script injection patterns | 20+ detections |
| **Bot** | Regular interval beacon traffic | 3+ beacon intervals |

---

## API Reference

### REST Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | System status and statistics |
| `/api/capture/start` | POST | Start packet capture |
| `/api/capture/stop` | POST | Stop packet capture |
| `/api/traffic/stats` | GET | Traffic statistics |
| `/api/alerts` | GET | Recent alerts |
| `/api/traffic/packets` | GET | Recent packets |

### WebSocket Events

- `traffic_update` - Real-time traffic statistics
- `alert` - New alert notification
- `classification` - ML classification result

---

## Documentation

For detailed documentation, see the [docs/](docs/) folder:

| Guide | Description |
|-------|-------------|
| [docs/what-is-netwatcher.md](docs/what-is-netwatcher.md) | What is Netwatcher and why use it |
| [docs/how-it-works.md](docs/how-it-works.md) | Internal architecture and data flow |
| [docs/setup-guide.md](docs/setup-guide.md) | Complete installation guide |
| [docs/architecture.md](docs/architecture.md) | System design and modules |
| [docs/tech-stack.md](docs/tech-stack.md) | Technologies and dependencies |
| [docs/configuration.md](docs/configuration.md) | All configuration options |
| [docs/modifying-detection.md](docs/modifying-detection.md) | Change detection thresholds |
| [docs/adding-new-attacks.md](docs/adding-new-attacks.md) | Add new attack types |
| [docs/faq.md](docs/faq.md) | Frequently asked questions |

Also see:
- [SPEC.md](SPEC.md) - Technical specification
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [LICENSE](LICENSE) - MIT License

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Capture | pyshark, tshark/Wireshark |
| ML | scikit-learn, Random Forest |
| Dashboard | Flask, Chart.js, Bootstrap 5 |
| Alerts | smtplib, Twilio, Slack webhooks |
| AI | OpenAI API (optional) |

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

## Acknowledgments

- [CICIDS2017 Dataset](https://www.unb.ca/cic/datasets/ids2017.html) - Canadian Institute for Cybersecurity
- Built with Python, Flask, scikit-learn, and modern web technologies