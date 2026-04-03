# Netwatcher - Network Traffic Analyzer with ML & AI

A powerful network traffic analysis tool that captures packets, classifies traffic using machine learning, generates AI-powered explanations, and alerts administrators about suspicious activity.

## Features

- **Live Traffic Capture**: Capture network packets using pyshark/tshark
- **ML Classification**: Detect threats using XGBoost trained on CICIDS2017 dataset
- **AI Explanations**: Get plain-English summaries of network traffic and threats
- **Multi-Channel Alerts**: Email, SMS (Twilio), and Slack notifications
- **Real-Time Dashboard**: Visual traffic stats, charts, and analysis

## Installation

### Prerequisites

- Python 3.8+
- Wireshark/tshark installed and in PATH
- (Optional) OpenAI API key for AI explanations

### Setup

```bash
# Clone or navigate to project
cd Netwatcher

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Install Wireshark (if not already installed)
# Download from https://www.wireshark.org/download.html
```

### Configuration

Copy `config.example.yaml` to `config.yaml` and adjust settings:

```yaml
capture:
  interface: "auto"
  filter: ""
  output_dir: "./data/captured"

ml:
  model_path: "./models/traffic_classifier.pkl"
  confidence_threshold: 0.8

ai:
  provider: "openai"
  api_key: "your-api-key"  # Set via OPENAI_API_KEY env var
  model: "gpt-3.5-turbo"

alerts:
  email:
    enabled: true
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

## Usage

### Train the ML Model

```bash
python train_model.py
```

This trains a classifier on the CICIDS2017 dataset. If no dataset is available, a sample model with synthetic data will be created.

### Run the Dashboard

```bash
python run.py
```

Then open http://localhost:5000 in your browser.

### CLI Mode

```bash
# Capture with live analysis
python -m src.capture.packet_capture --interface eth0 --duration 60

# Classify a PCAP file
python -m src.capture.packet_capture --file capture.pcap --analyze

# Generate a report
python export_report.py --input data/captured/session.pcap --output report.pdf
```

## Architecture

```
Netwatcher/
├── src/
│   ├── capture/        # Packet capture and processing
│   ├── ml/             # ML training and classification
│   ├── ai/             # AI explanation engine
│   ├── alerts/         # Alert channels (email, SMS, Slack)
│   ├── dashboard/       # Flask web interface
│   └── utils/          # Configuration and utilities
├── models/             # Trained ML models
├── data/               # Captured data and exports
├── train_model.py      # Model training script
└── run.py              # Application entry point
```

## API Reference

### REST Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | System status and statistics |
| `/api/capture/start` | POST | Start packet capture |
| `/api/capture/stop` | POST | Stop packet capture |
| `/api/capture/status` | GET | Capture status |
| `/api/traffic/stats` | GET | Traffic statistics |
| `/api/alerts` | GET | Recent alerts |
| `/api/config` | GET/PUT | Configuration |

### WebSocket Events

- `traffic_update` - Real-time traffic statistics
- `alert` - New alert notification
- `classification` - ML classification result

## Alert Configuration

### Email Alerts

Configure SMTP settings in `config.yaml`:

```yaml
alerts:
  email:
    enabled: true
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    username: "your-email@gmail.com"
    password: "your-app-password"
    recipients: ["admin@example.com"]
```

### SMS Alerts (Twilio)

```yaml
alerts:
  sms:
    enabled: true
    twilio_sid: "your-account-sid"
    twilio_token: "your-auth-token"
    from_number: "+1234567890"
    to_numbers: ["+0987654321"]
```

### Slack Alerts

```yaml
alerts:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/..."
```

## Development

### Run Tests

```bash
pytest tests/
```

### Code Quality

```bash
flake8 src/
mypy src/
```

## License

MIT License

## Acknowledgments

- CICIDS2017 dataset from Canadian Institute for Cybersecurity
- Built with pyshark, XGBoost, Flask, and OpenAI
