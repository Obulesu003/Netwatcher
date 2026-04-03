# Configuration Guide

This guide explains all configuration options in Netwatcher and how to modify them.

## Configuration Files

| File | Purpose |
|------|---------|
| `config.yaml` | Main configuration (version controlled example: `config.example.yaml`) |
| `.env` | Environment variables (secrets, API keys) |

## config.yaml Structure

```yaml
# ============================================
# NETWATCHER CONFIGURATION
# ============================================

capture:
  interface: "auto"           # Network interface to capture from
  filter: ""                   # BPF filter (e.g., "tcp port 80")
  buffer_size: 10000          # Max packets to keep in memory
  output_dir: "./data/captured"  # Where to save PCAP files

ml:
  model_path: "./models/traffic_classifier.pkl"  # ML model file
  confidence_threshold: 0.95   # Alert threshold (0-1)

ai:
  provider: "openai"           # "openai" or "local"
  api_key: "${OPENAI_API_KEY}" # API key (use env var)
  model: "gpt-3.5-turbo"      # OpenAI model
  explanation_level: "detailed"  # "brief" or "detailed"

alerts:
  rate_limit_seconds: 300     # Seconds between alerts
  max_alerts_per_window: 3    # Max alerts per time window
  email:
    enabled: false
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    username: "your-email@gmail.com"
    password: "${SMTP_PASSWORD}"
    recipients: ["admin@example.com"]
  sms:
    enabled: false
    twilio_sid: "${TWILIO_SID}"
    twilio_token: "${TWILIO_TOKEN}"
    from_number: "+1234567890"
    to_numbers: ["+0987654321"]
  slack:
    enabled: false
    webhook_url: "${SLACK_WEBHOOK_URL}"

dashboard:
  host: "0.0.0.0"             # Listen address
  port: 5000                   # Web port
  refresh_interval: 5         # Seconds between updates

export:
  csv_dir: "./data/exports"
  pdf_dir: "./data/reports"
```

## Configuration Sections

### 1. Capture Settings

**Location in code:** `src/capture/packet_capture.py`

```yaml
capture:
  interface: "auto"           # or "eth0", "wlan0", etc.
  filter: "tcp port 80"      # BPF filter syntax
  buffer_size: 10000          # Memory buffer for packets
  output_dir: "./data/captured"
```

**Options:**
| Setting | Values | Default | Description |
|---------|--------|---------|-------------|
| interface | "auto", "eth0", "wlan0", etc. | "auto" | Network interface |
| filter | BPF syntax | "" | Packet filter |
| buffer_size | 1000-100000 | 10000 | Packet buffer |
| output_dir | path | "./data/captured" | Save location |

**Find available interfaces:**
```bash
tshark -D
```

### 2. ML Settings

**Location in code:** `src/ml/classifier.py`

```yaml
ml:
  model_path: "./models/traffic_classifier.pkl"
  confidence_threshold: 0.95
```

| Setting | Values | Default | Description |
|---------|--------|---------|-------------|
| model_path | path | "./models/traffic_classifier.pkl" | Trained model file |
| confidence_threshold | 0.0-1.0 | 0.95 | Alert trigger threshold |

**Higher threshold = fewer false positives, but might miss some attacks.**

### 3. Detection Thresholds

**Location in code:** `src/capture/traffic_processor.py`

These are **hardcoded** in the code (not in config). To change them, edit the file:

```python
# In traffic_processor.py, look for these:

# XSS detection (line ~260)
if xss_count >= 20 or (xss_count >= 10 and web_payload >= 10):
    detected.append('XSS')

# SQL Injection detection (line ~260)
if sql_count >= 20:
    detected.append('SQL Injection')

# Brute Force detection (line ~266)
if brute_force >= 20:
    detected.append('Brute Force')

# DoS detection (line ~269)
if dos_packets >= 30 and packets_per_second >= 200:
    detected.append('DoS')

# Port Scan detection (line ~272)
if port_scan_score >= 0.5 and unique_dst_ports >= 20:
    detected.append('Port Scan')

# Bot detection (line ~275)
if bot_score >= 3:
    detected.append('Bot')
```

**To make thresholds configurable**, see [Adding New Attacks](adding-new-attacks.md).

### 4. Alert Settings

**Location in code:** `src/alerts/alert_manager.py`

```yaml
alerts:
  rate_limit_seconds: 300      # 5 minutes
  max_alerts_per_window: 3    # Max 3 alerts per window
```

| Setting | Values | Default | Description |
|---------|--------|---------|-------------|
| rate_limit_seconds | 60-3600 | 300 | Alert cooldown period |
| max_alerts_per_window | 1-20 | 3 | Alerts per period |

### 5. Email Alerts

```yaml
alerts:
  email:
    enabled: true
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    username: "your-email@gmail.com"
    password: "your-16-char-app-password"
    recipients: ["admin@example.com", "security@company.com"]
```

**Gmail Setup:**
1. Enable 2-factor authentication
2. Generate App Password: Google Account → Security → App Passwords
3. Use the 16-character app password, not your regular password

### 6. SMS Alerts (Twilio)

```yaml
alerts:
  sms:
    enabled: true
    twilio_sid: "ACxxxxxxxxxxxxxxxxx"
    twilio_token: "your-auth-token"
    from_number: "+1234567890"
    to_numbers: ["+0987654321"]
```

**Twilio Setup:**
1. Create account at https://twilio.com
2. Get Account SID and Auth Token from console
3. Get a phone number from Twilio
4. Add recipient numbers

### 7. Slack Alerts

```yaml
alerts:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/XXX/YYY/ZZZ"
```

**Slack Setup:**
1. Create Slack app at https://api.slack.com/apps
2. Enable Incoming Webhooks
3. Create webhook URL for your channel
4. Copy URL to config

### 8. Dashboard Settings

```yaml
dashboard:
  host: "0.0.0.0"             # "127.0.0.1" for local only
  port: 5000                  # Change if port in use
  refresh_interval: 5         # Dashboard refresh rate
```

| Setting | Values | Default | Description |
|---------|--------|---------|-------------|
| host | IP address | "0.0.0.0" | Bind address |
| port | 1024-65535 | 5000 | Web server port |
| refresh_interval | 1-60 | 5 | Seconds |

### 9. AI Settings

```yaml
ai:
  provider: "openai"          # "openai" or "local"
  api_key: "${OPENAI_API_KEY}"
  model: "gpt-3.5-turbo"      # or "gpt-4"
  explanation_level: "detailed"  # "brief" or "detailed"
```

**Without OpenAI key:** Set `provider: "local"` for template-based explanations.

## Environment Variables

Create a `.env` file for secrets:

```bash
# .env file
OPENAI_API_KEY=sk-your-key-here
SMTP_PASSWORD=your-app-password
TWILIO_SID=ACxxxxxxxxxxxxxxxxx
TWILIO_TOKEN=your-token-here
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ
```

**Never commit `.env` to git!** It's in `.gitignore`.

## Quick Reference: Common Changes

### Change Detection Sensitivity

Edit `src/capture/traffic_processor.py`:

```python
# Make it MORE sensitive (detect smaller attacks)
if xss_count >= 10:      # was 20
if sql_count >= 10:      # was 20
if brute_force >= 10:    # was 20

# Make it LESS sensitive (fewer false positives)
if xss_count >= 50:      # was 20
if sql_count >= 50:      # was 20
if brute_force >= 50:    # was 20
```

### Change Port Number

Edit `config.yaml`:
```yaml
dashboard:
  port: 8080  # instead of 5000
```

### Change Alert Threshold

Edit `config.yaml`:
```yaml
ml:
  confidence_threshold: 0.80  # was 0.95 (lower = more alerts)
```

### Add New Alert Channel

1. Create new file in `src/alerts/`
2. Implement `send(alert)` method
3. Register in `alert_manager.py`
4. Add config options in `config.yaml`

---

**Next:** [Modifying Detection](modifying-detection.md)