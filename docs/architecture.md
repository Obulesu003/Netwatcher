# Architecture

This document describes the high-level architecture and design decisions in Netwatcher.

## System Overview

Netwatcher follows a **modular, event-driven architecture** with clear separation of concerns:

```
┌──────────────────────────────────────────────────────────────────────┐
│                           CLIENT LAYER                               │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │                     Web Dashboard (Browser)                     │  │
│  │   HTML/CSS/JavaScript │ Bootstrap 5 │ Chart.js │ Socket.IO   │  │
│  └────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
                                    │ HTTP/WebSocket
                                    ▼
┌──────────────────────────────────────────────────────────────────────┐
│                          SERVER LAYER                               │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                      Flask Application                           │ │
│  │   REST API │ SocketIO Events │ Session Management │ Templates  │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                    │                                  │
│        ┌───────────────────────────┼───────────────────────────┐      │
│        ▼                           ▼                           ▼      │
│  ┌──────────────┐           ┌──────────────┐           ┌──────────┐ │
│  │   Capture    │           │   ML/AI      │           │  Alert   │ │
│  │   Module     │           │   Module     │           │  Module  │ │
│  └──────────────┘           └──────────────┘           └──────────┘ │
└──────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────┐
│                          EXTERNAL LAYER                              │
│   Network Interface (tshark) │ OpenAI API │ SMTP/SMS/Slack APIs    │
└──────────────────────────────────────────────────────────────────────┘
```

## Module Architecture

### 1. Capture Module (`src/capture/`)

```
┌─────────────────────────────────────────────────────────────────┐
│                        PacketCapture                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌─────────────────┐    ┌─────────────────┐                   │
│   │   Interface      │    │   BPF Filter    │                   │
│   │   Selector      │───▶│   (optional)     │                   │
│   └─────────────────┘    └─────────────────┘                   │
│            │                       │                           │
│            ▼                       ▼                           │
│   ┌─────────────────────────────────────────────────┐          │
│   │           pyshark capture session               │          │
│   │  - Live packet stream                           │          │
│   │  - Async packet callback                        │          │
│   └────────────────────────┬────────────────────────┘          │
│                            │                                   │
│                            ▼                                   │
│   ┌─────────────────────────────────────────────────┐          │
│   │           Packet → CapturedPacket               │          │
│   │  Converter (timestamp, IPs, ports, payload)    │          │
│   └────────────────────────┬────────────────────────┘          │
│                            │                                   │
│                            ▼                                   │
│   ┌─────────────────────────────────────────────────┐          │
│   │           TrafficProcessor                       │          │
│   │  - Statistics tracking                           │          │
│   │  - Attack pattern detection                      │          │
│   └────────────────────────┬────────────────────────┘          │
│                            │                                   │
│                            ▼                                   │
│   ┌─────────────────────────────────────────────────┐          │
│   │           SocketIO Event                        │          │
│   │  - Emit packet to connected clients             │          │
│   └─────────────────────────────────────────────────┘          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Key Classes:**
- `PacketCapture` - Main capture orchestrator
- `TrafficProcessor` - Packet processing and stats
- `CapturedPacket` - Data model for packet info

**Design Decisions:**
- Uses pyshark for Python binding to tshark (reliable, cross-platform)
- BPF filters applied at capture level (efficient)
- Packet processing in separate thread (non-blocking)

### 2. ML Module (`src/ml/`)

```
┌─────────────────────────────────────────────────────────────────┐
│                     TrafficClassifier                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Input: Features Dictionary                                     │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │ {                                                           │  │
│   │   packet_count, byte_count,                               │  │
│   │   tcp_packets, udp_packets,                               │  │
│   │   sql_injection_count, xss_count,                         │  │
│   │   brute_force_count, dos_packets,                         │  │
│   │   port_scan_score, bot_beacon_score,                       │  │
│   │   ...                                                      │  │
│   │ }                                                           │  │
│   └─────────────────────────────────────────────────────────┘  │
│                            │                                     │
│                            ▼                                     │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │  Phase 1: Rule-Based Detection                         │  │
│   │  ┌─────────────────────────────────────────────────────┐│  │
│   │  │ _detect_attack_patterns(features)                  ││  │
│   │  │                                                     ││  │
│   │  │ if xss_count >= 20: add 'XSS'                     ││  │
│   │  │ if sql_count >= 20: add 'SQL Injection'            ││  │
│   │  │ if brute_force >= 20: add 'Brute Force'            ││  │
│   │  │ if dos_packets >= 30 and pps >= 200: add 'DoS'     ││  │
│   │  │ if port_scan_score >= 0.5 and ports >= 20: add...  ││  │
│   │  └─────────────────────────────────────────────────────┘│  │
│   └─────────────────────────────────────────────────────────┘  │
│                            │                                     │
│                            ▼                                     │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │  Phase 2: Classification                                 │  │
│   │  ┌─────────────────────────────────────────────────────┐│  │
│   │  │ if attacks found:                                  ││  │
│   │  │   → Use rule-based result (high confidence)        ││  │
│   │  │ else:                                               ││  │
│   │  │   → Optionally check ML model                       ││  │
│   │  │   → Only trust BENIGN predictions from ML          ││  │
│   │  │   → Treat ML attack predictions as BENIGN          ││  │
│   │  │      (requires feature evidence)                    ││  │
│   │  └─────────────────────────────────────────────────────┘│  │
│   └─────────────────────────────────────────────────────────┘  │
│                            │                                     │
│                            ▼                                     │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │  Output: ClassificationResult                             │  │
│   │  { label, confidence, severity, is_threat, category }   │  │
│   └─────────────────────────────────────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Classification Logic:**
1. **Always run rule-based first** - Primary detection method
2. **If attacks detected** - Use rule-based result (high confidence)
3. **If no attacks** - Check ML as secondary verification
4. **ML attack predictions require evidence** - Prevents false positives

**Attack Labels:**
- `BENIGN`, `Bot`, `Brute Force`, `DoS`, `Port Scan`, `SQL Injection`, `XSS`

**Categories & Severity:**
| Category | Attacks | Severity |
|----------|---------|----------|
| Normal | BENIGN | 0 |
| Botnet | Bot | 4 |
| Brute Force | Brute Force | 3 |
| DoS | DoS | 3 |
| Reconnaissance | Port Scan | 2 |
| Web Attack | SQL Injection, XSS | 3 |

### 3. Dashboard Module (`src/dashboard/`)

```
┌─────────────────────────────────────────────────────────────────┐
│                         Flask App                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌───────────────────────────────────────────────────────────┐ │
│   │                    Routes                                   │ │
│   │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐     │ │
│   │  │  GET /  │  │GET /api │  │POST /api│  │GET /api │     │ │
│   │  │         │  │ status  │  │ capture │  │ alerts  │     │ │
│   │  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘     │ │
│   │       │             │             │             │          │ │
│   │       ▼             ▼             ▼             ▼          │ │
│   │   render        get_stats    start_capture  get_alerts     │ │
│   │   template      return       return         return         │ │
│   └───────────────────────────────────────────────────────────┘ │
│                              │                                  │
│                              ▼                                  │
│   ┌───────────────────────────────────────────────────────────┐ │
│   │                SocketIO Events                            │ │
│   │                                                           │ │
│   │   Server → Client:                                        │ │
│   │   • traffic_update: {stats every 5s}                     │ │
│   │   • packet: {new_packet_data}                             │ │
│   │   • alert: {alert_data}                                   │ │
│   │   • classification: {result}                              │ │
│   │                                                           │ │
│   │   Client → Server:                                        │ │
│   │   • start_capture: {interface, filter}                    │ │
│   │   • stop_capture: {}                                       │ │
│   │                                                           │ │
│   └───────────────────────────────────────────────────────────┘ │
│                              │                                  │
│                              ▼                                  │
│   ┌───────────────────────────────────────────────────────────┐ │
│   │              Application State (Global)                    │ │
│   │                                                           │ │
│   │   _app_state = {                                          │ │
│   │       capture: PacketCapture(),                           │ │
│   │       processor: TrafficProcessor(),                      │ │
│   │       classifier: TrafficClassifier(),                    │ │
│   │       alert_manager: AlertManager(),                      │ │
│   │       is_capturing: False                                  │ │
│   │   }                                                        │ │
│   │                                                           │ │
│   └───────────────────────────────────────────────────────────┘ │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 4. Alert Module (`src/alerts/`)

```
┌─────────────────────────────────────────────────────────────────┐
│                       AlertManager                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Alert Trigger (from classifier)                               │
│              │                                                   │
│              ▼                                                   │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │  Rate Limiter                                             │  │
│   │  - Max 3 alerts per 300 seconds (configurable)           │  │
│   │  - If limit exceeded, skip sending (but log)              │  │
│   └─────────────────────────────────────────────────────────┘  │
│              │                                                   │
│              ▼                                                   │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │  Alert Object Builder                                      │  │
│   │  { id, timestamp, attack_type, severity, confidence,     │  │
│   │    source_ip, destination_ip, recommendation }             │  │
│   └─────────────────────────────────────────────────────────┘  │
│              │                                                   │
│              ▼                                                   │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │  Channel Dispatcher                                       │  │
│   │                                                           │  │
│   │  ┌──────────┐  ┌──────────┐  ┌──────────┐              │  │
│   │  │  Email   │  │   SMS    │  │  Slack   │              │  │
│   │  │  SMTP    │  │ Twilio   │  │ Webhook  │              │  │
│   │  └──────────┘  └──────────┘  └──────────┘              │  │
│   └─────────────────────────────────────────────────────────┘  │
│              │                                                   │
│              ▼                                                   │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │  Alert Storage                                            │  │
│   │  - In-memory list (for dashboard)                        │  │
│   │  - Export to JSON/CSV (optional)                         │  │
│   └─────────────────────────────────────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Data Models

### CapturedPacket
```python
@dataclass
class CapturedPacket:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # TCP, UDP, ICMP, etc.
    length: int
    info: str
    flags: str
    payload: str
```

### ClassificationResult
```python
@dataclass
class ClassificationResult:
    label: str           # Attack type or "BENIGN"
    category: str       # Normal, DoS, Botnet, etc.
    confidence: float   # 0.0 - 1.0
    severity: int        # 0-4
    is_threat: bool
    timestamp: str
    features: Dict[str, float]
    all_detected_attacks: List[str]
```

### Alert
```python
@dataclass
class Alert:
    id: str
    timestamp: str
    attack_type: str
    severity: int
    confidence: float
    source_ip: str
    destination_ip: str
    recommendation: str
    acknowledged: bool
```

## Design Patterns Used

### 1. Singleton Pattern (Application State)
```python
# Global app state - single instance
_app_state = AppState()
```

### 2. Observer Pattern (SocketIO)
```python
# Register callback for packet events
processor.register_callback(on_new_packet)
```

### 3. Strategy Pattern (Alerts)
```python
# Different alert channels implement same interface
class EmailAlert:
    def send(self, alert): ...

class SMSAlert:
    def send(self, alert): ...
```

### 4. Factory Pattern (Classifier)
```python
# Create classifier based on config
classifier = TrafficClassifier(model_path=...)
```

## File Structure

```
Netwatcher/
├── src/
│   ├── ai/
│   │   └── explanation_engine.py    # AI explanations
│   ├── alerts/
│   │   ├── alert_manager.py         # Orchestrator
│   │   ├── email_alert.py          # Channel 1
│   │   ├── sms_alert.py            # Channel 2
│   │   └── slack_alert.py          # Channel 3
│   ├── capture/
│   │   ├── packet_capture.py       # Capture logic
│   │   └── traffic_processor.py     # Processing
│   ├── dashboard/
│   │   ├── app.py                  # Flask app
│   │   └── templates/
│   │       └── index.html          # Single-page UI
│   ├── ml/
│   │   ├── classifier.py           # Classification
│   │   └── features.py             # Feature extraction
│   └── utils/
│       ├── config.py               # Configuration
│       └── logger.py               # Logging
├── scripts/                         # Utility scripts
├── data/                            # Data storage
├── docs/                            # Documentation
├── run.py                           # Entry point
└── config.yaml                      # Configuration
```

## Configuration Management

```
config.yaml
    │
    ├── capture.*        → PacketCapture settings
    ├── ml.*              → Classifier settings
    ├── ai.*              → AI explanation settings
    ├── alerts.*          → Alert channels & limits
    ├── dashboard.*      → Web server settings
    └── export.*         → Report export settings
```

**Environment Variables:**
- `${OPENAI_API_KEY}` - OpenAI API key
- `${SMTP_PASSWORD}` - Email password
- `${TWILIO_TOKEN}` - Twilio auth token

## Error Handling Strategy

| Error Type | Handling |
|------------|----------|
| tshark not found | Clear error message + install instructions |
| Capture permission denied | Admin/sudo instructions |
| Network interface unavailable | List available interfaces |
| Alert delivery failed | Log error, continue operation |
| ML model load failure | Fallback to rule-based only |
| OpenAI API failure | Fallback to template explanations |

## Performance Considerations

- **Capture**: Async using pyshark (non-blocking)
- **Processing**: In-memory with circular buffer (10,000 packets max)
- **Dashboard**: WebSocket for real-time updates (no polling)
- **Alerts**: Rate limiting to prevent flood

---

**Next:** [Tech Stack](tech-stack.md)