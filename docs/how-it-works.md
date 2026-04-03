# How Netwatcher Works

This document explains the internal workings of Netwatcher from packet capture to threat detection.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        NETWATCHER                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │   Network    │───▶│   Packet    │───▶│  Traffic     │       │
│  │   Interface  │    │   Capture   │    │  Processor   │       │
│  └──────────────┘    └──────────────┘    └──────┬───────┘       │
│                                                  │               │
│                                                  ▼               │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │   Dashboard  │◀───│   Web        │◀───│    ML        │       │
│  │   (Browser)  │    │   Server     │    │  Classifier  │       │
│  └──────────────┘    └──────────────┘    └──────────────┘       │
│         │                  │                    │               │
│         │                  │                    │               │
│         ▼                  ▼                    ▼               │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │   Socket.IO  │    │    Flask     │    │    AI        │       │
│  │   Real-time │    │    API       │    │  Explanations│       │
│  └──────────────┘    └──────────────┘    └──────────────┘       │
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐                           │
│  │   Alert      │◀───│   Alert      │                           │
│  │   Manager    │    │  Triggers    │                           │
│  └──────────────┘    └──────────────┘                           │
│         │                                                           │
│         ▼                                                           │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │   Email      │    │   SMS        │    │   Slack      │       │
│  │   (SMTP)     │    │  (Twilio)    │    │  Webhooks    │       │
│  └──────────────┘    └──────────────┘    └──────────────┘       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Data Flow

### 1. Packet Capture

```
Network Interface (eth0, wlan0, etc.)
         │
         ▼
┌─────────────────┐
│  pyshark/tshark │
│  Captures raw   │
│  packets        │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Raw Packet     │
│  Data           │
└────────┬────────┘
```

**What happens:**
1. Netwatcher connects to network interface using `pyshark` (Python wrapper for tshark)
2. Applies optional BPF filter (e.g., `tcp port 80`)
3. Captures packets in real-time stream
4. Converts to internal `CapturedPacket` format

### 2. Traffic Processing

Each captured packet goes through:

```
CapturedPacket {
    timestamp, src_ip, dst_ip, src_port, dst_port,
    protocol, length, flags, payload
}
         │
         ▼
┌─────────────────────────────────────────┐
│         TrafficProcessor               │
├─────────────────────────────────────────┤
│  1. Update Statistics                   │
│     - packet count, byte count          │
│     - protocol distribution             │
│     - top IPs, top ports               │
│                                          │
│  2. Attack Pattern Detection            │
│     - Check payload for patterns        │
│     - Track connection attempts         │
│     - Calculate threat scores           │
│                                          │
│  3. Return Features                     │
│     - xss_count, sql_injection_count    │
│     - brute_force_count, dos_packets    │
│     - port_scan_score, bot_beacon_score  │
└─────────────────────────────────────────┘
         │
         ▼
Features Dictionary
```

### 3. Attack Detection Logic

Netwatcher uses **rule-based detection** with calibrated thresholds:

| Attack | Detection Method | File |
|--------|------------------|------|
| **DoS** | Count UDP packets >1000 bytes from same source in 10s window | `traffic_processor.py:_track_dos()` |
| **Port Scan** | Count unique destination ports from same source in 30s | `traffic_processor.py:_track_port_scan()` |
| **Brute Force** | Count SSH connection attempts from same source in 60s | `traffic_processor.py:_track_ssh_attempts()` |
| **SQL Injection** | Pattern matching in HTTP payloads | `traffic_processor.py:_update_stats()` |
| **XSS** | Script tag/handler detection in payloads | `traffic_processor.py:_update_stats()` |
| **Bot** | Regular interval detection to suspicious ports | `traffic_processor.py:_track_bot_beacon()` |

### 4. ML Classification

```
Features Dictionary
         │
         ▼
┌─────────────────────────────────────────┐
│       TrafficClassifier                 │
├─────────────────────────────────────────┤
│                                          │
│  Step 1: Rule-Based Detection            │
│  ┌─────────────────────────────────┐   │
│  │ _detect_attack_patterns(features)│   │
│  │ Returns list of detected attacks│   │
│  └─────────────────────────────────┘   │
│           │                             │
│           ▼                             │
│  Step 2: If attacks found              │
│  ┌─────────────────────────────────┐   │
│  │ _classify_rule_based(features)  │   │
│  │ Uses detection counters         │   │
│  └─────────────────────────────────┘   │
│           │                             │
│           ▼                             │
│  Step 3: If no attacks                 │
│  ┌─────────────────────────────────┐   │
│  │ Optional ML model check         │   │
│  │ (sklearn Random Forest)         │   │
│  └─────────────────────────────────┘   │
│                                          │
└─────────────────────────────────────────┘
         │
         ▼
ClassificationResult {
    label,        // Attack type or "BENIGN"
    confidence,  // 0.0 - 1.0
    severity,    // 0-4
    is_threat,   // boolean
    category     // Normal/Botnet/DoS/etc.
}
```

### 5. Alert Generation

```
ClassificationResult
         │
         ▼
┌─────────────────────────────────────────┐
│          AlertManager                  │
├─────────────────────────────────────────┤
│                                          │
│  1. Check Rate Limits                    │
│     - Max 3 alerts per 5 minutes         │
│     - Skip if rate limit exceeded        │
│                                          │
│  2. Build Alert Object                   │
│     - timestamp, attack_type             │
│     - severity, confidence              │
│     - source_ip, recommendation          │
│                                          │
│  3. Send via Channels                    │
│     - Email (if configured)              │
│     - SMS (if configured)                │
│     - Slack (if configured)             │
│                                          │
│  4. Store in History                     │
│     - Alert list for dashboard           │
│                                          │
└─────────────────────────────────────────┘
```

### 6. Web Dashboard

```
┌─────────────────────────────────────────┐
│           Flask + Socket.IO             │
├─────────────────────────────────────────┤
│                                          │
│  REST API Endpoints:                     │
│  ├── GET  /api/status        → stats    │
│  ├── POST /api/capture/start → start    │
│  ├── POST /api/capture/stop  → stop     │
│  ├── GET  /api/traffic/stats → features  │
│  ├── GET  /api/alerts        → history  │
│  └── GET  /api/traffic/packets → packets │
│                                          │
│  WebSocket Events:                       │
│  ├── 'traffic_update'   (server→client)  │
│  ├── 'packet'          (server→client)  │
│  ├── 'alert'           (server→client)  │
│  └── 'classification'  (server→client)  │
│                                          │
└─────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────┐
│        Browser Dashboard               │
├─────────────────────────────────────────┤
│  Tabs: Dashboard | Packets | Analytics │
│        Alerts | Reports                │
│                                          │
│  Components:                             │
│  - Stats cards (packets, threats, rate)  │
│  - Charts (protocol pie, traffic line)   │
│  - Tables (packets, alerts)              │
│  - AI Analysis panel                    │
│                                          │
│  Updates every 5 seconds via Socket.IO  │
└─────────────────────────────────────────┘
```

## Key Files and Their Roles

| File | Purpose |
|------|---------|
| `src/capture/packet_capture.py` | Live packet capture using pyshark |
| `src/capture/traffic_processor.py` | Process packets, detect attack patterns |
| `src/ml/classifier.py` | Classify traffic, determine threat level |
| `src/ai/explanation_engine.py` | Generate AI explanations (optional) |
| `src/alerts/alert_manager.py` | Orchestrate alerts, rate limiting |
| `src/dashboard/app.py` | Flask app, API endpoints, SocketIO |

## Processing Pipeline

```
[Network] → [Capture] → [Process] → [Classify] → [Alert] → [Dashboard]
              │           │           │           │           │
              ▼           ▼           ▼           ▼           ▼
         Raw packets   Features    Threat      Email/      Real-time
                      counters    decision    SMS/Slack   display
```

---

**Next:** [Setup Guide](setup-guide.md)