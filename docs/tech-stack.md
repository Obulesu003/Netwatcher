# Tech Stack

This document describes all technologies used in Netwatcher.

## Overview

| Layer | Technology | Purpose |
|-------|------------|---------|
| **Capture** | pyshark, tshark | Network packet capture |
| **ML** | scikit-learn, Random Forest | Traffic classification |
| **Backend** | Flask, Flask-SocketIO | Web server |
| **Frontend** | Bootstrap 5, Chart.js, Socket.IO | Dashboard UI |
| **Alerts** | smtplib, twilio, requests | Notification channels |
| **Config** | PyYAML, python-dotenv | Configuration management |
| **Utils** | logging, dataclasses | Common utilities |

## Detailed Tech Stack

### Capture Layer

| Package | Version | Purpose |
|---------|---------|---------|
| **pyshark** | >=0.4 | Python wrapper for tshark |
| **tshark** | (Wireshark) | Packet capture engine |
| **scapy** | >=2.5 | (optional) Packet manipulation |

**Why pyshark/tshark?**
- Battle-tested packet capture (Wireshark is industry standard)
- Cross-platform (Windows, Linux, macOS)
- Active development and community support
- BPF filter support built-in
- PCAP file reading capability

**Alternative considered:** Scapy
- Pros: Pure Python, no external dependencies
- Cons: Slower, less reliable for live capture

### Machine Learning Layer

| Package | Version | Purpose |
|---------|---------|---------|
| **scikit-learn** | >=1.0 | ML framework |
| **pandas** | >=1.5 | Data manipulation |
| **numpy** | >=1.21 | Numerical operations |

**Why scikit-learn?**
- Simple, proven implementations
- No complex dependencies (unlike TensorFlow/PyTorch)
- Random Forest classifier is fast and effective for IDS
- Easy model serialization with pickle

**Classification Model:** Random Forest
- Fast inference (<10ms)
- Handles imbalanced classes well
- Feature importance for debugging
- Works with limited training data

**Training Dataset:** CICIDS2017
- Canadian Institute for Cybersecurity
- 80+ network flow features
- 7 attack categories with labeled data
- Industry standard for IDS research

### Backend Layer

| Package | Version | Purpose |
|---------|---------|---------|
| **Flask** | >=2.0 | Web framework |
| **Flask-SocketIO** | latest | Real-time communication |
| **python-socketio** | latest | Socket.IO protocol |

**Why Flask?**
- Lightweight, minimal overhead
- Easy to extend
- Works well with threading (for capture)
- Jinja2 templates (if needed)

**Why Socket.IO over plain WebSocket?**
- Automatic reconnection
- Fallback to polling (for older browsers)
- Room/channel support for multi-user
- Event-based API

### Frontend Layer

| Package | Version | Purpose |
|---------|---------|---------|
| **Bootstrap 5** | 5.3 | CSS framework |
| **Bootstrap Icons** | 1.11 | Icon library |
| **Chart.js** | 4.4 | Data visualization |
| **Socket.IO Client** | 4.7 | Real-time client |

**Why Bootstrap 5?**
- Modern, responsive design out of the box
- Dark theme ready (Netwatcher uses custom dark theme)
- No build step required
- Extensive component library

**Why Chart.js?**
- Simple API, good defaults
- Responsive, animated charts
- Canvas-based (fast rendering)
- Large community

### Alert Channels

| Service | Package | Purpose |
|---------|---------|---------|
| **Email** | smtplib (built-in) | SMTP email alerts |
| **SMS** | twilio >=7.0 | Twilio SMS alerts |
| **Slack** | requests >=2.28 | Slack webhook alerts |

**Email (smtplib):**
- Built into Python, no extra dependencies
- TLS support for modern SMTP servers
- HTML email formatting

**SMS (Twilio):**
- Industry-leading SMS API
- Reliable delivery
- Competitive pricing

**Slack:**
- Webhook-based (simple integration)
- Rich formatting with blocks
- Channel/team notifications

### Configuration & Utilities

| Package | Version | Purpose |
|---------|---------|---------|
| **PyYAML** | >=6.0 | YAML config parsing |
| **python-dotenv** | >=0.19 | Environment variables |
| **python-dotenv** | - | .env file support |

**Why YAML config?**
- Human-readable, easy to edit
- Hierarchical structure matches app modules
- Type validation possible
- Environment variable substitution

## Development Tools

| Tool | Purpose |
|------|---------|
| **Git** | Version control |
| **GitHub** | Repository hosting |
| **Python venv** | Virtual environment |
| **Black** | Code formatting (optional) |
| **pytest** | Unit testing (optional) |

## Deployment Options

| Method | Pros | Cons |
|--------|------|------|
| **Direct (Python)** | Simple, full control | Manual management |
| **Docker** | Consistent environment | Container overhead |
| **systemd** | Auto-restart, logging | Linux only |
| **nginx + gunicorn** | Production-ready | More complex |

## Browser Compatibility

| Browser | Version | Support |
|---------|---------|---------|
| Chrome | 80+ | Full |
| Firefox | 75+ | Full |
| Edge | 80+ | Full |
| Safari | 13+ | Full |
| Mobile | iOS 13+, Android 8+ | Basic |

## System Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| **CPU** | 1 core | 2+ cores |
| **RAM** | 512 MB | 2 GB |
| **Disk** | 1 GB | 10 GB (for PCAP storage) |
| **OS** | Windows 10, Ubuntu 18.04, macOS 10.15 | Any modern OS |

**Network Capture:**
- Requires admin/root privileges
- Network interface must be accessible
- Some cloud providers block packet capture

## Dependencies Tree

```
Flask
├── Jinja2
├── Werkzeug
└── Click

Flask-SocketIO
├── Flask
├── python-socketio
└── eventlet (optional, for production)

pyshark
├── tshark (external)
└── lxml

scikit-learn
├── numpy
├── scipy
└── joblib

pandas
├── numpy
└── python-dateutil

twilio
└── requests

requirements.txt (all dependencies)
├── flask>=2.0
├── flask-socketio
├── pyshark>=0.4
├── scikit-learn>=1.0
├── pandas>=1.5
├── numpy>=1.21
├── twilio>=7.0
├── requests>=2.28
├── pyyaml>=6.0
├── python-dotenv>=0.19
└── reportlab>=4.0 (for PDF export)
```

## Version Compatibility Matrix

| Python | Flask | scikit-learn | Recommended |
|--------|-------|--------------|-------------|
| 3.8 | 2.x | 1.0 | Yes |
| 3.9 | 2.x | 1.0 | Yes |
| 3.10 | 2.x, 3.x | 1.1 | Yes |
| 3.11 | 3.x | 1.2 | Yes |
| 3.12 | 3.x | 1.3 | Yes |

---

**Next:** [Configuration Guide](configuration.md)