# What is Netwatcher?

**Netwatcher** is an open-source **Network Intrusion Detection System (IDS)** that monitors network traffic in real-time, detects cyber attacks using machine learning, and provides AI-powered threat analysis with actionable recommendations.

## Core Purpose

Netwatcher solves the problem of **manual threat hunting** by automating the detection of:
- DoS/DDoS attacks
- Port scanning
- Brute force attacks
- SQL injection
- XSS (Cross-Site Scripting)
- Botnet communications

## Who Should Use Netwatcher?

| User | Use Case |
|------|----------|
| **Network Administrators** | Monitor corporate network traffic |
| **Security Analysts** | Threat hunting and incident response |
| **DevOps Engineers** | Monitor production environment |
| **Students/Learners** | Learn network security concepts |
| **Small Businesses** | Affordable IDS without expensive tools |

## Key Benefits

1. **Real-time Detection** - Instant attack identification
2. **Low False Positives** - Tuned thresholds minimize alert fatigue
3. **AI Explanations** - Plain-English threat context (optional OpenAI)
4. **Multi-Channel Alerts** - Email, SMS, Slack notifications
5. **Interactive Dashboard** - Visual monitoring with charts and tables
6. **Open Source** - Free to use, modify, and contribute

## What Makes Netwatcher Different?

| Feature | Traditional IDS | Netwatcher |
|---------|-----------------|------------|
| Detection Method | Signature-based only | ML + Rule-based hybrid |
| Configuration | Complex config files | Simple YAML + UI |
| Alert Noise | High false positive rate | Tuned thresholds |
| Threat Context | Raw alerts | AI explanations |
| Setup Time | Hours to days | Minutes |

## Quick Demo

```bash
# Start capture and see real-time detection
python run.py
# Open http://localhost:5000
# Import test PCAP files from data/test_pcaps/
# Watch attacks get detected automatically
```

## License

Netwatcher is released under the **MIT License** - free for personal and commercial use.

---

**Next:** [How It Works](how-it-works.md)