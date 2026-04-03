# Frequently Asked Questions

Common questions about Netwatcher.

## Installation & Setup

### Q: Python version requirements?
**A:** Python 3.8 or higher is required. Check with:
```bash
python --version
```

### Q: tshark not found error?
**A:** Install Wireshark which includes tshark:
- Windows/macOS: Download from https://www.wireshark.org/download.html
- Linux: `sudo apt install wireshark`

### Q: Permission denied when capturing?
**A:** You need admin/root privileges for packet capture:
- **Linux:** `sudo usermod -aG wireshark $USER` then log out/in
- **Windows:** Run terminal as Administrator
- **macOS:** Usually not required if properly installed

### Q: No network interfaces found?
**A:** Check available interfaces:
```bash
tshark -D
```
Then set interface in `config.yaml`:
```yaml
capture:
  interface: "eth0"  # Use one from the list
```

## Detection & Classification

### Q: Why are some attacks not detected?
**A:** Possible reasons:
1. Thresholds too high - see [Modifying Detection](modifying-detection.md)
2. Attack pattern not in detection rules - see [Adding New Attacks](adding-new-attacks.md)
3. Not enough packets for detection window
4. BPF filter is excluding relevant traffic

### Q: Too many false positives?
**A:** Increase detection thresholds:
```python
# In traffic_processor.py, increase values:
if xss_count >= 50:    # was 20
if sql_count >= 50:   # was 20
if brute_force >= 25: # was 20
```

Or raise confidence threshold in `config.yaml`:
```yaml
ml:
  confidence_threshold: 0.99
```

### Q: How accurate is the ML model?
**A:** The system uses:
- Rule-based detection (primary) - very accurate for known patterns
- ML model (secondary) - only trusted for BENIGN predictions
- This hybrid approach minimizes false positives

### Q: Can I use my own ML model?
**A:** Yes! Train a model with `scripts/train_real_model.py` or place a pickle file at `models/traffic_classifier.pkl`.

## Dashboard & Interface

### Q: Dashboard not loading?
**A:** Check:
1. Port not in use: `lsof -i :5000` (Linux) or `netstat -ano | findstr :5000` (Windows)
2. Firewall blocking: Allow port 5000
3. Browser cache: Try hard refresh (Ctrl+Shift+R)

### Q: How to export captured data?
**A:**
1. Go to **Packet Monitor** tab
2. Click **Export** button
3. Saves as CSV file

Or use CLI:
```bash
python scripts/export_report.py --input data/captured/session.pcap --output report.csv
```

### Q: Can I run without internet?
**A:** Yes! The IDS works fully offline. AI explanations use templates if OpenAI API is not configured.

## Alerts & Notifications

### Q: Alerts not sending?
**A:** Check:
1. Configuration in `config.yaml` is correct
2. Alert channels are enabled (`enabled: true`)
3. Credentials are valid
4. Rate limit not exceeded

### Q: Too many alert emails?
**A:** Increase rate limiting:
```yaml
alerts:
  rate_limit_seconds: 600  # 10 minutes instead of 5
  max_alerts_per_window: 2  # Max 2 instead of 3
```

### Q: SMS alerts not working?
**A:** Verify Twilio setup:
1. Account SID and Auth Token are correct
2. From number is a Twilio number
3. To numbers are verified (or use paid account)

## Troubleshooting

### Q: Server crashes on startup?
**A:** Try:
```bash
# Clear Python cache
find . -type d -name __pycache__ -exec rm -rf {} +

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

### Q: High CPU usage?
**A:** Normal during capture. If excessive:
1. Reduce buffer size in config
2. Use BPF filter to reduce captured packets
3. Close other network-intensive applications

### Q: Memory usage growing?
**A:** Netwatcher uses a circular buffer (10,000 packets max). Memory should stay constant. If growing:
1. Check for memory leaks in custom code
2. Restart capture periodically

### Q: Import PCAP shows no packets?
**A:** Verify file:
```bash
# Check file exists and has content
ls -la file.pcap

# Verify with tshark
tshark -r file.pcap | head
```

## Development

### Q: How to add a new attack type?
**A:** See [Adding New Attacks](adding-new-attacks.md) guide.

### Q: Can I run tests?
**A:** Tests are not currently implemented. You can test manually:
1. Generate test data: `python scripts/generate_pcaps_fast.py`
2. Import in dashboard
3. Check detection works

### Q: How to contribute?
**A:** See [CONTRIBUTING.md](../CONTRIBUTING.md).

## Performance

### Q: Maximum packets per second?
**A:** Depends on hardware. Typical:
- Modern CPU: 10,000-50,000 pps
- Detection adds minimal overhead (~5%)
- Dashboard updates every 5 seconds

### Q: Storage requirements?
**A:** Depends on capture volume:
- In-memory: ~10 MB for 10,000 packets
- PCAP files: ~1 KB per packet average
- For 1GB/day continuous capture, budget ~50GB/month

---

## Still Need Help?

- **GitHub Issues:** https://github.com/Obulesu003/Netwatcher/issues
- **Documentation:** [Setup Guide](setup-guide.md), [Architecture](architecture.md)