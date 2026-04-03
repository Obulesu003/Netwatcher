# Modifying Detection

This guide explains how to modify Netwatcher's attack detection logic.

## Where Detection Happens

| File | Purpose |
|------|---------|
| `src/capture/traffic_processor.py` | Rule-based attack detection |
| `src/ml/classifier.py` | Classification with thresholds |

## Understanding the Detection Pipeline

```
Packet → TrafficProcessor → Features → Classifier → Alert
              │                              │
              ▼                              ▼
        Detection Logic               Threshold Checks
```

## Modifying Detection Thresholds

### 1. DoS Detection

**File:** `src/capture/traffic_processor.py`
**Method:** `_track_dos()`
**Lines:** ~255-274

```python
def _track_dos(self, packet: CapturedPacket, protocol: str):
    # Current logic:
    # - Track large UDP packets (>1000 bytes)
    # - Flag if 20+ packets in 10 seconds

    if protocol == 'UDP' and packet.length > 1000:
        self._dos_tracker[src_ip].append(now)

        if len(self._dos_tracker[src_ip]) >= 20:  # <-- CHANGE THIS
            self.stats.dos_packets = max(...)
```

**Current threshold:** 20 packets in 10 seconds

**To make more sensitive:**
```python
if len(self._dos_tracker[src_ip]) >= 10:  # Lower = detect smaller floods
```

**To make less sensitive:**
```python
if len(self._dos_tracker[src_ip]) >= 50:  # Raise = only detect large floods
```

### 2. Port Scan Detection

**File:** `src/capture/traffic_processor.py`
**Method:** `_track_port_scan()`
**Lines:** ~225-253

```python
# Current logic:
# - Track unique destination ports per source IP
# - Flag if 15+ ports in 30 seconds

if unique_ports >= 15:  # <-- CHANGE THIS
    # Mark as port scan
```

**To make more sensitive:**
```python
if unique_ports >= 10:  # Lower threshold
```

**To make less sensitive:**
```python
if unique_ports >= 30:  # Higher threshold
```

### 3. Brute Force Detection

**File:** `src/capture/traffic_processor.py`
**Method:** `_track_ssh_attempts()`
**Lines:** ~202-223

```python
# Current logic:
# - Track SSH (port 22) connection attempts
# - Flag if 10+ attempts in 60 seconds

if len(self._ssh_attempts[packet.src_ip]) >= 10:  # <-- CHANGE THIS
    self.stats.brute_force_count = ...
```

**Change threshold:**
```python
# More sensitive:
if len(self._ssh_attempts[packet.src_ip]) >= 5:

# Less sensitive:
if len(self._ssh_attempts[packet.src_ip]) >= 25:
```

### 4. SQL Injection Detection

**File:** `src/capture/traffic_processor.py`
**Method:** `_update_stats()`
**Lines:** ~156-169

```python
# Current logic:
# - Check for dangerous SQL patterns
# - Require dangerous keyword OR 2+ indicators

sql_dangerous = [
    "union select", "drop table", "exec(", "xp_", "0x",
    "load_file", "into outfile", "benchmark(", "sleep("
]
sql_indicators = [" or 1=1", "' or '1'='1", "--", "/*", "*/"]

if has_dangerous or has_indicators >= 2:  # <-- CHANGE THIS
    self.stats.sql_injection_count += 1
```

**To add more patterns:**
```python
sql_dangerous = [
    "union select",
    "drop table",
    "exec(",
    "xp_",
    "0x",
    "char(",
    "benchmark(",
    "sleep(",
    "load_file",
    "into outfile",
    "into dumpfile",
    # ADD YOUR PATTERNS HERE:
    "waitfor delay",  # SQL Server time-based
    "pg_sleep",       # PostgreSQL
]
```

### 5. XSS Detection

**File:** `src/capture/traffic_processor.py`
**Method:** `_update_stats()`
**Lines:** ~171-180

```python
xss_dangerous = [
    "<script", "</script", "javascript:",
    "onerror=", "onload=", "onmouseover=",
    "document.cookie", "document.write",
    "window.location", "eval(", "<svg", "<body",
    "innerhtml", "outerhtml", "vbscript:"
]

if any(p in payload_lower for p in xss_dangerous):  # Any match triggers
    self.stats.xss_count += 1
```

**To add patterns:**
```python
xss_dangerous = [
    "<script", "</script", "javascript:",
    "onerror=", "onload=", "onmouseover=",
    "document.cookie", "document.write",
    "window.location", "eval(", "<svg", "<body",
    "innerhtml", "outerhtml", "vbscript:",
    # ADD YOUR PATTERNS HERE:
    "<embed",        # Flash/plugin injection
    "onfocus",       # Focus event
    "onblur",        # Blur event
]
```

### 6. Bot Detection

**File:** `src/capture/traffic_processor.py`
**Method:** `_track_bot_beacon()`
**Lines:** ~276-303

```python
# Current logic:
# - Track packets to suspicious ports (4444, 5555)
# - Flag if 3+ regular-interval packets detected

suspicious_ports = [4444, 5555]  # <-- CHANGE THIS

if packet.dst_port in suspicious_ports and packet.length < 200:
    # Track beacon pattern

if bot_score >= 3:  # <-- CHANGE THIS
    detected.append('Bot')
```

**To add more C2 ports:**
```python
suspicious_ports = [4444, 5555, 6666, 7777, 8888, 31337]
```

## Modifying Classification Thresholds

**File:** `src/ml/classifier.py`
**Method:** `_detect_attack_patterns()`
**Lines:** ~243-278

```python
# These thresholds determine when to classify as an attack

if xss_count >= 20 or (xss_count >= 10 and web_payload >= 10):
    detected.append('XSS')

if sql_count >= 20:
    detected.append('SQL Injection')

if brute_force >= 20:  # <-- MATCH with traffic_processor.py
    detected.append('Brute Force')

if dos_packets >= 30 and packets_per_second >= 200:
    detected.append('DoS')

if port_scan_score >= 0.5 and unique_dst_ports >= 20:
    detected.append('Port Scan')

if bot_score >= 3:
    detected.append('Bot')
```

**IMPORTANT:** Keep these thresholds **in sync** with `traffic_processor.py`.

## Changing Confidence Thresholds

**File:** `src/utils/config.py` or `config.yaml`

```yaml
ml:
  confidence_threshold: 0.95
```

**Effect:**
| Value | Behavior |
|-------|----------|
| 0.99 | Only highest confidence attacks trigger alerts |
| 0.95 | Balanced (recommended) |
| 0.80 | More alerts, more false positives |
| 0.70 | Very sensitive, many false positives |

## Testing Your Changes

### 1. Generate Test Traffic

```bash
# Generate test PCAPs
python scripts/generate_pcaps_fast.py
```

### 2. Run and Monitor

```bash
# Start dashboard
python run.py

# Open browser, go to Packet Monitor
# Import test PCAP and watch detection
```

### 3. Check Logs

```bash
# Monitor console output
python run.py 2>&1 | grep -i "detected\|alert\|attack"
```

## Quick Reference: Threshold Changes

| Attack | Current | More Sensitive | Less Sensitive |
|--------|---------|----------------|----------------|
| DoS | 20 packets | 10 | 50 |
| Port Scan | 15 ports | 8 | 30 |
| Brute Force | 10 attempts | 5 | 25 |
| SQL Injection | 20 hits | 10 | 50 |
| XSS | 20 hits | 10 | 50 |
| Bot | 3 beacons | 2 | 5 |

---

**Next:** [Adding New Attacks](adding-new-attacks.md)