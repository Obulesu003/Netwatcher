# Adding New Attack Types

This guide explains how to add detection for a completely new attack type to Netwatcher.

## Overview

Adding a new attack requires changes to:
1. `src/capture/traffic_processor.py` - Track the attack pattern
2. `src/ml/classifier.py` - Add classification label
3. `src/ai/explanation_engine.py` - Add explanation template
4. `docs/architecture.md` - Update documentation

## Example: Adding DNS Tunneling Detection

Let's add detection for DNS tunneling (exfiltrating data via DNS queries).

### Step 1: Modify TrafficProcessor

**File:** `src/capture/traffic_processor.py`

#### 1a. Add new counter to PacketStats

```python
@dataclass
class PacketStats:
    # ... existing fields ...

    # Attack pattern detection
    web_payload_count: int = 0
    sql_injection_count: int = 0
    xss_count: int = 0
    brute_force_count: int = 0
    port_scan_sources: Dict[str, int] = field(default_factory=dict)
    dos_packets: int = 0
    bot_beacon_score: float = 0

    # ADD NEW: DNS tunneling counter
    dns_tunneling_score: float = 0  # Use float for score, not count

    def to_dict(self) -> Dict[str, Any]:
        # ... existing to_dict logic ...

        # ADD to return dict:
        'dns_tunneling_score': round(self.dns_tunneling_score, 2)
```

#### 1b. Add tracking method

```python
def _track_dns_tunneling(self, packet: CapturedPacket):
    """Track potential DNS tunneling - high frequency DNS queries"""
    if packet.protocol.upper() != 'DNS':  # or check dst_port == 53
        return

    if not hasattr(self, '_dns_query_tracker'):
        self._dns_query_tracker: Dict[str, List[float]] = defaultdict(list)

    now = time.time()
    src_ip = packet.src_ip

    # Clean old entries (older than 60 seconds)
    self._dns_query_tracker[src_ip] = [
        t for t in self._dns_query_tracker[src_ip] if now - t < 60
    ]

    # Record this DNS query
    self._dns_query_tracker[src_ip].append(now)

    # Calculate query rate
    queries_per_minute = len(self._dns_query_tracker[src_ip])

    # Detect tunneling if:
    # - More than 50 DNS queries per minute (legitimate is <10)
    # - AND query length is unusually long
    if queries_per_minute > 50:
        # Increment score (cap at 10)
        self.stats.dns_tunneling_score = min(
            self.stats.dns_tunneling_score + 0.5,
            10.0
        )

    # Also check for long subdomains (data exfiltration)
    if hasattr(packet, 'payload') and packet.payload:
        # Check if subdomain length > 50 chars (suspicious)
        if len(packet.payload) > 50:
            self.stats.dns_tunneling_score = min(
                self.stats.dns_tunneling_score + 1.0,
                10.0
            )
```

#### 1c. Call tracking method

In `_update_stats()`, add:

```python
def _update_stats(self, packet: CapturedPacket):
    # ... existing code ...

    # Existing tracking calls
    self._track_ssh_attempts(packet)
    self._track_port_scan(packet)
    self._track_dos(packet, protocol)
    self._track_bot_beacon(packet)

    # ADD NEW:
    self._track_dns_tunneling(packet)
```

### Step 2: Modify Classifier

**File:** `src/ml/classifier.py`

#### 2a. Add new label

```python
ATTACK_LABELS = [
    'BENIGN', 'Bot', 'Brute Force', 'DoS', 'Port Scan',
    'SQL Injection', 'XSS',
    'DNS Tunneling'  # ADD NEW
]

ATTACK_CATEGORIES = {
    'BENIGN': 'Normal',
    'Bot': 'Botnet',
    'Brute Force': 'Brute Force',
    'DoS': 'DoS',
    'Port Scan': 'Reconnaissance',
    'SQL Injection': 'Web Attack',
    'XSS': 'Web Attack',
    'DNS Tunneling': 'Covert Channel',  # ADD NEW
}

SEVERITY_LEVELS = {
    'Normal': 0,
    'Botnet': 4,
    'Brute Force': 3,
    'DoS': 3,
    'Reconnaissance': 2,
    'Web Attack': 3,
    'Covert Channel': 3,  # ADD NEW
    'Unknown': 0
}
```

#### 2b. Add detection in pattern matching

```python
@staticmethod
def _check_attack_pattern_match(label: str, features: Dict[str, float]) -> bool:
    # ... existing checks ...

    # ADD NEW:
    if label == 'DNS Tunneling':
        dns_score = features.get('dns_tunneling_score', 0)
        return dns_score >= 5

    return False
```

#### 2c. Add to detection method

```python
def _detect_attack_patterns(self, features: Dict[str, float]) -> List[str]:
    detected = []

    # ... existing detection code ...

    # ADD NEW:
    dns_score = features.get('dns_tunneling_score', 0)
    if dns_score >= 5:
        detected.append('DNS Tunneling')

    return detected
```

#### 2d. Add to rule-based classification

```python
def _classify_rule_based(self, features: Dict[str, float]) -> ClassificationResult:
    # ... existing code ...

    # ADD to detected_attacks:
    dns_score = features.get('dns_tunneling_score', 0)
    if dns_score >= 5:
        detected_attacks.append('DNS Tunneling')

    # ADD to priority list:
    def _get_attack_priority(self, attacks: List[str]) -> str:
        priority = ['DoS', 'Brute Force', 'DNS Tunneling',  # ADD HERE
                    'SQL Injection', 'XSS', 'Port Scan', 'Bot']
```

### Step 3: Add AI Explanation

**File:** `src/ai/explanation_engine.py`

```python
def generate_explanation(self, stats: Dict, classification: Dict) -> Dict:
    # ... existing logic ...

    # ADD NEW ATTACK TYPE:
    elif attack_type == 'DNS Tunneling':
        analysis += f"**Covert Channel Activity Detected**\n"
        analysis += f"- Unusually high DNS query rate from {unique_dst}\n"
        analysis += f"- Source: {stats.get('unique_src_ips', 0)} unique IP(s)\n"
        analysis += f"- Pattern: Data exfiltration via DNS\n\n"

        analysis += "**Threat Assessment:**\n"
        analysis += "DNS tunneling detected - attacker may be exfiltrating data\n"
        analysis += "via DNS queries, bypassing traditional network monitoring.\n\n"

        analysis += "**Recommended Actions:**\n"
        analysis += "- Block external DNS queries from affected hosts\n"
        analysis += "- Monitor for long subdomains in DNS queries\n"
        analysis += "- Enable DNS logging and analysis\n"
        analysis += "- Consider using DNS over HTTPS (DoH) monitoring\n"
```

### Step 4: Update Display (Dashboard)

**File:** `src/dashboard/templates/index.html`

Add color for new attack type in the threat level display:

```javascript
// In addToPacketsTable or updateThreatLevel functions:
const colors = {
    'Normal': 'success',
    'DoS': 'danger',
    'Port Scan': 'warning',
    'Brute Force': 'warning',
    'SQL Injection': 'danger',
    'XSS': 'danger',
    'Bot': 'purple',
    'DNS Tunneling': 'info'  // ADD NEW - info is blue
};
```

## Complete Checklist

When adding a new attack type, update:

| File | Changes Needed |
|------|---------------|
| `traffic_processor.py` | Add counter, tracking method, call in `_update_stats()` |
| `classifier.py` | Add label, category, severity, detection logic |
| `explanation_engine.py` | Add explanation template |
| `index.html` | Add display color for threat level |
| `SPEC.md` | Document new attack type |
| `docs/modifying-detection.md` | Add to threshold table |
| `docs/architecture.md` | Update attack detection table |

## Template: Adding Any Attack

```python
# 1. In traffic_processor.py - PacketStats dataclass:
new_attack_count: int = 0

# 2. In traffic_processor.py - _update_stats() or new method:
if detection_condition:
    self.stats.new_attack_count += 1

# 3. In classifier.py - ATTACK_LABELS:
'New Attack'

# 4. In classifier.py - ATTACK_CATEGORIES:
'New Attack': 'Category Name'

# 5. In classifier.py - SEVERITY_LEVELS:
'Category Name': severity_int

# 6. In classifier.py - _detect_attack_patterns():
if new_attack_count >= threshold:
    detected.append('New Attack')

# 7. In explanation_engine.py:
elif attack_type == 'New Attack':
    analysis += f"**New Attack Description**\n..."

# 8. Test with:
python scripts/generate_pcaps_fast.py  # Generate test data
python run.py  # Start and import
```

## Common Attack Patterns

| Attack Type | Detection Method | Port/Pattern |
|-------------|-----------------|--------------|
| **ICMP Tunnel** | Large ICMP packets | Protocol 1 |
| **SMB Exploit** | SMB traffic to vulnerable ports | 445 |
| **FTP Brute Force** | Rapid FTP connection attempts | 21 |
| **Telnet Brute Force** | Rapid telnet attempts | 23 |
| **HTTP Flood** | High HTTP request rate | 80/443 |
| **Slowloris** | Slow HTTP headers | 80/443 |
| **Heartbleed** | SSL heartbeat anomaly | 443 |
| **C2 Beacon** | Regular interval HTTPS | 443 |

---

**Need help?** Check existing patterns in `traffic_processor.py` or open an issue.