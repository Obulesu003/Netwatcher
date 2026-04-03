# Setup Guide

This guide covers everything you need to get Netwatcher running.

## Prerequisites

### Required
- **Python 3.8+** - [Download](https://www.python.org/downloads/)
- **Wireshark/tshark** - [Download](https://www.wireshark.org/download.html)

### Optional (for full features)
- **OpenAI API Key** - For AI explanations
- **Twilio Account** - For SMS alerts
- **Slack Workspace** - For Slack alerts

## Step-by-Step Installation

### 1. Clone or Download the Repository

```bash
# If using git
git clone https://github.com/Obulesu003/Netwatcher.git
cd Netwatcher

# If downloading ZIP, extract and navigate to folder
cd Netwatcher
```

### 2. Create Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate it
# Windows:
venv\Scripts\activate

# Linux/Mac:
source venv/bin/activate
```

You should see `(venv)` prefix in your terminal.

### 3. Install Dependencies

```bash
# Install all dependencies
pip install -r requirements.txt

# If you encounter issues, try minimal version:
pip install -r requirements-minimal.txt
```

### 4. Install Wireshark/tshark

**Windows:**
1. Download Wireshark from https://www.wireshark.org/download.html
2. Run installer, select "Install tshark" during setup
3. Restart terminal after installation

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install wireshark
# During install, select "Yes" to allow non-root capture
# Or run: sudo dpkg-reconfigure wireshark-common
```

**macOS:**
```bash
brew install wireshark
```

**Verify installation:**
```bash
tshark --version
```

### 5. Configure (Optional)

Copy and edit the configuration file:

```bash
# Copy example config
cp config.example.yaml config.yaml

# Edit with your settings
nano config.yaml  # or use any text editor
```

**Key settings in `config.yaml`:**

```yaml
# Dashboard
dashboard:
  host: "0.0.0.0"  # Listen on all interfaces
  port: 5000        # Web port

# Detection sensitivity
ml:
  confidence_threshold: 0.95  # Higher = fewer false positives

# Email alerts (optional)
alerts:
  email:
    enabled: false  # Set to true to enable
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    username: "your-email@gmail.com"
    password: "your-app-password"
    recipients: ["admin@example.com"]

# AI explanations (optional)
ai:
  provider: "openai"  # or "local" for template-based
  api_key: "${OPENAI_API_KEY}"  # Set environment variable
```

### 6. Set Environment Variables (Optional)

**Windows (Command Prompt):**
```cmd
set OPENAI_API_KEY=sk-your-api-key-here
```

**Windows (PowerShell):**
```powershell
$env:OPENAI_API_KEY="sk-your-api-key-here"
```

**Linux/Mac:**
```bash
export OPENAI_API_KEY=sk-your-api-key-here
```

## Running Netwatcher

### Option 1: Full Dashboard (Recommended)

```bash
python run.py
```

Then open http://localhost:5000 in your browser.

### Option 2: Dashboard Only

```bash
python run_dashboard.py
```

### Option 3: CLI Mode

```bash
# Capture from default interface for 60 seconds
python -m src.capture.packet_capture --duration 60

# Capture with filter
python -m src.capture.packet_capture --interface eth0 --filter "tcp port 80"

# Analyze PCAP file
python -m src.capture.packet_capture --file captured_traffic.pcap --analyze
```

## Testing with Sample Data

### Generate Test PCAP Files

```bash
# Generate attack simulation PCAPs
python scripts/generate_pcaps_fast.py
```

This creates test files in `data/test_pcaps/`:
- `dos_attack.pcap` - 50,000 packets
- `port_scan.pcap` - 30,000 packets
- `brute_force.pcap` - 25,000 packets
- `sql_injection.pcap` - 30,000 packets
- `xss_attack.pcap` - 30,000 packets
- `mixed_attack.pcap` - 40,000 packets

### Import PCAP in Dashboard

1. Open http://localhost:5000
2. Go to **Packet Monitor** tab
3. Click **Import** button
4. Select any `.pcap` file
5. Watch attacks get detected!

## Docker Installation (Alternative)

```dockerfile
# Dockerfile
FROM python:3.11-slim

# Install tshark
RUN apt-get update && apt-get install -y wireshark-common && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
CMD ["python", "run.py"]
```

```bash
# Build and run
docker build -t netwatcher .
docker run -p 5000:5000 --cap-add=NET_ADMIN netwatcher
```

## Troubleshooting

### "tshark not found" error

**Problem:** tshark is not installed or not in PATH.

**Solution:**
1. Download Wireshark from https://www.wireshark.org/download.html
2. Install with tshark component
3. Restart terminal
4. Verify: `tshark --version`

### "Permission denied" error

**Problem:** Need root/admin to capture packets.

**Linux solution:**
```bash
# Add user to wireshark group
sudo usermod -aG wireshark $USER
# Log out and back in

# Or run with sudo (not recommended)
sudo python run.py
```

**Windows solution:**
- Run terminal as Administrator

### "No network interfaces found"

**Problem:** No network interfaces available to capture from.

**Solution:**
1. Check available interfaces: `tshark -D`
2. Specify interface in config: `interface: "eth0"` or `interface: "Wi-Fi"`
3. On Windows, make sure WinPcap/Npcap is installed

### Port 5000 already in use

**Problem:** Another process is using port 5000.

**Solution:**
```bash
# Change port in config.yaml
dashboard:
  port: 5001  # Use different port
```

### Import PCAP shows no packets

**Problem:** PCAP file format issue or empty file.

**Solution:**
1. Verify file exists and has content: `ls -la file.pcap`
2. Check with Wireshark: `tshark -r file.pcap | head`
3. Try regenerating: `python scripts/generate_pcaps_fast.py`

## Next Steps

- **[How It Works](how-it-works.md)** - Understand the detection logic
- **[Architecture](architecture.md)** - System design details
- **[Modifying Detection](modifying-detection.md)** - Customize attack detection
- **[Adding New Attacks](adding-new-attacks.md)** - Extend detection capabilities

---

**Need Help?** Open an issue on GitHub or check the [FAQ](faq.md)