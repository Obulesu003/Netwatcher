"""Generate test PCAP with multiple attack scenarios"""
from scapy.all import IP, TCP, UDP, ICMP, wrpcap, RandIP, RandShort
import time

packets = []
base_time = time.time()

# === XSS Attack (Web Traffic on port 80) ===
print("Generating XSS attack...")
for i in range(20):
    pkt = IP(src="203.0.113.50", dst="192.168.1.100")/TCP(sport=RandShort(), dport=80)/("GET /search?q=<script>alert('XSS')</script> HTTP/1.1\r\n")
    pkt.time = base_time + i * 0.05
    packets.append(pkt)

# === SQL Injection (Traffic on port 3306 - MySQL) ===
print("Generating SQL Injection attack...")
for i in range(15):
    pkt = IP(src="198.51.100.25", dst="192.168.1.100")/TCP(sport=RandShort(), dport=3306)/("' OR '1'='1' --\r\n")
    pkt.time = base_time + 2 + i * 0.1
    packets.append(pkt)

# === Brute Force SSH (Port 22) ===
print("Generating Brute Force attack...")
for i in range(30):
    pkt = IP(src="203.0.113.100", dst="192.168.1.100")/TCP(sport=RandShort(), dport=22, flags="S")
    pkt.time = base_time + 4 + i * 0.03
    packets.append(pkt)

# === Port Scan (Multiple ports) ===
print("Generating Port Scan...")
ports = [21, 22, 23, 25, 80, 110, 143, 443, 445, 3389, 8080]
for port in ports:
    for i in range(5):
        pkt = IP(src="192.0.2.10", dst="192.168.1.100")/TCP(sport=RandShort(), dport=port, flags="S")
        pkt.time = base_time + 6 + port * 0.1 + i * 0.02
        packets.append(pkt)

# === DoS Attack (High volume UDP) ===
print("Generating DoS attack...")
for i in range(50):
    pkt = IP(src="203.0.113.200", dst="192.168.1.100")/UDP(sport=RandShort(), dport=80)/("X"*1400)
    pkt.time = base_time + 8 + i * 0.01
    packets.append(pkt)

# === Bot C2 Traffic (Small periodic packets) ===
print("Generating Bot C2 traffic...")
for i in range(25):
    pkt = IP(src="198.51.100.99", dst="192.168.1.50")/TCP(sport=4444, dport=8080)/("BEACON" + str(i))
    pkt.time = base_time + 10 + i * 2
    packets.append(pkt)

# === Normal Traffic (Background) ===
print("Generating normal traffic...")
for i in range(40):
    if i % 3 == 0:
        pkt = IP(src="192.168.1.10", dst="8.8.8.8")/UDP(sport=54321, dport=53)/("google.com")
    else:
        pkt = IP(src="192.168.1.10", dst="151.101.1.140")/TCP(sport=60000+i, dport=443, flags="A")/("HTTP/1.1 200 OK\r\n")
    pkt.time = base_time + 12 + i * 0.5
    packets.append(pkt)

# Save PCAP
output_file = "C:/Users/bobul/Downloads/Netwatcher/test_data/multi_attack_scenarios.pcap"
wrpcap(output_file, packets)
print(f"\nCreated: {output_file}")
print(f"Total packets: {len(packets)}")
print("\nAttack scenarios included:")
print("  1. XSS - 20 packets targeting port 80")
print("  2. SQL Injection - 15 packets targeting port 3306")
print("  3. Brute Force SSH - 30 packets targeting port 22")
print("  4. Port Scan - 55 packets scanning multiple ports")
print("  5. DoS Attack - 50 high-volume UDP packets")
print("  6. Bot C2 Traffic - 25 periodic beacon packets")
print("  7. Normal Traffic - 40 packets for baseline")
