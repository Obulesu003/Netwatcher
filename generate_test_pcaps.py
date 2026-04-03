#!/usr/bin/env python3
"""Generate synthetic PCAP files for testing IDS with various attack types"""

import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from scapy.all import *
    import random
    import struct
    import time
except ImportError:
    print("Installing scapy...")
    os.system("pip install scapy")
    from scapy.all import *
    import random
    import time

# Network ranges
ATTACKER_IP = "192.168.1.100"
VICTIM_IP = "192.168.1.50"
SERVER_IP = "192.168.1.10"
FAKE_IP = "10.0.0.1"

def generate_dos_attack(output_file, packets=50000):
    """Generate DoS attack PCAP - high volume UDP flood"""
    print(f"Generating DoS attack: {output_file} ({packets} packets)...")
    wrpcap(output_file, [])

    packets_list = []
    start_time = time.time()

    for i in range(packets):
        # UDP flood with large payloads
        payload = bytes([random.randint(0, 255) for _ in range(1024)])

        pkt = Ether()/IP(src=ATTACKER_IP, dst=VICTIM_IP)/UDP(sport=random.randint(1024, 65535), dport=80)/Raw(payload)
        packets_list.append(pkt)

        # Batch write for performance
        if len(packets_list) >= 5000:
            append_packets(output_file, packets_list)
            packets_list = []
            print(f"  {i+1}/{packets} packets...")

    if packets_list:
        append_packets(output_file, packets_list)

    print(f"  Done! Duration: {time.time() - start_time:.1f}s")

def generate_port_scan(output_file, packets=30000):
    """Generate port scan PCAP - single source scanning many ports"""
    print(f"Generating Port Scan: {output_file} ({packets} packets)...")

    packets_list = []
    start_time = time.time()

    # TCP scan across many ports
    ports = list(range(1, 10000))  # Scan 10k ports
    random.shuffle(ports)

    packets_per_port = max(1, packets // len(ports[:1000]))  # Sample 1000 ports

    for port_idx, port in enumerate(ports[:1000]):
        for _ in range(packets_per_port):
            # SYN scan
            pkt = Ether()/IP(src=ATTACKER_IP, dst=VICTIM_IP)/TCP(sport=random.randint(1024, 65535), dport=port, flags='S')
            packets_list.append(pkt)

            # SYN-ACK response (spoofed)
            resp = Ether()/IP(src=VICTIM_IP, dst=ATTACKER_IP)/TCP(sport=port, dport=random.randint(1024, 65535), flags='SA')
            packets_list.append(resp)

            # Batch write
            if len(packets_list) >= 5000:
                append_packets(output_file, packets_list)
                packets_list = []

        if (port_idx + 1) % 100 == 0:
            print(f"  Scanned {port_idx + 1}/1000 ports...")

    if packets_list:
        append_packets(output_file, packets_list)

    print(f"  Done! Duration: {time.time() - start_time:.1f}s")

def generate_brute_force(output_file, packets=25000):
    """Generate brute force attack PCAP - rapid SSH connection attempts"""
    print(f"Generating Brute Force: {output_file} ({packets} packets)...")

    packets_list = []
    start_time = time.time()

    # Rapid SSH connection attempts with login attempts
    ssh_ports = [22, 2222, 22222]
    usernames = ["root", "admin", "user", "test", "guest", "administrator"]
    passwords = ["password", "123456", "admin", "root", "test123", "letmein", "qwerty"]

    for i in range(packets):
        port = random.choice(ssh_ports)
        user = random.choice(usernames)
        pwd = random.choice(passwords)

        # TCP handshake
        syn = Ether()/IP(src=ATTACKER_IP, dst=SERVER_IP)/TCP(sport=random.randint(1024, 65535), dport=port, flags='S', seq=random.randint(0, 2**32))
        packets_list.append(syn)

        syn_ack = Ether()/IP(src=SERVER_IP, dst=ATTACKER_IP)/TCP(sport=port, dport=random.randint(1024, 65535), flags='SA', ack=syn[TCP].seq + 1)
        packets_list.append(syn_ack)

        ack = Ether()/IP(src=ATTACKER_IP, dst=SERVER_IP)/TCP(sport=random.randint(1024, 65535), dport=port, flags='A', seq=syn[TCP].seq + 1)
        packets_list.append(ack)

        # SSH login attempt payload (malformed authentication)
        payload = f"SSH-2.0-PuTTY\r\n{user}\r\n{pwd}\r\n".encode()
        login = Ether()/IP(src=ATTACKER_IP, dst=SERVER_IP)/TCP(sport=random.randint(1024, 65535), dport=port, flags='PA')/Raw(payload)
        packets_list.append(login)

        if len(packets_list) >= 5000:
            append_packets(output_file, packets_list)
            packets_list = []
            print(f"  {i+1}/{packets} attempts...")

    if packets_list:
        append_packets(output_file, packets_list)

    print(f"  Done! Duration: {time.time() - start_time:.1f}s")

def generate_sql_injection(output_file, packets=30000):
    """Generate SQL injection attack PCAP - HTTP requests with SQL payloads"""
    print(f"Generating SQL Injection: {output_file} ({packets} packets)...")

    packets_list = []
    start_time = time.time()

    # SQL injection payloads
    sql_payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "'; DROP TABLE users; --",
        "1' AND '1'='1",
        "' UNION SELECT NULL--",
        "admin'--",
        "' OR 1=1--",
        "1' UNION SELECT username, password FROM users--",
        "' OR 'a'='a",
        "'; EXEC xp_cmdshell('dir');--",
        "' OR 1=1 LIMIT 1--",
        "1' ORDER BY 1--",
        "1' GROUP BY 1--",
        "'; SELECT * FROM users WHERE id=1--",
    ]

    sql_patterns = [
        "UNION SELECT", "DROP TABLE", "OR 1=1", "OR '1'='1",
        "admin'--", "';--", "1=1", "SLEEP("
    ]

    for i in range(packets):
        payload = random.choice(sql_payloads)

        # Add some randomness
        if random.random() > 0.5:
            payload = f"/search?q={payload}"
        else:
            payload = f"/admin/login?user=admin&pass={payload}"

        # HTTP GET request with SQL injection
        http_req = f"GET {payload} HTTP/1.1\r\nHost: {VICTIM_IP}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"

        pkt = Ether()/IP(src=ATTACKER_IP, dst=VICTIM_IP)/TCP(sport=random.randint(1024, 65535), dport=80, flags='PA')/Raw(http_req.encode())
        packets_list.append(pkt)

        # HTTP response (spoofed)
        http_resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Login Failed</html>"
        resp = Ether()/IP(src=VICTIM_IP, dst=ATTACKER_IP)/TCP(sport=80, dport=random.randint(1024, 65535), flags='PA')/Raw(http_resp)
        packets_list.append(resp)

        if len(packets_list) >= 5000:
            append_packets(output_file, packets_list)
            packets_list = []
            print(f"  {i+1}/{packets} requests...")

    if packets_list:
        append_packets(output_file, packets_list)

    print(f"  Done! Duration: {time.time() - start_time:.1f}s")

def generate_xss_attack(output_file, packets=30000):
    """Generate XSS attack PCAP - HTTP requests with XSS payloads"""
    print(f"Generating XSS Attack: {output_file} ({packets} packets)...")

    packets_list = []
    start_time = time.time()

    # XSS payloads
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<iframe src='javascript:alert(\"XSS\")'>",
        "javascript:alert(document.cookie)",
        "<body onload=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<script>document.write('<img src=x>')</script>",
        "';alert('XSS');//",
        "<input onfocus=alert('XSS') autofocus>",
        "<embed src='data:text/html,<script>alert(1)</script>'>",
    ]

    for i in range(packets):
        payload = random.choice(xss_payloads)

        # URL encode some variations
        if random.random() > 0.7:
            payload = payload.replace("<", "%3C").replace(">", "%3E")

        # Add to URL
        url_path = f"/comment?text={payload}"

        http_req = f"POST {url_path} HTTP/1.1\r\nHost: {VICTIM_IP}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(payload)}\r\n\r\n{payload}"

        pkt = Ether()/IP(src=ATTACKER_IP, dst=VICTIM_IP)/TCP(sport=random.randint(1024, 65535), dport=80, flags='PA')/Raw(http_req.encode())
        packets_list.append(pkt)

        # HTTP response
        http_resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Comment posted</html>"
        resp = Ether()/IP(src=VICTIM_IP, dst=ATTACKER_IP)/TCP(sport=80, dport=random.randint(1024, 65535), flags='PA')/Raw(http_resp)
        packets_list.append(resp)

        if len(packets_list) >= 5000:
            append_packets(output_file, packets_list)
            packets_list = []
            print(f"  {i+1}/{packets} requests...")

    if packets_list:
        append_packets(output_file, packets_list)

    print(f"  Done! Duration: {time.time() - start_time:.1f}s")

def generate_mixed_attack(output_file, packets=40000):
    """Generate mixed attack PCAP - all attack types combined"""
    print(f"Generating Mixed Attack: {output_file} ({packets} packets)...")

    packets_list = []
    start_time = time.time()

    attack_types = ['dos', 'scan', 'brute', 'sql', 'xss']

    for i in range(packets):
        attack = random.choice(attack_types)

        if attack == 'dos':
            # UDP flood
            payload = bytes([random.randint(0, 255) for _ in range(512)])
            pkt = Ether()/IP(src=FAKE_IP, dst=VICTIM_IP)/UDP(sport=random.randint(1024, 65535), dport=53)/Raw(payload)
        elif attack == 'scan':
            # Port scan
            pkt = Ether()/IP(src=FAKE_IP, dst=VICTIM_IP)/TCP(sport=random.randint(1024, 65535), dport=random.randint(1, 1000), flags='S')
        elif attack == 'brute':
            # SSH brute force
            http_req = f"GET / HTTP/1.1\r\nHost: {SERVER_IP}\r\n\r\n".encode()
            pkt = Ether()/IP(src=FAKE_IP, dst=SERVER_IP)/TCP(sport=random.randint(1024, 65535), dport=22, flags='PA')/Raw(http_req)
        elif attack == 'sql':
            # SQL injection
            payload = "' OR '1'='1"
            http_req = f"GET /search?q={payload} HTTP/1.1\r\nHost: {VICTIM_IP}\r\n\r\n".encode()
            pkt = Ether()/IP(src=FAKE_IP, dst=VICTIM_IP)/TCP(sport=random.randint(1024, 65535), dport=80, flags='PA')/Raw(http_req)
        else:
            # XSS
            payload = "<script>alert(1)</script>"
            http_req = f"POST /comment HTTP/1.1\r\nHost: {VICTIM_IP}\r\n\r\n{payload}".encode()
            pkt = Ether()/IP(src=FAKE_IP, dst=VICTIM_IP)/TCP(sport=random.randint(1024, 65535), dport=80, flags='PA')/Raw(http_req)

        packets_list.append(pkt)

        if len(packets_list) >= 5000:
            append_packets(output_file, packets_list)
            packets_list = []
            print(f"  {i+1}/{packets} packets...")

    if packets_list:
        append_packets(output_file, packets_list)

    print(f"  Done! Duration: {time.time() - start_time:.1f}s")

def append_packets(filename, packets):
    """Append packets to existing pcap file efficiently"""
    if os.path.exists(filename) and os.path.getsize(filename) > 24:  # 24 bytes is minimum pcap header
        # Read existing and append
        existing = list(rdpcap(filename))
        wrpcap(filename, existing + packets)
    else:
        wrpcap(filename, packets)

def ensure_pcap_dir():
    """Create pcap files directory"""
    pcap_dir = os.path.join(os.path.dirname(__file__), 'data', 'test_pcaps')
    os.makedirs(pcap_dir, exist_ok=True)
    return pcap_dir

def main():
    print("=" * 60)
    print("Netwatcher - PCAP Test File Generator")
    print("=" * 60)

    pcap_dir = ensure_pcap_dir()

    # Generate test PCAP files
    files = [
        (os.path.join(pcap_dir, "dos_attack.pcap"), generate_dos_attack, 50000),
        (os.path.join(pcap_dir, "port_scan.pcap"), generate_port_scan, 30000),
        (os.path.join(pcap_dir, "brute_force.pcap"), generate_brute_force, 25000),
        (os.path.join(pcap_dir, "sql_injection.pcap"), generate_sql_injection, 30000),
        (os.path.join(pcap_dir, "xss_attack.pcap"), generate_xss_attack, 30000),
        (os.path.join(pcap_dir, "mixed_attack.pcap"), generate_mixed_attack, 40000),
    ]

    print(f"\nOutput directory: {pcap_dir}\n")

    for filepath, generator, count in files:
        # Clear existing file
        if os.path.exists(filepath):
            os.remove(filepath)

        generator(filepath, count)
        size_mb = os.path.getsize(filepath) / (1024 * 1024)
        print(f"  File size: {size_mb:.2f} MB\n")

    print("=" * 60)
    print("All test PCAP files generated!")
    print(f"Files are in: {pcap_dir}")
    print("=" * 60)

if __name__ == "__main__":
    main()