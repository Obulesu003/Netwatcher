#!/usr/bin/env python3
"""Fast PCAP generator using raw binary format - no scapy overhead"""

import struct
import os
import random
import time

def create_pcap_file(filepath):
    """Create empty pcap file with proper header"""
    # PCAP global header
    pcap_header = struct.pack(
        '<IHHiIII',
        0xa1b2c3d4,  # magic number
        2,           # major version
        4,           # minor version
        0,           # timezone
        0,           # sigfigs
        65535,       # snaplen
        1            # network (Ethernet)
    )
    with open(filepath, 'wb') as f:
        f.write(pcap_header)

def write_packet(filepath, packet_data):
    """Append packet to pcap file"""
    with open(filepath, 'ab') as f:
        # Packet header: timestamp, timestamp us, captured length, original length
        timestamp = int(time.time())
        timestamp_us = random.randint(0, 999999)
        captured_len = len(packet_data)
        original_len = len(packet_data)

        header = struct.pack('<IIII', timestamp, timestamp_us, captured_len, original_len)
        f.write(header)
        f.write(packet_data)

def create_ethernet_header(src_mac=None, dst_mac=None, ethertype=0x0800):
    """Create Ethernet header"""
    if src_mac is None:
        src_mac = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    if dst_mac is None:
        dst_mac = bytes([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
    return dst_mac + src_mac + struct.pack('!H', ethertype)

def create_ip_header(src_ip, dst_ip, protocol=17, payload_len=0):
    """Create IPv4 header"""
    version_ihl = 0x45
    tos = 0
    total_len = 20 + payload_len
    identification = random.randint(0, 65535)
    flags_fragment = random.randint(0, 16384)
    ttl = 64
    checksum = 0

    header = struct.pack('!BBHHHBBH4s4s',
        version_ihl, tos, total_len, identification,
        flags_fragment, ttl, protocol, checksum,
        ip_to_bytes(src_ip), ip_to_bytes(dst_ip)
    )

    # Calculate checksum
    checksum = calculate_ip_checksum(header)
    return struct.pack('!BBHHHBBH4s4s',
        version_ihl, tos, total_len, identification,
        flags_fragment, ttl, protocol, checksum,
        ip_to_bytes(src_ip), ip_to_bytes(dst_ip)
    )

def ip_to_bytes(ip):
    """Convert IP string to bytes"""
    parts = ip.split('.')
    return bytes([int(p) for p in parts])

def calculate_ip_checksum(header):
    """Calculate IP header checksum"""
    if len(header) % 2:
        header += b'\x00'

    checksum = 0
    for i in range(0, len(header), 2):
        word = (header[i] << 8) + header[i+1]
        checksum += word

    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += (checksum >> 16)
    return ~checksum & 0xffff

def create_udp_header(src_port, dst_port, payload_len=0):
    """Create UDP header"""
    udp_len = 8 + payload_len
    checksum = 0
    return struct.pack('!HHHH', src_port, dst_port, udp_len, checksum)

def create_tcp_header(src_port, dst_port, flags='S', seq=0, ack=0):
    """Create TCP header"""
    data_offset = 5
    reserved = 0
    flags_byte = 0
    if 'S' in flags:
        flags_byte |= 0x02  # SYN
    if 'A' in flags:
        flags_byte |= 0x10  # ACK
    if 'P' in flags:
        flags_byte |= 0x08  # PSH
    if 'F' in flags:
        flags_byte |= 0x01  # FIN

    window = 65535
    checksum = 0
    urgent = 0

    return struct.pack('!HHIIBBHHH',
        src_port, dst_port, seq, ack,
        data_offset << 4, flags_byte, window, checksum, urgent
    )

def generate_packets(filepath, attack_type, count):
    """Generate packets based on attack type"""
    print(f"  Generating {count} packets...")

    attack_ip = "192.168.1.100"
    victim_ip = "192.168.1.50"
    server_ip = "192.168.1.10"

    start = time.time()
    last_print = start

    for i in range(count):
        if attack_type == 'dos':
            # UDP flood - large payload
            payload = bytes([random.randint(0, 255) for _ in range(1024)])
            eth = create_ethernet_header()
            ip = create_ip_header(attack_ip, victim_ip, 17, len(payload))
            udp = create_udp_header(random.randint(1024, 65535), 80, len(payload))
            packet = eth + ip + udp + payload

        elif attack_type == 'scan':
            # TCP SYN scan
            eth = create_ethernet_header()
            ip = create_ip_header(attack_ip, victim_ip, 6)
            tcp = create_tcp_header(random.randint(1024, 65535), random.randint(1, 10000), 'S')
            packet = eth + ip + tcp

        elif attack_type == 'brute':
            # SSH brute force attempt
            eth = create_ethernet_header()
            payload = b"SSH-2.0-PuTTY\r\n"
            ip = create_ip_header(attack_ip, server_ip, 6, len(payload))
            tcp = create_tcp_header(random.randint(1024, 65535), 22, 'PA')
            packet = eth + ip + tcp + payload

        elif attack_type == 'sql':
            # SQL injection HTTP request
            sql_payloads = [
                b"GET /search?q=' OR '1'='1 HTTP/1.1\r\n",
                b"GET /admin?user=admin'-- HTTP/1.1\r\n",
                b"GET /login?q=1 UNION SELECT NULL-- HTTP/1.1\r\n",
                b"POST /api HTTP/1.1\r\nUser=admin&pass=' OR 1=1--",
            ]
            payload = random.choice(sql_payloads)
            eth = create_ethernet_header()
            ip = create_ip_header(attack_ip, victim_ip, 6, len(payload))
            tcp = create_tcp_header(random.randint(1024, 65535), 80, 'PA')
            packet = eth + ip + tcp + payload

        elif attack_type == 'xss':
            # XSS attack HTTP request
            xss_payloads = [
                b"POST /comment HTTP/1.1\r\ntext=<script>alert(1)</script>",
                b"GET /search?q=<img src=x onerror=alert('XSS')> HTTP/1.1",
                b"POST /submit HTTP/1.1\r\ndata=<iframe src='javascript:alert(1)'>",
            ]
            payload = random.choice(xss_payloads)
            eth = create_ethernet_header()
            ip = create_ip_header(attack_ip, victim_ip, 6, len(payload))
            tcp = create_tcp_header(random.randint(1024, 65535), 80, 'PA')
            packet = eth + ip + tcp + payload

        else:  # mixed
            attack_types = ['dos', 'scan', 'brute', 'sql', 'xss']
            packet = generate_single_packet(random.choice(attack_types), attack_ip, victim_ip, server_ip)

        write_packet(filepath, packet)

        # Progress update every 2 seconds
        now = time.time()
        if now - last_print >= 2:
            elapsed = now - start
            rate = (i + 1) / elapsed
            print(f"    {i+1}/{count} packets ({rate:.0f}/sec)")
            last_print = now

    elapsed = time.time() - start
    print(f"  Done! {count} packets in {elapsed:.1f}s ({count/elapsed:.0f}/sec)")

def generate_single_packet(attack_type, attack_ip, victim_ip, server_ip):
    """Generate a single packet for mixed attacks"""
    if attack_type == 'dos':
        payload = bytes([random.randint(0, 255) for _ in range(512)])
        eth = create_ethernet_header()
        ip = create_ip_header(attack_ip, victim_ip, 17, len(payload))
        udp = create_udp_header(random.randint(1024, 65535), 53, len(payload))
        return eth + ip + udp + payload
    elif attack_type == 'scan':
        eth = create_ethernet_header()
        ip = create_ip_header(attack_ip, victim_ip, 6)
        tcp = create_tcp_header(random.randint(1024, 65535), random.randint(1, 1000), 'S')
        return eth + ip + tcp
    elif attack_type == 'brute':
        eth = create_ethernet_header()
        payload = b"SSH-2.0-PuTTY\r\n"
        ip = create_ip_header(attack_ip, server_ip, 6, len(payload))
        tcp = create_tcp_header(random.randint(1024, 65535), 22, 'PA')
        return eth + ip + tcp + payload
    elif attack_type == 'sql':
        payload = b"GET /search?q=' OR '1'='1 HTTP/1.1\r\n"
        eth = create_ethernet_header()
        ip = create_ip_header(attack_ip, victim_ip, 6, len(payload))
        tcp = create_tcp_header(random.randint(1024, 65535), 80, 'PA')
        return eth + ip + tcp + payload
    else:
        payload = b"<script>alert(1)</script>"
        eth = create_ethernet_header()
        ip = create_ip_header(attack_ip, victim_ip, 6, len(payload))
        tcp = create_tcp_header(random.randint(1024, 65535), 80, 'PA')
        return eth + ip + tcp + payload

def main():
    print("=" * 60)
    print("Netwatcher - Fast PCAP Generator")
    print("=" * 60)

    output_dir = os.path.join(os.path.dirname(__file__), 'data', 'test_pcaps')
    os.makedirs(output_dir, exist_ok=True)

    files = [
        ('dos_attack.pcap', 'dos', 50000),
        ('port_scan.pcap', 'scan', 30000),
        ('brute_force.pcap', 'brute', 25000),
        ('sql_injection.pcap', 'sql', 30000),
        ('xss_attack.pcap', 'xss', 30000),
        ('mixed_attack.pcap', 'mixed', 40000),
    ]

    print(f"\nOutput: {output_dir}\n")

    for filename, attack_type, count in files:
        filepath = os.path.join(output_dir, filename)
        if os.path.exists(filepath):
            os.remove(filepath)

        print(f"Creating {filename} ({attack_type}, {count} packets)...")
        create_pcap_file(filepath)

        start = time.time()
        generate_packets(filepath, attack_type, count)

        size_mb = os.path.getsize(filepath) / (1024 * 1024)
        total_time = time.time() - start
        print(f"  File size: {size_mb:.2f} MB, Time: {total_time:.1f}s\n")

    print("=" * 60)
    print("All PCAP files generated!")
    print(f"Location: {output_dir}")
    print("=" * 60)

if __name__ == "__main__":
    main()