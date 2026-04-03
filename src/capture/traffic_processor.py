"""Traffic processing and feature extraction (simplified without numpy)"""

import time
import re
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from collections import defaultdict
from threading import Lock

from .packet_capture import CapturedPacket


@dataclass
class PacketStats:
    total_packets: int = 0
    total_bytes: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    other_packets: int = 0
    tcp_bytes: int = 0
    udp_bytes: int = 0
    duration: float = 0
    packets_per_second: float = 0
    bytes_per_second: float = 0
    avg_packet_size: float = 0
    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    unique_src_ports: int = 0
    unique_dst_ports: int = 0
    start_time: float = field(default_factory=time.time)
    last_update: float = field(default_factory=time.time)

    protocol_distribution: Dict[str, int] = field(default_factory=dict)
    top_src_ips: Dict[str, int] = field(default_factory=dict)
    top_dst_ips: Dict[str, int] = field(default_factory=dict)
    top_dst_ports: Dict[str, int] = field(default_factory=dict)

    # Attack pattern detection
    web_payload_count: int = 0  # XSS/SQLi payloads in web traffic
    sql_injection_count: int = 0
    xss_count: int = 0
    brute_force_count: int = 0  # Rapid connections to same port
    port_scan_sources: Dict[str, int] = field(default_factory=dict)  # src -> ports scanned
    dos_packets: int = 0  # High-volume UDP packets
    bot_beacon_score: float = 0  # Regular interval packets to same destination
    
    def to_dict(self) -> Dict[str, Any]:
        # Calculate protocol ratios
        total = self.total_packets or 1
        tcp_ratio = self.tcp_packets / total
        udp_ratio = self.udp_packets / total
        icmp_ratio = self.icmp_packets / total

        return {
            # Primary names
            'total_packets': self.total_packets,
            'packet_count': self.total_packets,
            'total_bytes': self.total_bytes,
            'byte_count': self.total_bytes,
            # Protocol info
            'tcp_packets': self.tcp_packets,
            'udp_packets': self.udp_packets,
            'icmp_packets': self.icmp_packets,
            'other_packets': self.other_packets,
            'tcp_ratio': tcp_ratio,
            'udp_ratio': udp_ratio,
            'icmp_ratio': icmp_ratio,
            # Timing
            'duration': round(self.duration, 2),
            'packets_per_second': round(self.packets_per_second, 2),
            'bytes_per_second': round(self.bytes_per_second, 2),
            'avg_packet_size': round(self.avg_packet_size, 2),
            # Network info
            'unique_src_ips': self.unique_src_ips,
            'unique_dst_ips': self.unique_dst_ips,
            'unique_src_ports': self.unique_src_ports,
            'unique_dst_ports': self.unique_dst_ports,
            'protocol_distribution': dict(sorted(self.protocol_distribution.items(), key=lambda x: x[1], reverse=True)[:5]),
            'top_src_ips': dict(sorted(self.top_src_ips.items(), key=lambda x: x[1], reverse=True)[:5]),
            'top_dst_ips': dict(sorted(self.top_dst_ips.items(), key=lambda x: x[1], reverse=True)[:5]),
            'top_dst_ports': dict(sorted(self.top_dst_ports.items(), key=lambda x: x[1], reverse=True)[:5]),
            # Attack detection
            'sql_injection_count': self.sql_injection_count,
            'xss_count': self.xss_count,
            'web_payload_count': self.web_payload_count,
            'brute_force_count': self.brute_force_count,
            'port_scan_sources': {k: list(v) for k, v in self.port_scan_sources.items()},
            'dos_packets': self.dos_packets,
            'bot_beacon_score': round(self.bot_beacon_score, 2)
        }


class TrafficProcessor:
    def __init__(self, window_size: int = 60):
        self.window_size = window_size
        self.packets: list = []
        self.max_packets = 10000
        self.stats = PacketStats()
        self._lock = Lock()
        self._callbacks: List[Callable] = []
    
    def add_packet(self, packet: CapturedPacket):
        with self._lock:
            self.packets.append(packet)
            if len(self.packets) > self.max_packets:
                self.packets = self.packets[-self.max_packets:]
            self._update_stats(packet)
            
            for callback in self._callbacks:
                try:
                    callback(packet, self.stats)
                except:
                    pass
    
    def _update_stats(self, packet: CapturedPacket):
        self.stats.total_packets += 1
        self.stats.total_bytes += packet.length
        self.stats.last_update = time.time()
        
        protocol = packet.protocol.upper()
        self.stats.protocol_distribution[protocol] = self.stats.protocol_distribution.get(protocol, 0) + 1
        
        if protocol == 'TCP':
            self.stats.tcp_packets += 1
            self.stats.tcp_bytes += packet.length
        elif protocol == 'UDP':
            self.stats.udp_packets += 1
            self.stats.udp_bytes += packet.length
        elif protocol == 'ICMP':
            self.stats.icmp_packets += 1
        else:
            self.stats.other_packets += 1
        
        self.stats.top_src_ips[packet.src_ip] = self.stats.top_src_ips.get(packet.src_ip, 0) + 1
        self.stats.top_dst_ips[packet.dst_ip] = self.stats.top_dst_ips.get(packet.dst_ip, 0) + 1
        
        if packet.dst_port > 0:
            self.stats.top_dst_ports[packet.dst_port] = self.stats.top_dst_ports.get(packet.dst_port, 0) + 1
        
        self.stats.duration = time.time() - self.stats.start_time
        self.stats.packets_per_second = self.stats.total_packets / max(self.stats.duration, 0.001)
        self.stats.bytes_per_second = self.stats.total_bytes / max(self.stats.duration, 0.001)
        self.stats.avg_packet_size = self.stats.total_bytes / max(self.stats.total_packets, 1)
        
        self.stats.unique_src_ips = len(self.stats.top_src_ips)
        self.stats.unique_dst_ips = len(self.stats.top_dst_ips)
        self.stats.unique_src_ports = len(set(p.src_port for p in self.packets if p.src_port > 0))
        self.stats.unique_dst_ports = len(self.stats.top_dst_ports)

        # Attack pattern detection based on payload analysis
        payload = getattr(packet, 'payload', '') or ''
        payload_lower = payload.lower()

        # SQL Injection detection - require dangerous constructs, not single chars
        sql_dangerous = [
            "union select", "union all select", "drop table", "drop database",
            "exec(", "execute(", "xp_", "sp_", "0x", "char(",
            "benchmark(", "sleep(", "waitfor delay",
            "load_file", "into outfile", "into dumpfile"
        ]
        sql_injection_indicators = [" or 1=1", "' or '1'='1", "--", "/*", "*/",
                                    "1=1", "' or \"", "or null", "having "]
        has_dangerous = any(p in payload_lower for p in sql_dangerous)
        has_indicators = sum(1 for p in sql_injection_indicators if p in payload_lower)
        # Require dangerous keyword OR multiple indicators (avoid "Bob's data" false positives)
        if has_dangerous or has_indicators >= 2:
            self.stats.sql_injection_count += 1

        # XSS detection - require actual dangerous patterns, not benign HTML
        xss_dangerous = [
            "<script", "</script", "javascript:", "onerror=", "onload=",
            "onmouseover=", "onfocus=", "onblur=", "document.cookie",
            "document.write", "window.location", "eval(", "<svg", "<body",
            "innerhtml", "outerhtml", "vbscript:"
        ]
        # Only flag if dangerous XSS vectors found, not benign <img> or <iframe>
        if any(p in payload_lower for p in xss_dangerous):
            self.stats.xss_count += 1

        # Web payload detection - only count truly suspicious payloads
        # Require combination of indicators to avoid flagging normal browsing
        web_suspicious = ["<script", "onerror=", "onload=", "javascript:",
                          "union select", "drop table", "eval("]
        if any(p in payload_lower for p in web_suspicious) and packet.dst_port in [80, 443, 8080, 8443]:
            self.stats.web_payload_count += 1

        # Brute force detection - track connection attempts over time
        # Only flag SSH if multiple connections from same source in short window
        self._track_ssh_attempts(packet)

        # Port scan detection (same source hitting many ports rapidly)
        self._track_port_scan(packet)

        # DoS detection (high-volume UDP from single source)
        self._track_dos(packet, protocol)

        # Bot C2 beacon detection (periodic regular-interval traffic to C2 ports)
        self._track_bot_beacon(packet)

    def _track_ssh_attempts(self, packet: CapturedPacket):
        """Track SSH brute force - only flag if multiple failed connections detected"""
        if packet.dst_port != 22:
            return

        # Track connection timestamps per source IP
        if not hasattr(self, '_ssh_attempts'):
            self._ssh_attempts: Dict[str, List[float]] = defaultdict(list)

        now = time.time()
        # Keep only attempts in last 60 seconds
        self._ssh_attempts[packet.src_ip] = [
            t for t in self._ssh_attempts[packet.src_ip] if now - t < 60
        ]
        self._ssh_attempts[packet.src_ip].append(now)

        # Only flag as brute force if 10+ attempts in 60 seconds (not every packet)
        if len(self._ssh_attempts[packet.src_ip]) >= 10:
            self.stats.brute_force_count = max(
                self.stats.brute_force_count,
                len(self._ssh_attempts[packet.src_ip])
            )

    def _track_port_scan(self, packet: CapturedPacket):
        """Track port scan - only flag if single source hits many ports rapidly"""
        if not hasattr(self, '_port_scan_hits'):
            self._port_scan_hits: Dict[str, Dict[int, List[float]]] = defaultdict(lambda: defaultdict(list))

        now = time.time()
        src_ip = packet.src_ip

        # Clean old entries (older than 30 seconds)
        if src_ip in self._port_scan_hits:
            for port in list(self._port_scan_hits[src_ip].keys()):
                self._port_scan_hits[src_ip][port] = [
                    t for t in self._port_scan_hits[src_ip][port] if now - t < 30
                ]
                if not self._port_scan_hits[src_ip][port]:
                    del self._port_scan_hits[src_ip][port]

        # Only track TCP packets (port scans are TCP-based)
        if packet.protocol.upper() == 'TCP':
            self._port_scan_hits[src_ip][packet.dst_port].append(now)

            # Count unique ports hit by this source in last 30 seconds
            unique_ports = len(self._port_scan_hits[src_ip])
            # Port scan: single source hitting 15+ distinct ports in 30s (not normal browsing)
            if unique_ports >= 15:
                # Store as dict of ports (already aggregated in port_scan_sources)
                if src_ip not in self.stats.port_scan_sources:
                    self.stats.port_scan_sources[src_ip] = set()
                self.stats.port_scan_sources[src_ip].update(self._port_scan_hits[src_ip].keys())

    def _track_dos(self, packet: CapturedPacket, protocol: str):
        """Track DoS - only flag sustained high-volume UDP from single source"""
        if not hasattr(self, '_dos_tracker'):
            self._dos_tracker: Dict[str, List[float]] = defaultdict(list)

        now = time.time()
        src_ip = packet.src_ip

        # Clean old entries (older than 10 seconds for DoS detection)
        self._dos_tracker[src_ip] = [
            t for t in self._dos_tracker[src_ip] if now - t < 10
        ]

        # UDP packets > 1000 bytes from same source within 10s window
        if protocol == 'UDP' and packet.length > 1000:
            self._dos_tracker[src_ip].append(now)

            # Only flag as DoS if 20+ large UDP packets in 10 seconds
            if len(self._dos_tracker[src_ip]) >= 20:
                self.stats.dos_packets = max(self.stats.dos_packets, len(self._dos_tracker[src_ip]))

    def _track_bot_beacon(self, packet: CapturedPacket):
        """Track bot C2 beacons - require periodic timing, not just small packets"""
        if not hasattr(self, '_beacon_tracker'):
            self._beacon_tracker: Dict[str, List[float]] = defaultdict(list)

        now = time.time()
        # Only track to known C2 ports (4444, 5555 are suspicious, 443/8080 need timing)
        suspicious_ports = [4444, 5555]

        # For known malicious ports, check for regular intervals
        if packet.dst_port in suspicious_ports and packet.length < 200:
            self._beacon_tracker[packet.dst_ip].append(now)

            # Look for periodic traffic (packets ~60s apart)
            timestamps = self._beacon_tracker[packet.dst_ip]
            if len(timestamps) >= 3:
                intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                # Check if intervals are regular (std dev < 20% of mean)
                if intervals:
                    mean_interval = sum(intervals) / len(intervals)
                    if mean_interval > 0:
                        std_dev = (sum((x - mean_interval)**2 for x in intervals) / len(intervals)) ** 0.5
                        # Only flag if intervals are regular (beacon-like) and rate is suspicious
                        if std_dev / mean_interval < 0.2 and 30 < mean_interval < 120:
                            self.stats.bot_beacon_score = min(
                                self.stats.bot_beacon_score + 1.0,
                                10.0  # Cap at 10 to prevent runaway scores
                            )

    def get_current_features(self) -> Dict[str, Any]:
        with self._lock:
            features = self.stats.to_dict()
            # Ensure both naming conventions exist
            features['packet_count'] = features.get('packet_count', features.get('total_packets', 0))
            features['byte_count'] = features.get('byte_count', features.get('total_bytes', 0))
            features['total_packets'] = features.get('total_packets', features.get('packet_count', 0))
            features['total_bytes'] = features.get('total_bytes', features.get('byte_count', 0))
            # Recalculate port scan score with better formula
            unique_dst_ports = features['unique_dst_ports']
            if unique_dst_ports >= 15:
                features['port_scan_score'] = min(unique_dst_ports / 50, 1.0)
            else:
                features['port_scan_score'] = 0.0
            return features
    
    def get_stats(self) -> PacketStats:
        with self._lock:
            return PacketStats(
                total_packets=self.stats.total_packets,
                total_bytes=self.stats.total_bytes,
                tcp_packets=self.stats.tcp_packets,
                udp_packets=self.stats.udp_packets,
                icmp_packets=self.stats.icmp_packets,
                other_packets=self.stats.other_packets,
                tcp_bytes=self.stats.tcp_bytes,
                udp_bytes=self.stats.udp_bytes,
                duration=self.stats.duration,
                packets_per_second=self.stats.packets_per_second,
                bytes_per_second=self.stats.bytes_per_second,
                avg_packet_size=self.stats.avg_packet_size,
                unique_src_ips=self.stats.unique_src_ips,
                unique_dst_ips=self.stats.unique_dst_ips,
                protocol_distribution=dict(self.stats.protocol_distribution),
                top_src_ips=dict(sorted(self.stats.top_src_ips.items(), key=lambda x: x[1], reverse=True)[:5]),
                top_dst_ips=dict(sorted(self.stats.top_dst_ips.items(), key=lambda x: x[1], reverse=True)[:5]),
                top_dst_ports=dict(sorted(self.stats.top_dst_ports.items(), key=lambda x: x[1], reverse=True)[:5]),
                # Attack pattern fields
                web_payload_count=self.stats.web_payload_count,
                sql_injection_count=self.stats.sql_injection_count,
                xss_count=self.stats.xss_count,
                brute_force_count=self.stats.brute_force_count,
                port_scan_sources={k: list(v) for k, v in self.stats.port_scan_sources.items()},
                dos_packets=self.stats.dos_packets,
                bot_beacon_score=self.stats.bot_beacon_score
            )
    
    def register_callback(self, callback: Callable):
        self._callbacks.append(callback)
    
    def get_recent_packets(self, count: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            packets = self.packets[-count:]
            return [p.to_dict() for p in packets]
    
    def reset(self):
        with self._lock:
            self.packets.clear()
            self.stats = PacketStats()
