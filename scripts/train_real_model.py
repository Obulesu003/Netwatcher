#!/usr/bin/env python3
"""Enhanced model training with features matching actual extractor output"""

import os
import sys
import pickle
import random
import numpy as np
from pathlib import Path
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.utils.logger import setup_logger
from src.utils.config import get_config

logger = setup_logger("netwatcher.train")


# Features that match FeatureExtractor output
FEATURE_NAMES = [
    'flow_duration', 'total_fwd_packets', 'total_bwd_packets',
    'total_length_fwd', 'total_length_bwd',
    'fwd_packet_length_max', 'fwd_packet_length_min', 'fwd_packet_length_mean', 'fwd_packet_length_std',
    'bwd_packet_length_max', 'bwd_packet_length_min', 'bwd_packet_length_mean', 'bwd_packet_length_std',
    'flow_bytes_per_sec', 'flow_packets_per_sec', 'flow_iat_mean', 'flow_iat_std',
    'fwd_iat_total', 'fwd_iat_mean', 'fwd_iat_std', 'fwd_iat_max', 'fwd_iat_min',
    'bwd_iat_total', 'bwd_iat_mean', 'bwd_iat_std', 'bwd_iat_max', 'bwd_iat_min',
    'active_mean', 'active_std', 'active_max', 'active_min',
    'idle_mean', 'idle_std', 'idle_max', 'idle_min',
    'destination_port', 'packet_length_mean', 'packet_length_std',
    'down_up_ratio', 'average_packet_size', 'avg_fwd_segment_size', 'avg_bwd_segment_size',
    'fwd_header_length', 'bwd_header_length', 'fwd_packets_per_sec', 'bwd_packets_per_sec',
    'min_packet_length', 'max_packet_length',
    'syn_flag_count', 'rst_flag_count', 'psh_flag_count', 'ack_flag_count', 'urg_flag_count',
    'init_win_bytes_forward', 'init_win_bytes_backward',
    'act_data_pkt_fwd', 'min_seg_size_forward',
    'subflow_fwd_packets', 'subflow_fwd_bytes', 'subflow_bwd_packets', 'subflow_bwd_bytes',
    'packet_count', 'byte_count', 'duration', 'packets_per_second', 'bytes_per_second',
    'tcp_ratio', 'udp_ratio', 'icmp_ratio', 'unique_src_ips', 'unique_dst_ips',
    'unique_src_ports', 'unique_dst_ports', 'port_scan_score',
    'dst_ports_per_src', 'src_ports_per_src', 'syn_ack_ratio', 'fwd_packets_ratio'
]


def compute_features(total_packets, total_bytes, duration, pps, bps, avg_size,
                     prot_dist, unique_src_ips, unique_dst_ips, unique_src_ports, unique_dst_ports,
                     top_dst_ports):
    """Compute all features similar to FeatureExtractor"""
    features = {}

    # Basic flow statistics
    features['flow_duration'] = duration
    features['duration'] = duration

    # Packet counts
    features['total_fwd_packets'] = int(total_packets * 0.6)
    features['total_bwd_packets'] = int(total_packets * 0.4)
    features['packet_count'] = total_packets

    # Byte counts
    features['total_length_fwd'] = int(total_bytes * 0.6)
    features['total_length_bwd'] = int(total_bytes * 0.4)
    features['byte_count'] = total_bytes

    # Packet length statistics
    features['fwd_packet_length_max'] = avg_size * 1.2
    features['fwd_packet_length_min'] = avg_size * 0.7
    features['fwd_packet_length_mean'] = avg_size * 0.9
    features['fwd_packet_length_std'] = avg_size * 0.3
    features['bwd_packet_length_max'] = avg_size * 1.1
    features['bwd_packet_length_min'] = avg_size * 0.6
    features['bwd_packet_length_mean'] = avg_size * 0.85
    features['bwd_packet_length_std'] = avg_size * 0.25
    features['packet_length_mean'] = avg_size
    features['packet_length_std'] = avg_size * 0.3
    features['average_packet_size'] = avg_size
    features['min_packet_length'] = 40
    features['max_packet_length'] = 1500

    # Rate features
    features['flow_bytes_per_sec'] = bps
    features['flow_packets_per_sec'] = pps
    features['packets_per_second'] = pps
    features['bytes_per_second'] = bps
    features['fwd_packets_per_sec'] = pps * 0.6
    features['bwd_packets_per_sec'] = pps * 0.4

    # IAT features
    features['flow_iat_mean'] = 1.0 / max(pps, 0.001)
    features['flow_iat_std'] = features['flow_iat_mean'] * 0.5
    features['fwd_iat_total'] = duration * 0.6
    features['fwd_iat_mean'] = features['flow_iat_mean'] * 1.2
    features['fwd_iat_std'] = features['fwd_iat_mean'] * 0.4
    features['fwd_iat_max'] = features['fwd_iat_mean'] * 5
    features['fwd_iat_min'] = features['fwd_iat_mean'] * 0.1
    features['bwd_iat_total'] = duration * 0.4
    features['bwd_iat_mean'] = features['flow_iat_mean'] * 1.5
    features['bwd_iat_std'] = features['bwd_iat_mean'] * 0.4
    features['bwd_iat_max'] = features['bwd_iat_mean'] * 5
    features['bwd_iat_min'] = features['bwd_iat_mean'] * 0.1

    # Activity features
    features['active_mean'] = duration / max(total_packets, 1) * 10
    features['active_std'] = features['active_mean'] * 0.3
    features['active_max'] = features['active_mean'] * 3
    features['active_min'] = features['active_mean'] * 0.2
    features['idle_mean'] = features['active_mean'] * 0.5
    features['idle_std'] = features['idle_mean'] * 0.3
    features['idle_max'] = features['idle_mean'] * 2
    features['idle_min'] = features['idle_mean'] * 0.2

    # Protocol ratios
    total_prot = sum(prot_dist.values()) or 1
    features['tcp_ratio'] = prot_dist.get('TCP', 0) / total_prot
    features['udp_ratio'] = prot_dist.get('UDP', 0) / total_prot
    features['icmp_ratio'] = prot_dist.get('ICMP', 0) / total_prot

    # Unique counts
    features['unique_src_ips'] = unique_src_ips
    features['unique_dst_ips'] = unique_dst_ips
    features['unique_src_ports'] = unique_src_ports
    features['unique_dst_ports'] = unique_dst_ports

    # Destination port
    features['destination_port'] = list(top_dst_ports.keys())[0] if top_dst_ports else 80

    # Flag counts
    tcp_count = prot_dist.get('TCP', 0)
    features['syn_flag_count'] = int(tcp_count * 0.1)
    features['rst_flag_count'] = 0
    features['psh_flag_count'] = int(tcp_count * 0.2)
    features['ack_flag_count'] = int(tcp_count * 0.7)
    features['urg_flag_count'] = 0

    # Window sizes
    features['init_win_bytes_forward'] = 65535
    features['init_win_bytes_backward'] = 65535
    features['act_data_pkt_fwd'] = int(total_packets * 0.5)
    features['min_seg_size_forward'] = 32

    # Subflow features
    features['subflow_fwd_packets'] = int(total_packets * 0.6)
    features['subflow_fwd_bytes'] = int(total_bytes * 0.6)
    features['subflow_bwd_packets'] = int(total_packets * 0.4)
    features['subflow_bwd_bytes'] = int(total_bytes * 0.4)

    # Segment sizes
    features['avg_fwd_segment_size'] = avg_size * 0.9
    features['avg_bwd_segment_size'] = avg_size * 0.85

    # Header lengths
    features['fwd_header_length'] = 54
    features['bwd_header_length'] = 54

    # Down/Up ratio
    fwd_bytes = features['total_length_fwd']
    bwd_bytes = features['total_length_bwd']
    features['down_up_ratio'] = fwd_bytes / max(bwd_bytes, 1)

    # Port scan score (KEY discriminator between Port Scan vs Brute Force)
    # Port Scan: high dst ports per source IP (many ports scanned from few IPs)
    # Brute Force: low dst ports but high src ports (same port, many source ports)
    # Formula: (unique_dst_ports * unique_dst_ips) / (unique_src_ips * 10)
    features['port_scan_score'] = min(
        (unique_dst_ports * unique_dst_ips) / (unique_src_ips * 10), 1.0
    )

    # Additional discriminative features
    # dst_ports_per_src: Port Scan >> Brute Force
    features['dst_ports_per_src'] = unique_dst_ports / max(unique_src_ips, 1)
    # src_ports_per_src: Brute Force >> Port Scan
    features['src_ports_per_src'] = unique_src_ports / max(unique_src_ips, 1)
    # syn_ack_ratio: Port Scan (high SYN, low ACK) vs Brute Force (ACK-heavy)
    syn_count = features['syn_flag_count']
    ack_count = features['ack_flag_count']
    features['syn_ack_ratio'] = syn_count / max(ack_count, 1)
    # fwd_packets_ratio: Port Scan is mostly forward (one-way)
    features['fwd_packets_ratio'] = features['total_fwd_packets'] / max(total_packets, 1)

    return features


def generate_normal_samples(n):
    """Generate normal traffic samples"""
    samples = []
    for _ in range(n):
        total_packets = random.randint(20, 500)
        total_bytes = total_packets * random.randint(60, 200)
        duration = random.uniform(5, 120)
        pps = total_packets / max(duration, 0.001)
        bps = total_bytes / max(duration, 0.001)
        avg_size = total_bytes / max(total_packets, 1)
        prot_dist = {'TCP': int(total_packets * random.uniform(0.6, 0.9)),
                     'UDP': int(total_packets * random.uniform(0.1, 0.3)),
                     'ICMP': int(total_packets * random.uniform(0, 0.05))}
        features = compute_features(
            total_packets, total_bytes, duration, pps, bps, avg_size,
            prot_dist,
            random.randint(1, 10), random.randint(1, 20),
            random.randint(1, 50), random.randint(1, 10),
            {80: 100, 443: 80, 22: 20}
        )
        features['label'] = 'BENIGN'
        samples.append(features)
    return samples


def generate_dos_samples(n):
    """Generate DoS attack samples - HIGH packet rate, many src IPs"""
    samples = []
    for _ in range(n):
        total_packets = random.randint(5000, 50000)
        total_bytes = total_packets * random.randint(40, 70)  # Small packets
        duration = random.uniform(1, 30)
        pps = total_packets / max(duration, 0.001)  # Very high PPS
        bps = total_bytes / max(duration, 0.001)
        avg_size = 50  # Small, uniform packets
        prot_dist = {'TCP': int(total_packets * 0.95), 'UDP': int(total_packets * 0.05), 'ICMP': 0}
        features = compute_features(
            total_packets, total_bytes, duration, pps, bps, avg_size,
            prot_dist,
            random.randint(50, 500),  # Many source IPs
            random.randint(1, 5),
            random.randint(50, 500),
            random.randint(1, 5),
            {80: 10000, 443: 5000}
        )
        features['label'] = 'DoS'
        samples.append(features)
    return samples


def generate_portscan_samples(n):
    """Generate port scan samples - VERY HIGH unique dst ports, LOW packet rate"""
    samples = []
    for _ in range(n):
        # Port scan: low packets, very wide port distribution, slow rate
        total_packets = random.randint(100, 1000)
        total_bytes = total_packets * random.randint(40, 70)
        duration = random.uniform(10, 120)  # Long duration, slow scan
        pps = total_packets / max(duration, 0.001)  # Low PPS
        bps = total_bytes / max(duration, 0.001)
        avg_size = 50  # Small packets (SYN probes)
        # Primarily TCP SYN scans
        prot_dist = {'TCP': int(total_packets * 0.95), 'UDP': int(total_packets * 0.03), 'ICMP': int(total_packets * 0.02)}
        # KEY DIFFERENTIATOR: Very high dst ports, few src IPs
        features = compute_features(
            total_packets, total_bytes, duration, pps, bps, avg_size,
            prot_dist,
            random.randint(1, 5),  # FEW source IPs (1 attacker)
            random.randint(10, 50),  # Many destination IPs
            random.randint(1, 10),  # FEW source ports
            random.randint(100, 500),  # VERY HIGH unique destination ports
            {i: 1 for i in range(1, 1024)}  # Full port range
        )
        # Override syn_flag for more realistic SYN scan
        features['syn_flag_count'] = int(total_packets * 0.8)  # Most are SYN
        features['psh_flag_count'] = 0
        features['ack_flag_count'] = 0
        features['rst_flag_count'] = int(total_packets * 0.1)
        features['act_data_pkt_fwd'] = 0  # No data in SYN scan
        features['subflow_fwd_packets'] = int(total_packets * 0.95)
        features['subflow_bwd_packets'] = int(total_packets * 0.05)  # Mostly one-way
        features['subflow_fwd_bytes'] = int(total_bytes * 0.95)
        features['subflow_bwd_bytes'] = int(total_bytes * 0.05)
        features['down_up_ratio'] = 20.0  # Almost all forward traffic
        features['port_scan_score'] = 0.8 + random.random() * 0.2  # Very high
        features['label'] = 'Port Scan'
        samples.append(features)
    return samples


def generate_bruteforce_samples(n):
    """Generate brute force samples - HIGH src ports, LOW dst ports, TCP ACK pattern"""
    samples = []
    for _ in range(n):
        # Brute force: moderate packets, few dst ports, many src ports
        total_packets = random.randint(500, 5000)
        total_bytes = total_packets * random.randint(40, 80)
        duration = random.uniform(60, 600)  # Long duration
        pps = total_packets / max(duration, 0.001)
        bps = total_bytes / max(duration, 0.001)
        avg_size = 50
        prot_dist = {'TCP': int(total_packets * 0.95), 'UDP': int(total_packets * 0.05), 'ICMP': 0}
        features = compute_features(
            total_packets, total_bytes, duration, pps, bps, avg_size,
            prot_dist,
            random.randint(5, 50),  # Multiple source IPs (botnet or proxy)
            random.randint(1, 3),  # Single or very few dest IPs
            random.randint(100, 1000),  # VERY HIGH unique source ports (credential attempts)
            random.randint(1, 3),  # Single dest port (SSH=22, FTP=21, HTTP=80)
            {22: 2000, 21: 1000, 23: 500}  # Single port focus
        )
        # Override flags for more realistic SSH/FTP brute force
        features['syn_flag_count'] = int(total_packets * 0.05)  # Few SYN
        features['ack_flag_count'] = int(total_packets * 0.6)  # Many ACK (keep-alive)
        features['psh_flag_count'] = int(total_packets * 0.3)  # Some PSH+ACK with credentials
        features['rst_flag_count'] = int(total_packets * 0.05)  # Some RST (failed attempts)
        features['act_data_pkt_fwd'] = int(total_packets * 0.3)  # Contains auth data
        features['subflow_fwd_packets'] = int(total_packets * 0.5)
        features['subflow_bwd_packets'] = int(total_packets * 0.5)  # More back-channel (server responses)
        features['subflow_fwd_bytes'] = int(total_bytes * 0.4)
        features['subflow_bwd_bytes'] = int(total_bytes * 0.6)  # Server responses
        features['down_up_ratio'] = 0.7  # Some back-channel traffic
        features['port_scan_score'] = random.random() * 0.1  # Very low port scan score
        features['label'] = 'Brute Force'
        samples.append(features)
    return samples


def generate_bot_samples(n):
    """Generate bot/C2 samples - Regular intervals, beaconing"""
    samples = []
    for _ in range(n):
        total_packets = random.randint(50, 500)
        total_bytes = total_packets * random.randint(80, 200)
        duration = random.uniform(60, 600)  # Long duration
        pps = total_packets / max(duration, 0.001)  # Low PPS
        bps = total_bytes / max(duration, 0.001)
        avg_size = 100
        prot_dist = {'TCP': int(total_packets * 0.8), 'UDP': int(total_packets * 0.15), 'ICMP': int(total_packets * 0.05)}
        features = compute_features(
            total_packets, total_bytes, duration, pps, bps, avg_size,
            prot_dist,
            random.randint(1, 5),  # Single source
            random.randint(1, 3),  # Single dest
            random.randint(1, 20),
            random.randint(1, 3),
            {443: 300, 80: 100, 4444: 50}
        )
        # Make IAT more regular (beaconing pattern)
        features['flow_iat_std'] = features['flow_iat_mean'] * 0.1  # Low variance = regular
        features['label'] = 'Bot'
        samples.append(features)
    return samples


def generate_sql_injection_samples(n):
    """Generate SQL injection samples - HTTP traffic with specific patterns"""
    samples = []
    for _ in range(n):
        total_packets = random.randint(10, 100)
        total_bytes = total_packets * random.randint(100, 500)  # Large packets (payload)
        duration = random.uniform(1, 30)
        pps = total_packets / max(duration, 0.001)
        bps = total_bytes / max(duration, 0.001)
        avg_size = 200  # Larger than normal HTTP due to payloads
        prot_dist = {'TCP': int(total_packets * 0.98), 'UDP': 0, 'ICMP': 0}  # Almost all TCP
        features = compute_features(
            total_packets, total_bytes, duration, pps, bps, avg_size,
            prot_dist,
            random.randint(1, 50),
            random.randint(1, 10),
            random.randint(1, 100),
            random.randint(1, 3),
            {80: 50, 8080: 30}
        )
        features['label'] = 'SQL Injection'
        samples.append(features)
    return samples


def generate_xss_samples(n):
    """Generate XSS attack samples - HTTP traffic with script patterns"""
    samples = []
    for _ in range(n):
        total_packets = random.randint(5, 50)
        total_bytes = total_packets * random.randint(150, 600)  # Larger due to script payloads
        duration = random.uniform(0.5, 20)
        pps = total_packets / max(duration, 0.001)
        bps = total_bytes / max(duration, 0.001)
        avg_size = 250  # Larger packets with script content
        prot_dist = {'TCP': int(total_packets * 0.99), 'UDP': 0, 'ICMP': 0}
        features = compute_features(
            total_packets, total_bytes, duration, pps, bps, avg_size,
            prot_dist,
            random.randint(1, 100),  # Many sources
            random.randint(1, 5),
            random.randint(1, 50),
            random.randint(1, 3),
            {80: 30, 8080: 20}
        )
        features['label'] = 'XSS'
        samples.append(features)
    return samples


def main():
    """Train the model"""
    logger.info("="*60)
    logger.info("Netwatcher - Enhanced Model Training")
    logger.info("="*60)

    config = get_config("config.yaml")
    model_path = config.ml.model_path

    # Generate training data
    logger.info("\nGenerating training dataset...")

    samples = []
    samples.extend(generate_normal_samples(5000))
    samples.extend(generate_dos_samples(2000))
    samples.extend(generate_portscan_samples(2000))  # Increased for better coverage
    samples.extend(generate_bruteforce_samples(2000))  # Increased for better coverage
    samples.extend(generate_bot_samples(800))
    samples.extend(generate_sql_injection_samples(500))
    samples.extend(generate_xss_samples(300))

    # Fix: shuffle BEFORE creating DataFrame to maintain feature-label alignment
    random.shuffle(samples)
    df = pd.DataFrame(samples)

    logger.info(f"\nTotal samples: {len(df)}")
    logger.info(f"\nLabel distribution:")
    logger.info(df['label'].value_counts())

    # Prepare features
    feature_cols = [col for col in df.columns if col != 'label']
    X = df[feature_cols].values.astype(np.float64)
    y = df['label'].values

    # Handle any NaN or Inf values
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    # Encode labels
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)

    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )

    # Train Random Forest
    logger.info("\nTraining Random Forest classifier...")
    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=25,
        min_samples_split=5,
        min_samples_leaf=2,
        n_jobs=-1,
        random_state=42,
        class_weight='balanced',
        verbose=1
    )

    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    logger.info(f"\n{'='*60}")
    logger.info(f"Model Accuracy: {accuracy:.4f}")
    logger.info(f"{'='*60}")
    logger.info("\nClassification Report:")
    logger.info(classification_report(y_test, y_pred, target_names=label_encoder.classes_))

    # Feature importance
    importance = dict(zip(feature_cols, model.feature_importances_))
    top_features = sorted(importance.items(), key=lambda x: x[1], reverse=True)[:10]
    logger.info("\nTop 10 Important Features:")
    for feat, imp in top_features:
        logger.info(f"  {feat}: {imp:.4f}")

    # Save model
    model_data = {
        'model': model,
        'scaler': scaler,
        'label_encoder': label_encoder,
        'feature_names': feature_cols,
        'accuracy': accuracy,
        'training_date': datetime.now().isoformat(),
        'n_samples': len(df),
        'attack_labels': ['BENIGN', 'Bot', 'Brute Force', 'DoS', 'Port Scan', 'SQL Injection', 'XSS'],
        'attack_categories': {
            'BENIGN': 'Normal',
            'Bot': 'Botnet',
            'Brute Force': 'Brute Force',
            'DoS': 'DoS',
            'Port Scan': 'Reconnaissance',
            'SQL Injection': 'Web Attack',
        },
    }

    Path(model_path).parent.mkdir(parents=True, exist_ok=True)
    with open(model_path, 'wb') as f:
        pickle.dump(model_data, f)

    logger.info(f"\n{'='*60}")
    logger.info("Training Complete!")
    logger.info(f"Accuracy: {accuracy:.4f}")
    logger.info(f"Model saved to: {model_path}")
    logger.info("="*60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
