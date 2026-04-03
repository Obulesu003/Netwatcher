"""Traffic classifier using trained ML model"""

import pickle
import numpy as np
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import logging

from .features import FeatureExtractor
from ..utils.logger import get_logger
from ..utils.config import get_config

logger = get_logger(__name__)


ATTACK_LABELS = [
    'BENIGN', 'Bot', 'Brute Force', 'DoS', 'Port Scan', 'SQL Injection', 'XSS'
]

ATTACK_CATEGORIES = {
    'BENIGN': 'Normal',
    'Bot': 'Botnet',
    'Brute Force': 'Brute Force',
    'DoS': 'DoS',
    'Port Scan': 'Reconnaissance',
    'SQL Injection': 'Web Attack',
    'XSS': 'Web Attack'
}

SEVERITY_LEVELS = {
    'Normal': 0,
    'Botnet': 4,
    'Brute Force': 3,
    'DoS': 3,
    'Reconnaissance': 2,
    'Web Attack': 3,
    'Unknown': 0
}


@dataclass
class ClassificationResult:
    label: str
    category: str
    confidence: float
    severity: int
    is_threat: bool
    timestamp: str
    features: Dict[str, float]
    all_detected_attacks: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'label': self.label,
            'category': self.category,
            'confidence': round(self.confidence, 4),
            'severity': self.severity,
            'is_threat': self.is_threat,
            'timestamp': self.timestamp,
            'threat_level': self._get_threat_level(),
            'all_detected_attacks': self.all_detected_attacks
        }

    def _get_threat_level(self) -> str:
        if self.severity >= 4:
            return 'critical'
        elif self.severity >= 3:
            return 'high'
        elif self.severity >= 2:
            return 'medium'
        elif self.severity >= 1:
            return 'low'
        return 'none'

    @classmethod
    def from_raw(cls, label: str, confidence: float, features: Dict[str, float],
                 detected_attacks: List[str] = None) -> 'ClassificationResult':
        category = ATTACK_CATEGORIES.get(label, 'Normal')
        severity = SEVERITY_LEVELS.get(category, 0)
        attacks = detected_attacks or []

        # Check for strong attack patterns that match the label
        attack_patterns_confirmed = cls._check_attack_pattern_match(label, features)

        # Only mark as threat if:
        # 1. Attack patterns are confirmed by features, OR
        # 2. We have detected attacks from rule-based detection
        # ML model confidence alone is NOT sufficient - require feature evidence!
        if label != 'BENIGN' and (attack_patterns_confirmed or attacks):
            is_threat = True
            # Boost confidence if attack patterns are confirmed
            if attack_patterns_confirmed or attacks:
                confidence = max(confidence, 0.90)  # Minimum 90% confidence if patterns confirmed
        else:
            # ML model predicted an attack but no feature evidence - treat as BENIGN
            is_threat = False
            label = 'BENIGN'
            category = 'Normal'
            severity = 0
            attacks = []
            confidence = 0.5  # Neutral confidence

        return cls(
            label=label,
            category=category,
            confidence=confidence,
            severity=severity,
            is_threat=is_threat,
            timestamp=datetime.now().isoformat(),
            features=features,
            all_detected_attacks=attacks
        )

    @staticmethod
    def _check_attack_pattern_match(label: str, features: Dict[str, float]) -> bool:
        """Check if attack patterns in features match the predicted label

        Balanced thresholds to detect real attacks while avoiding false positives.
        """
        sql_count = features.get('sql_injection_count', 0)
        xss_count = features.get('xss_count', 0)
        brute_force = features.get('brute_force_count', 0)
        dos_packets = features.get('dos_packets', 0)
        web_payload = features.get('web_payload_count', 0)
        bot_score = features.get('bot_beacon_score', 0)
        port_scan_score = features.get('port_scan_score', 0)
        unique_dst_ports = features.get('unique_dst_ports', 0)
        pps = features.get('packets_per_second', 0)

        if label == 'XSS' and (xss_count >= 20 or (xss_count >= 10 and web_payload >= 10)):
            return True
        if label == 'SQL Injection' and sql_count >= 20:
            return True
        if label == 'Brute Force' and brute_force >= 20:
            return True
        if label == 'DoS' and dos_packets >= 30 and pps >= 200:
            return True
        if label == 'Port Scan' and port_scan_score >= 0.5 and unique_dst_ports >= 20:
            return True
        if label == 'Bot' and bot_score >= 3:
            return True

        return False


class TrafficClassifier:
    """Traffic classifier using trained Random Forest model"""

    def __init__(self, model_path: Optional[str] = None, config=None):
        self.config = config or get_config()
        self.model_path = Path(model_path or self.config.ml.model_path)
        self.feature_extractor = FeatureExtractor()
        self.model_data = None
        self._load_model()

    def _load_model(self):
        """Load trained model from pickle file"""
        if self.model_path.exists():
            try:
                with open(self.model_path, 'rb') as f:
                    self.model_data = pickle.load(f)
                logger.info(f"Loaded model from {self.model_path}")
                logger.info(f"Model accuracy: {self.model_data.get('accuracy', 'N/A')}")
                logger.info(f"Model classes: {list(self.model_data['label_encoder'].classes_)}")
            except Exception as e:
                logger.error(f"Failed to load model: {e}")
                self.model_data = None
        else:
            logger.warning(f"Model not found at {self.model_path}")

    def classify(self, traffic_data: Dict[str, Any]) -> ClassificationResult:
        """Classify traffic using trained model"""
        features = self.feature_extractor.extract(traffic_data)
        features_dict = features.to_dict()

        # Use trained model if available
        if self.model_data is not None:
            return self._classify_with_model(features_dict)
        else:
            # Fallback to rule-based classification
            return self._classify_rule_based(features_dict)

    def _classify_with_model(self, features: Dict[str, float]) -> ClassificationResult:
        """Classify using trained ML model with attack pattern override

        IMPORTANT: ML model predictions are NOT trusted alone.
        All attacks must be confirmed by feature evidence (rule-based detection).
        This prevents false positives from model misclassifications.
        """
        try:
            # ALWAYS run rule-based detection first to get feature evidence
            attack_patterns = self._detect_attack_patterns(features)

            # If we have attack patterns from features, use rule-based result
            if attack_patterns:
                logger.info(f"Attack patterns detected by rule-based: {attack_patterns}")
                result = self._classify_rule_based(features)
                return result

            # No attack patterns detected - check ML model as secondary indicator
            # Only trust ML if features suggest benign traffic AND ML agrees
            if self.model_data is not None:
                model = self.model_data['model']
                scaler = self.model_data['scaler']
                label_encoder = self.model_data['label_encoder']
                feature_names = self.model_data['feature_names']

                # Prepare feature vector in correct order
                feature_vector = []
                for name in feature_names:
                    value = features.get(name, 0.0)
                    feature_vector.append(value)

                X = np.array([feature_vector], dtype=np.float64)
                X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
                X_scaled = scaler.transform(X)

                # Get prediction and probabilities
                prediction = model.predict(X_scaled)[0]
                probabilities = model.predict_proba(X_scaled)[0]

                ml_label = label_encoder.inverse_transform([prediction])[0]
                ml_confidence = float(probabilities[prediction])

                # ML prediction is only trusted if it says BENIGN
                # Any attack prediction from ML requires feature confirmation
                if ml_label == 'BENIGN':
                    return ClassificationResult.from_raw(ml_label, ml_confidence, features, attack_patterns)

                # ML predicted attack but we have no feature evidence - treat as BENIGN
                logger.info(f"ML predicted {ml_label} but no feature evidence - treating as BENIGN")
                return ClassificationResult.from_raw('BENIGN', 0.5, features, [])

            # No model - use pure rule-based (already checked above)
            return self._classify_rule_based(features)

        except Exception as e:
            logger.error(f"Model classification error: {e}")
            return self._classify_rule_based(features)

    def _detect_attack_patterns(self, features: Dict[str, float]) -> List[str]:
        """Detect attack patterns with balanced thresholds

        Calibrated to detect real attacks while minimizing false positives.
        """
        detected = []
        sql_count = features.get('sql_injection_count', 0)
        xss_count = features.get('xss_count', 0)
        brute_force = features.get('brute_force_count', 0)
        dos_packets = features.get('dos_packets', 0)
        web_payload = features.get('web_payload_count', 0)
        bot_score = features.get('bot_beacon_score', 0)
        port_scan_score = features.get('port_scan_score', 0)
        unique_dst_ports = features.get('unique_dst_ports', 0)
        packets_per_second = features.get('packets_per_second', 0)

        # XSS: Require suspicious patterns + web context
        if xss_count >= 20 or (xss_count >= 10 and web_payload >= 10):
            detected.append('XSS')
        # SQL Injection: Require dangerous patterns
        if sql_count >= 20:
            detected.append('SQL Injection')
        # Brute Force: Require sustained attempts (20+ from same source in short window)
        if brute_force >= 20:
            detected.append('Brute Force')
        # DoS: Require sustained flood
        if dos_packets >= 30 and packets_per_second >= 200:
            detected.append('DoS')
        # Port Scan: Require rapid port enumeration
        if port_scan_score >= 0.5 and unique_dst_ports >= 20:
            detected.append('Port Scan')
        # Bot: Require periodic beacon pattern
        if bot_score >= 3:
            detected.append('Bot')

        return detected

    def _get_attack_priority(self, attacks: List[str]) -> str:
        """Return the highest priority attack from detected attacks"""
        priority = ['DoS', 'Brute Force', 'SQL Injection', 'XSS', 'Port Scan', 'Bot']
        for attack in priority:
            if attack in attacks:
                return attack
        return attacks[0] if attacks else 'BENIGN'

    def _classify_rule_based(self, features: Dict[str, float]) -> ClassificationResult:
        """Fallback rule-based classification using attack pattern features"""
        port_scan_score = features.get('port_scan_score', 0)
        pps = features.get('packets_per_second', 0)
        unique_ports = features.get('unique_dst_ports', 0)

        # Use attack pattern detection features
        sql_count = features.get('sql_injection_count', 0)
        xss_count = features.get('xss_count', 0)
        brute_force = features.get('brute_force_count', 0)
        dos_packets = features.get('dos_packets', 0)
        web_payload = features.get('web_payload_count', 0)
        bot_score = features.get('bot_beacon_score', 0)

        # Detect all attacks with balanced thresholds
        detected_attacks = []
        if xss_count >= 20 or (xss_count >= 10 and web_payload >= 10):
            detected_attacks.append('XSS')
        if sql_count >= 20:
            detected_attacks.append('SQL Injection')
        if brute_force >= 20:
            detected_attacks.append('Brute Force')
        if dos_packets >= 30 and pps >= 200:
            detected_attacks.append('DoS')
        if port_scan_score >= 0.5 and unique_ports >= 20:
            detected_attacks.append('Port Scan')
        if bot_score >= 3:
            detected_attacks.append('Bot')

        # Get highest priority attack
        label = self._get_attack_priority(detected_attacks) if detected_attacks else 'BENIGN'

        # Calculate confidence based on attack strength
        if detected_attacks:
            if label == 'DoS':
                confidence = min(0.75 + (dos_packets * 0.005), 0.90)
            elif label == 'Brute Force':
                confidence = min(0.75 + (brute_force * 0.005), 0.90)
            elif label == 'SQL Injection':
                confidence = min(0.80 + (sql_count * 0.01), 0.95)
            elif label == 'XSS':
                confidence = min(0.80 + (xss_count * 0.01), 0.95)
            elif label == 'Port Scan':
                confidence = 0.75 + port_scan_score * 0.2
            else:
                confidence = 0.75
        else:
            confidence = 0.85

        return ClassificationResult.from_raw(label, min(confidence, 0.99), features, detected_attacks)

    def is_threat(self, traffic_data: Dict[str, Any]) -> Tuple[bool, ClassificationResult]:
        """Check if traffic is a threat"""
        result = self.classify(traffic_data)
        threshold = self.config.ml.confidence_threshold
        is_threat = result.is_threat and result.confidence >= threshold
        return is_threat, result

    def get_supported_labels(self) -> List[str]:
        """Get list of supported attack labels"""
        if self.model_data is not None:
            return list(self.model_data['label_encoder'].classes_)
        return ATTACK_LABELS


def classify_traffic(traffic_data: Dict[str, Any], model_path: Optional[str] = None) -> ClassificationResult:
    """Convenience function to classify traffic"""
    classifier = TrafficClassifier(model_path)
    return classifier.classify(traffic_data)
