#!/usr/bin/env python3
"""Download CICIDS2017 dataset and train the ML model"""

import os
import sys
import zipfile
import requests
from pathlib import Path
from io import BytesIO
import pandas as pd
import numpy as np
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.ml.model_trainer import ModelTrainer, ATTACK_LABELS
from src.utils.logger import setup_logger
from src.utils.config import get_config

logger = setup_logger("netwatcher.train")


def download_from_huggingface(data_dir: Path) -> pd.DataFrame:
    """Download CICIDS2017 from HuggingFace"""
    try:
        from datasets import load_dataset

        logger.info("Downloading CICIDS2017 from HuggingFace...")
        dataset = load_dataset("bvsam/cic-ids-2017", "machine_learning", split="train")

        df = dataset.to_pandas()
        logger.info(f"Loaded {len(df)} rows from HuggingFace")
        return df
    except ImportError:
        logger.warning("datasets library not installed, trying alternative...")
        raise ImportError("Please install: pip install datasets")


# CICIDS2017 feature columns we need (subset of available features)
FEATURE_COLUMNS = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',
    'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
    'Destination Port', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
    'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
    'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
    'Min Packet Length', 'Max Packet Length', 'Packet Length Variance',
    'SYN Flag Count', 'CWE Flag Count', 'FIN Flag Count', 'RST Flag Count',
    'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'ECE Flag Count',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
    'act_data_pkt_fwd', 'min_seg_size_forward',
    'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
]

LABEL_COLUMN = 'Label'


def download_cicids2017(data_dir: Path) -> Path:
    """Download CICIDS2017 dataset from official source"""
    data_dir.mkdir(parents=True, exist_ok=True)

    # Try multiple download sources
    download_urls = [
        # Primary source
        "https://www.unb.ca/cic/datasets/IDS2017.zip",
        # Fallback mirrors
        "https://mirror.gcr.io/www.unb.ca/cic/datasets/IDS2017.zip",
    ]

    zip_path = data_dir / "CICIDS2017.zip"

    if zip_path.exists():
        logger.info(f"Dataset already exists at {zip_path}")
        return zip_path

    for url in download_urls:
        try:
            logger.info(f"Downloading CICIDS2017 dataset from {url}...")
            response = requests.get(url, timeout=300, stream=True)
            response.raise_for_status()

            total_size = int(response.headers.get('content-length', 0))
            logger.info(f"Download size: {total_size / (1024*1024):.1f} MB")

            downloaded = 0
            with open(zip_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size > 0 and downloaded % (50 * 1024 * 1024) < 8192:
                            logger.info(f"Downloaded: {downloaded / (1024*1024):.1f} MB")

            logger.info(f"Downloaded to {zip_path}")
            return zip_path

        except requests.RequestException as e:
            logger.warning(f"Failed to download from {url}: {e}")
            if zip_path.exists():
                zip_path.unlink()
            continue

    raise Exception("Could not download CICIDS2017 dataset from any source")


def extract_dataset(zip_path: Path, data_dir: Path) -> Path:
    """Extract the dataset"""
    extracted_dir = data_dir / "CICIDS2017"

    if extracted_dir.exists():
        logger.info(f"Dataset already extracted at {extracted_dir}")
        return extracted_dir

    logger.info("Extracting dataset...")

    # Create directory structure
    extracted_dir.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # Extract all files
            for member in zip_ref.namelist():
                # Skip large pcap files
                if member.endswith('.pcap') or member.endswith('.pcapng'):
                    continue

                # Extract CSV files
                if member.endswith('.csv'):
                    try:
                        zip_ref.extract(member, data_dir / "CICIDS2017_temp")
                    except Exception as e:
                        logger.warning(f"Failed to extract {member}: {e}")

        # Rename and reorganize
        temp_dir = data_dir / "CICIDS2017_temp"
        if temp_dir.exists():
            for item in temp_dir.rglob('*.csv'):
                dest = extracted_dir / item.name
                if not dest.exists():
                    item.rename(dest)
            # Cleanup temp
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

        logger.info(f"Dataset extracted to {extracted_dir}")
        return extracted_dir

    except zipfile.BadZipFile:
        logger.error("Downloaded file is not a valid ZIP archive")
        raise


def load_and_process_data(data_dir: Path):
    """Load and process CICIDS2017 CSV files"""
    csv_files = list(data_dir.glob("*.csv"))

    if not csv_files:
        # Try subdirectories
        csv_files = list(data_dir.rglob("*.csv"))

    if not csv_files:
        raise FileNotFoundError("No CSV files found in dataset")

    logger.info(f"Found {len(csv_files)} CSV files")

    dfs = []
    for csv_file in csv_files:
        try:
            logger.info(f"Loading {csv_file.name}...")
            df = pd.read_csv(csv_file, low_memory=False, nrows=50000)
            dfs.append(df)
            logger.info(f"  Loaded {len(df)} rows")
        except Exception as e:
            logger.warning(f"Failed to load {csv_file.name}: {e}")
            continue

    if not dfs:
        raise Exception("No CSV files could be loaded")

    # Combine all dataframes
    combined_df = pd.concat(dfs, ignore_index=True)
    logger.info(f"Combined dataset: {len(combined_df)} rows")

    return combined_df


def preprocess_data(df: pd.DataFrame) -> tuple:
    """Preprocess data for training"""
    logger.info("Preprocessing data...")

    # Handle infinite values
    df = df.replace([np.inf, -np.inf], np.nan)

    # Fill NaN values
    df = df.fillna(0)

    # Get available feature columns
    available_features = [col for col in FEATURE_COLUMNS if col in df.columns]

    if not available_features:
        # Use all numeric columns except label
        available_features = df.select_dtypes(include=[np.number]).columns.tolist()
        if LABEL_COLUMN in available_features:
            available_features.remove(LABEL_COLUMN)

    logger.info(f"Using {len(available_features)} features")

    # Extract features
    X = df[available_features].values

    # Process labels
    df[LABEL_COLUMN] = df[LABEL_COLUMN].astype(str)

    # Map labels to our categories
    label_mapping = {
        'Benign': 'BENIGN',
        'BENIGN': 'BENIGN',
        'Bot': 'Bot',
        'FTP-BruteForce': 'Brute Force',
        'SSH-Bruteforce': 'Brute Force',
        'Brute Force': 'Brute Force',
        'DoS攻击-SYN': 'DoS',
        'DoS SYN': 'DoS',
        'DoS Hulk': 'DoS',
        'DoS GoldenEye': 'DoS',
        'DoS slowloris': 'DoS',
        'DoS attack': 'DoS',
        'DDoS': 'DoS',
        'PortScan': 'Port Scan',
        'Port Scan': 'Port Scan',
        'SQL Injection': 'SQL Injection',
        'SQL injection': 'SQL Injection',
        'XSS': 'XSS',
        'Infiltration': 'Infiltration',
        'Web Attack': 'Web Attack',
    }

    y = df[LABEL_COLUMN].map(lambda x: label_mapping.get(x, 'BENIGN'))

    # Filter to only known labels
    known_labels = set(ATTACK_LABELS)
    mask = y.isin(known_labels)
    X = X[mask]
    y = y[mask]

    logger.info(f"After filtering: {len(X)} samples")
    logger.info(f"Label distribution:\n{y.value_counts()}")

    return X, y, available_features


def train_model_with_real_data(X: np.ndarray, y: np.ndarray, feature_names: list, model_path: str):
    """Train the ML model with real data"""
    import pickle
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import accuracy_score, classification_report

    logger.info(f"Training with {len(X)} samples...")

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

    # Train Random Forest (works well for network intrusion detection)
    logger.info("Training Random Forest classifier...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        n_jobs=-1,
        random_state=42,
        class_weight='balanced'
    )

    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    logger.info(f"\n{'='*50}")
    logger.info(f"Model Accuracy: {accuracy:.4f}")
    logger.info(f"{'='*50}")
    logger.info("\nClassification Report:")
    logger.info(classification_report(y_test, y_pred, target_names=label_encoder.classes_))

    # Get feature importance
    importance = dict(zip(feature_names, model.feature_importances_))
    top_features = sorted(importance.items(), key=lambda x: x[1], reverse=True)[:10]
    logger.info("\nTop 10 Important Features:")
    for feat, imp in top_features:
        logger.info(f"  {feat}: {imp:.4f}")

    # Save model
    model_data = {
        'model': model,
        'scaler': scaler,
        'label_encoder': label_encoder,
        'feature_names': feature_names,
        'accuracy': accuracy,
        'training_date': pd.Timestamp.now().isoformat(),
        'n_samples': len(X),
        'attack_labels': ATTACK_LABELS
    }

    Path(model_path).parent.mkdir(parents=True, exist_ok=True)
    with open(model_path, 'wb') as f:
        pickle.dump(model_data, f)

    logger.info(f"\nModel saved to {model_path}")
    return accuracy


def main():
    """Main training pipeline"""
    logger.info("="*60)
    logger.info("Netwatcher - CICIDS2017 Model Training")
    logger.info("="*60)

    config = get_config("config.yaml")
    model_path = config.ml.model_path

    # Setup paths
    data_dir = Path("./data/cicids2017")
    data_dir.mkdir(parents=True, exist_ok=True)

    # Step 1: Download dataset
    df = None

    # Try HuggingFace first
    try:
        df = download_from_huggingface(data_dir)
    except Exception as e:
        logger.warning(f"HuggingFace download failed: {e}")

    # Fallback to UNB direct download
    if df is None:
        try:
            zip_path = download_cicids2017(data_dir)
            extracted_dir = extract_dataset(zip_path, data_dir)
            df = load_and_process_data(extracted_dir)
        except Exception as e:
            logger.warning(f"UNB download failed: {e}")

    # Fallback to synthetic data
    if df is None:
        logger.info("Falling back to synthetic data training...")
        trainer = ModelTrainer(model_path)
        result = trainer.train()
        return 0 if result else 1

    # Step 2: Process data
    try:
        X, y, feature_names = preprocess_data(df)
    except Exception as e:
        logger.error(f"Failed to process data: {e}")
        return 1

    if len(X) < 1000:
        logger.warning("Not enough training samples, using synthetic data")
        trainer = ModelTrainer(model_path)
        result = trainer.train()
        return 0 if result else 1

    # Step 3: Train model
    try:
        accuracy = train_model_with_real_data(X, y, feature_names, model_path)
        logger.info("="*60)
        logger.info("Training Complete!")
        logger.info(f"Accuracy: {accuracy:.4f}")
        logger.info(f"Model saved to: {model_path}")
        logger.info("="*60)
        return 0
    except Exception as e:
        logger.error(f"Training failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
