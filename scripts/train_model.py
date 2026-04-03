#!/usr/bin/env python3
"""Train ML model for traffic classification"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.ml.model_trainer import train_model, ModelTrainer
from src.utils.logger import setup_logger
from src.utils.config import get_config

logger = setup_logger("netwatcher.train")


def main():
    logger.info("Starting model training...")
    
    config = get_config("config.yaml")
    model_path = config.ml.model_path
    
    trainer = ModelTrainer(model_path)
    
    try:
        result = trainer.train()
        
        logger.info("=" * 50)
        logger.info("Training Complete!")
        logger.info(f"Accuracy: {result.accuracy:.4f}")
        logger.info(f"Model saved to: {result.model_path}")
        logger.info(f"Training samples: {result.num_samples}")
        logger.info(f"Features: {result.num_features}")
        logger.info("=" * 50)
        
        return 0
        
    except Exception as e:
        logger.error(f"Training failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
